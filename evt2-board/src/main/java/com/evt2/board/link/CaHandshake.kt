package com.evt2.board.link

import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject

/** The handshake could not complete: the call must NOT start (there are no authenticated session keys). */
class CaHandshakeException(message: String) : Exception(message)

/** A completed handshake. The AES-256-GCM session keys stay in the board; START_STREAM picks them up. */
data class CaHandshakeResult(val myRole: Int, val peerId: String)

/** Ordered, reliable message channel to the one peer of the call (JSON text messages). */
interface CaChannel {
    suspend fun send(message: String)

    /** Next message from the peer; suspends until one arrives. */
    suspend fun receive(): String
}

/**
 * The CA key-exchange handshake (M1..M4, same messages and fields as E2EE-App's CaHandshake and
 * SDCARD-QRNG's ca_peer_sim.py) with the peer on [channel]. Every cryptographic step (sign, verify, ECDH/ML-KEM,
 * HKDF, HMAC) runs on this phone's board through [device]; this class only sequences them and moves bytes.
 *
 * [initiator] = role A (sends M1). Both sides must agree on it, e.g. from their call identities.
 *
 * Before M1 the two sides exchange "ca_hello" so that no message is sent to a peer that is not listening yet:
 * A repeats its hello until it hears B's, then sends M1; B repeats its hello until M1 arrives.
 */
class CaHandshake(
    private val device: DeviceLink,
    private val channel: CaChannel,
    private val initiator: Boolean,
    private val onStatus: (String) -> Unit = {},
) {
    companion object {
        private const val HELLO_PERIOD_MS = 1_000L
        // The peer's app answers within a second or two once it is in the call; silence this long means the other
        // phone did not choose board E2EE (or has no board), so the call cannot be secured.
        private const val PEER_HELLO_TIMEOUT_MS = 60_000L
        // One step of the peer may include its board's VERIFY_PEER + SIGN_TRANSCRIPT, which take seconds with the
        // composite ML-DSA-65 identity (DeviceLink's CA_V3_* timeouts).
        private const val STEP_TIMEOUT_MS = 45_000L
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) =
        ByteArray(s.length / 2) { ((Character.digit(s[it * 2], 16) shl 4) + Character.digit(s[it * 2 + 1], 16)).toByte() }

    private suspend fun send(t: String, fields: Map<String, String> = emptyMap()) {
        val o = JSONObject().put("t", t)
        for ((k, v) in fields) o.put(k, v)
        channel.send(o.toString())
    }

    /** Runs the whole handshake; throws [CaHandshakeException] on any failure. */
    suspend fun run(): CaHandshakeResult = try {
        if (initiator) runInitiator() else runResponder()
    } catch (e: TimeoutCancellationException) {
        throw CaHandshakeException("hết thời gian chờ một bước của quá trình xác thực")
    }

    /** Next message of type [t]; anything else (a repeated hello, a stale message) is skipped. */
    private suspend fun receiveType(t: String): JSONObject {
        while (true) {
            val msg = try {
                JSONObject(channel.receive())
            } catch (_: Exception) {
                continue
            }
            if (msg.optString("t") == t) return msg
        }
    }

    private suspend fun waitFor(t: String): JSONObject = withTimeout(STEP_TIMEOUT_MS) { receiveType(t) }

    /** Sends a hello every HELLO_PERIOD_MS until [t] arrives (at most PEER_HELLO_TIMEOUT_MS), and returns it. */
    private suspend fun helloUntil(t: String): JSONObject = coroutineScope {
        val hello = launch {
            while (true) {
                send("ca_hello")
                delay(HELLO_PERIOD_MS)
            }
        }
        try {
            withTimeoutOrNull(PEER_HELLO_TIMEOUT_MS) { receiveType(t) }
                ?: throw CaHandshakeException(
                    "máy kia không trả lời bắt tay trong ${PEER_HELLO_TIMEOUT_MS / 1000} s " +
                        "(máy kia có chọn \"Mã hóa qua QRNG-SDCARD\" và đã cắm board chưa?)",
                )
        } finally {
            hello.cancel()
        }
    }

    private suspend fun runInitiator(): CaHandshakeResult {
        onStatus("Đang chờ board đối tác sẵn sàng...")
        helloUntil("ca_hello")

        onStatus("Đang sinh khóa tạm + số ngẫu nhiên trên board...")
        val (nA, epkA, pkKemA) = device.caBegin()
        val m1Fields = mutableMapOf("nA" to hex(nA), "epkA" to hex(epkA))
        if (pkKemA != null) m1Fields["pk_kem_a"] = hex(pkKemA)
        send("ca_m1", m1Fields)
        onStatus("Đã gửi M1" + (if (pkKemA != null) " (hybrid ML-KEM-768)" else "") + ", đang chờ đối tác...")

        val m2 = waitFor("ca_m2")
        val nB = unhex(m2.getString("nB"))
        val epkB = unhex(m2.getString("epkB"))
        val ctKemB = if (m2.has("ct_kem_b")) unhex(m2.getString("ct_kem_b")) else null
        val issuingB = unhex(m2.getString("issuing"))
        val certB = unhex(m2.getString("cert"))
        val tokenB = unhex(m2.getString("token"))
        val sigB = unhex(m2.getString("sig"))

        onStatus("Nhận M2, đang xác minh chứng chỉ + chữ ký của đối tác...")
        val vr = device.caVerifyPeer(CaCmd.ROLE_B, nA, epkA, nB, epkB, issuingB, certB, tokenB, sigB, pkKemA, ctKemB)
        if (!vr.ok) throw CaHandshakeException(verifyFailureMessage(vr))

        onStatus("Đối tác hợp lệ (${vr.peerId}), đang ký bản ghi bắt tay...")
        val (sigA, _) = device.caSignTranscript(CaCmd.ROLE_A, nA, epkA, nB, epkB, pkKemA, ctKemB)
        val idn = device.caGetIdentity()
        val tokenA = device.caGetStatusToken()
        send("ca_m3", mapOf("issuing" to hex(idn.issuingCert), "cert" to hex(idn.cert), "token" to hex(tokenA), "sig" to hex(sigA)))

        onStatus("Đang tính khóa phiên trên board...")
        device.caDeriveKeys(CaCmd.ROLE_A, nA, epkA, nB, epkB, pkKemA, ctKemB)
        val macA = device.caConfirm(CaCmd.ROLE_A, nA, epkA, nB, epkB, pkKemA, ctKemB)
        send("ca_m4", mapOf("mac" to hex(macA)))
        onStatus("Đang chờ xác nhận từ đối tác...")
        val m4 = waitFor("ca_m4")
        val vc = device.caVerifyConfirm(CaCmd.ROLE_B, nA, epkA, nB, epkB, unhex(m4.getString("mac")), pkKemA, ctKemB)
        if (vc != 0) throw CaHandshakeException("xác nhận lẫn nhau KHÔNG khớp (result=$vc)")
        return CaHandshakeResult(CaCmd.ROLE_A, vr.peerId ?: "?")
    }

    private suspend fun runResponder(): CaHandshakeResult {
        onStatus("Đang chờ M1 từ đối tác...")
        val m1 = helloUntil("ca_m1")
        val nA = unhex(m1.getString("nA"))
        val epkA = unhex(m1.getString("epkA"))
        val pkKemA = if (m1.has("pk_kem_a")) unhex(m1.getString("pk_kem_a")) else null

        onStatus("Đang sinh khóa tạm + ký bản ghi bắt tay trên board...")
        val (nB, epkB, _) = device.caBegin() // role B does not offer its own ML-KEM key
        val (sigB, ctKemB) = device.caSignTranscript(CaCmd.ROLE_B, nA, epkA, nB, epkB, pkKemA, null)
        val idn = device.caGetIdentity()
        val tokenB = device.caGetStatusToken()
        val m2Fields = mutableMapOf(
            "nB" to hex(nB), "epkB" to hex(epkB), "issuing" to hex(idn.issuingCert),
            "cert" to hex(idn.cert), "token" to hex(tokenB), "sig" to hex(sigB),
        )
        if (ctKemB != null) m2Fields["ct_kem_b"] = hex(ctKemB)
        send("ca_m2", m2Fields)
        onStatus("Đã gửi M2, đang chờ M3...")

        val m3 = waitFor("ca_m3")
        val issuingA = unhex(m3.getString("issuing"))
        val certA = unhex(m3.getString("cert"))
        val tokenA = unhex(m3.getString("token"))
        val sigA = unhex(m3.getString("sig"))
        onStatus("Nhận M3, đang xác minh chứng chỉ + chữ ký của đối tác...")
        val vr = device.caVerifyPeer(CaCmd.ROLE_A, nA, epkA, nB, epkB, issuingA, certA, tokenA, sigA, pkKemA, ctKemB)
        if (!vr.ok) throw CaHandshakeException(verifyFailureMessage(vr))

        onStatus("Đối tác hợp lệ (${vr.peerId}), đang tính khóa phiên trên board...")
        device.caDeriveKeys(CaCmd.ROLE_B, nA, epkA, nB, epkB, pkKemA, ctKemB)
        val macB = device.caConfirm(CaCmd.ROLE_B, nA, epkA, nB, epkB, pkKemA, ctKemB)
        send("ca_m4", mapOf("mac" to hex(macB)))
        onStatus("Đang chờ xác nhận từ đối tác...")
        val m4 = waitFor("ca_m4")
        val vc = device.caVerifyConfirm(CaCmd.ROLE_A, nA, epkA, nB, epkB, unhex(m4.getString("mac")), pkKemA, ctKemB)
        if (vc != 0) throw CaHandshakeException("xác nhận lẫn nhau KHÔNG khớp (result=$vc)")
        return CaHandshakeResult(CaCmd.ROLE_B, vr.peerId ?: "?")
    }

    private fun verifyFailureMessage(vr: CaVerifyResult): String = when (vr.result) {
        1 -> "chuỗi chứng chỉ hoặc thẻ trạng thái của đối tác KHÔNG hợp lệ (mã lỗi ${vr.x509Status})"
        2 -> "chữ ký trên bản ghi bắt tay của đối tác KHÔNG khớp"
        3 -> "đối tác có cùng danh tính với mình (đang gọi chính board này?)"
        4 -> "gói tin của đối tác thiếu dữ liệu bắt buộc"
        else -> "VERIFY_PEER thất bại, result=${vr.result}"
    }
}
