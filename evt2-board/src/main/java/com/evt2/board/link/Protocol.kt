package com.evt2.board.link

import java.util.zip.CRC32

/**
 * Kotlin mirror of EVT2's Core_app/Middleware/CommandProtocol/command_protocol.h
 * wire format for the CMD_TYPE_MEDIA_FIRST..CMD_TYPE_MEDIA_LAST (0x03-0x10)
 * range, dispatched firmware-side by Core_app/App/protocol_adapters/media_protocol.c.
 * Ported from usb_encrypt_host/android's own link/Protocol.kt (that project's
 * PROTOCOL.md-derived framing) with two EVT2-specific differences, both
 * verified against EVT2's actual header, not assumed:
 *
 *   - PROTOCOL_VERSION is 1 here, matching command_protocol.h's
 *     CMD_PROTOCOL_VERSION (the reference project's own protocol.py/
 *     app_protocol.h use 2 -- a different, unrelated numbering; EVT2's
 *     firmware doesn't currently reject a mismatched VER byte, but sending
 *     the wrong one anyway would be confusing given HELLO's payload also
 *     carries this same value verbatim).
 *   - MAX_PAYLOAD is 49152 (raised from 32768, 2026-09-19 -- see
 *     command_protocol.h's CMD_PROTO_MAX_PAYLOAD doc comment for the real
 *     H.264 keyframe measurement and RAM-budget accounting behind the new
 *     value), matching CMD_PROTOCOL_HEADER's CMD_PROTO_MAX_PAYLOAD exactly
 *     (the reference's 65000 was sized for a different transport ceiling
 *     that doesn't apply here).
 *   - PacketType's 0x0F/0x10 are DECRYPT_CHUNK/DECRYPTED_CHUNK, not the
 *     reference's DEBUG_TIMING/DEBUG_TIMING_RESULT -- EVT2 exposes its own
 *     send-timing diagnostics through CMD_TYPE_QRNG's own sub-command
 *     instead (unrelated to this media channel), leaving 0x0F/0x10 free for
 *     the two-directional-crypto extension EVT2's media_protocol.c needs
 *     (see that file's own doc comment on why: unlike usb_encrypt_host,
 *     which only ever encrypts on the device and decrypts the peer's stream
 *     in Android software, EVT2 does BOTH directions on the device's AES-256-GCM
 *     hardware accelerator).
 *
 * Frame format: FLAG | escaped( HEADER(10B) + PAYLOAD(0..MAX_PAYLOAD) + CRC32(4B) ) | FLAG
 * HEADER (little-endian): VER(1) TYPE(1) SESSION_ID(2) SEQ(4) LENGTH(2)
 */
object Protocol {
    const val PROTOCOL_VERSION: Int = 1

    const val FLAG: Int = 0x7E
    const val ESC: Int = 0x7D
    const val ESC_XOR: Int = 0x20

    // HARD CEILING: the wire header's LENGTH field is 2 bytes (le16() below),
    // 0..65535 -- MAX_PAYLOAD can never exceed that, and here it's further
    // bounded to match command_protocol.h's CMD_PROTO_MAX_PAYLOAD (49152)
    // exactly, since that's the real ceiling the firmware enforces on both
    // its RX ring and TX body buffer.
    const val MAX_PAYLOAD: Int = 49152
    const val HEADER_LEN: Int = 10
    const val CRC_LEN: Int = 4
}

enum class PacketType(val value: Int) {
    HELLO(0x01),
    HELLO_ACK(0x02),
    START_STREAM(0x03),
    DATA_CHUNK(0x04),
    END_STREAM(0x05),
    ACK(0x06),
    NACK(0x07),
    ABORT_STREAM(0x08),
    PING(0x09),
    PONG(0x0A),
    ENCRYPT_RESULT(0x0B),
    ERROR(0x0C),
    RESET(0x0D),
    ENCRYPTED_CHUNK(0x0E),
    DECRYPT_CHUNK(0x0F),      // EVT2 extension -- host->device: [nonce 12B][tag 16B][ciphertext]
    DECRYPTED_CHUNK(0x10),    // EVT2 extension -- device->host: [acked_seq 4B][status 1B][plaintext, only if status==OK]
    QRNG(0x13),               // host->device: [sub_cmd 1B][params...] -- only DEVICE_STATUS, see DeviceLink.deviceStatus()
    RESULT(0x14),             // device->host: [sub_cmd 1B][status 1B][data...], same seq as the request in the header
    CA(0x15),                 // host->device: [sub_cmd 1B][params...] -- CA-based key-exchange handshake, see
                               // Core_app/App/protocol_adapters/ca_protocol.c and CaCmd below
    // 0x16 = CMD_TYPE_PROVISION (factory firmware only, not used by this app)
    FW_UPDATE(0x17);          // host->device: [sub_cmd 1B][params...] -- firmware info / update, answered by the
                               // application AND by Boot's updater, see FirmwareUpdater.kt and FwCmd

    companion object {
        fun fromValue(v: Int): PacketType? = entries.find { it.value == v }
    }
}

enum class StreamMode(val value: Int) {
    BATCH(0x00),
    LIVE_AUDIO(0x01),
}

enum class NackReason(val value: Int) {
    CRC_ERROR(0x01),
    OUT_OF_ORDER(0x02),
    UNKNOWN_SESSION(0x03),
    BUSY(0x04),
    BAD_LENGTH(0x05),
    UNSUPPORTED_VERSION(0x06);

    companion object {
        fun fromValue(v: Int): NackReason? = entries.find { it.value == v }
    }
}

/** CMD_TYPE_CA (0x15) sub-commands -- exact mirror of ca_protocol.c's ca_cmd_t. Wire format for each, and the whole
 *  handshake message flow: docs/key_exchange_ca_profile.md section 6. */
object CaCmd {
    const val GET_IDENTITY = 0x01
    const val GET_STATUS_TOKEN = 0x02
    const val BEGIN = 0x03
    const val SIGN_TRANSCRIPT = 0x04
    const val VERIFY_PEER = 0x05
    const val DERIVE_KEYS = 0x06
    const val CONFIRM = 0x07
    const val VERIFY_CONFIRM = 0x08
    const val END_SESSION = 0x09

    const val ROLE_A = 1 // "I am A" (initiator): epkA is mine
    const val ROLE_B = 2 // "I am B" (responder): epkB is mine
}

/** [role][nA 32B][epkA 65B][nB 32B][epkB 65B] -- the 195-byte block SIGN_TRANSCRIPT/VERIFY_PEER/DERIVE_KEYS/CONFIRM/
 *  VERIFY_CONFIRM all share, exactly matching ca_protocol.c's ca_quad_t / tools/ca_peer_sim.py's build_quad(). */
fun caQuad(role: Int, nA: ByteArray, epkA: ByteArray, nB: ByteArray, epkB: ByteArray): ByteArray {
    require(nA.size == 32 && epkA.size == 65 && nB.size == 32 && epkB.size == 65) {
        "bad quad field size: nA=${nA.size} epkA=${epkA.size} nB=${nB.size} epkB=${epkB.size}"
    }
    return byteArrayOf(role.toByte()) + nA + epkA + nB + epkB
}

/** Hybrid PQC (Giai đoạn 3, 2026-09-24, see CLAUDE.md) -- ML-KEM-768 sizes, MUST match Core_app/Middleware/PQC/
 *  pqc_kem.h / ca_protocol.c's CA_KEM_* exactly. This app never does any ML-KEM math itself (no library needed
 *  here at all): the actual keygen/encapsulate/decapsulate always runs on THIS device's own board, exactly like
 *  every other CA cryptographic operation (sign, verify, ECDH, HKDF, HMAC) -- this app only relays the resulting
 *  public key / ciphertext bytes to the peer over the relay (M1/M2) and passes the peer's back into its own
 *  board's calls, the same "board does the crypto, app just moves bytes" split DeviceLink.kt already has for
 *  everything else. */
object CaKem {
    const val PK_LEN = 1184  // role A's ML-KEM-768 public key
    const val CT_LEN = 1088  // role B's ML-KEM-768 ciphertext
}

/** [pk_kem_a_len:2B LE][pk_kem_a][ct_kem_b_len:2B LE][ct_kem_b] -- mirrors ca_protocol.c's ca_kem_ext_t wire form
 *  (read_kem_ext()) / tools/ca_wire.py's build_ext() exactly. `null` for a slot means "not offered/available this
 *  call" (0-length) -- the classical-only fallback, not an error; every quad-carrying sub-command since
 *  CA_PROTO_VERSION 2 (Giai đoạn 1) requires this trailer even when both slots are empty. */
fun caExt(pkKemA: ByteArray?, ctKemB: ByteArray?): ByteArray {
    fun slot(b: ByteArray?, expectLen: Int, name: String): ByteArray {
        if (b == null) return byteArrayOf(0, 0)
        require(b.size == expectLen) { "$name must be $expectLen bytes, got ${b.size}" }
        return byteArrayOf((b.size and 0xFF).toByte(), ((b.size shr 8) and 0xFF).toByte()) + b
    }
    return slot(pkKemA, CaKem.PK_LEN, "pkKemA") + slot(ctKemB, CaKem.CT_LEN, "ctKemB")
}

/** Result of CA_CMD_BEGIN: this device's fresh nonce/ephemeral key, plus (Giai đoạn 3) its freshly-generated
 *  ML-KEM-768 public key -- null if this boot's best-effort keygen failed (see ca_protocol.c's BEGIN doc comment;
 *  BEGIN still succeeds classically in that case) or, in principle, an older pre-Giai-đoạn-1 board. Destructures as
 *  (nMine, epkMine, pkKemMine). */
data class CaBeginResult(val nMine: ByteArray, val epkMine: ByteArray, val pkKemMine: ByteArray?)

/** This device's public material for the CA handshake -- what CA_CMD_GET_IDENTITY returns. Never contains a
 *  private key (the identity private key never leaves the SE052F). `rootPublicKey` is the trust anchor's key: a
 *  65-byte P-256 point on a wire-v2 board, a 2017-byte composite ML-DSA-65 + ECDSA-P256 key on a wire-v3 board
 *  (ca_protocol.c CA_PROTO_VERSION 3). */
data class CaIdentity(
    val deviceId: ByteArray,
    val cert: ByteArray,
    val issuingCert: ByteArray,
    val rootPublicKey: ByteArray,
    val rootSubject: ByteArray,
) {
    val isComposite: Boolean get() = rootPublicKey.size == 2017
}

/** Result of CA_CMD_VERIFY_PEER -- see ca_protocol.c's doc comment on that sub-command for exactly what each
 *  `result` value means (0 OK, 1 chain/token invalid, 2 transcript signature invalid, 3 peer is myself, 4 bad
 *  parameter). `x509Status` is only meaningful when result == 1 (a ca_x509_status_t numeric value). */
data class CaVerifyResult(val result: Int, val x509Status: Int, val peerId: String?) {
    val ok: Boolean get() = result == 0
}

/** DECRYPTED_CHUNK's status byte -- see media_protocol.c's media_decrypt_status_t. */
object DecryptStatus {
    const val OK = 0x00
    const val AUTH_FAIL = 0x01
}

class ProtocolException(message: String) : Exception(message)

data class Packet(
    val ver: Int,
    val type: Int,
    val sessionId: Int,
    val seq: Long,
    val payload: ByteArray,
) {
    override fun toString(): String {
        val typeName = PacketType.fromValue(type)?.name ?: "0x%02X".format(type)
        return "Packet($typeName, session=$sessionId, seq=$seq, len=${payload.size})"
    }
}

/** Zlib-compatible CRC32 (poly 0xEDB88320) -- java.util.zip.CRC32 implements the same algorithm,
 *  matching command_protocol.c's table-driven crc32_of(). */
private fun crc32(vararg parts: ByteArray): Long {
    val crc = CRC32()
    for (p in parts) crc.update(p)
    return crc.value
}

private fun escape(data: ByteArray): ByteArray {
    val out = ByteArray(data.size * 2) // worst case: every byte escaped
    var n = 0
    for (b in data) {
        val u = b.toInt() and 0xFF
        if (u == Protocol.FLAG || u == Protocol.ESC) {
            out[n++] = Protocol.ESC.toByte()
            out[n++] = (u xor Protocol.ESC_XOR).toByte()
        } else {
            out[n++] = b
        }
    }
    return out.copyOf(n)
}

private fun le16(v: Int): ByteArray = byteArrayOf((v and 0xFF).toByte(), ((v shr 8) and 0xFF).toByte())
private fun le32(v: Long): ByteArray = byteArrayOf(
    (v and 0xFF).toByte(), ((v shr 8) and 0xFF).toByte(),
    ((v shr 16) and 0xFF).toByte(), ((v shr 24) and 0xFF).toByte(),
)

fun encodePacket(type: Int, sessionId: Int, seq: Long, payload: ByteArray = ByteArray(0)): ByteArray {
    if (payload.size > Protocol.MAX_PAYLOAD) {
        throw ProtocolException("payload too large: ${payload.size} > ${Protocol.MAX_PAYLOAD}")
    }
    check(payload.size <= 0xFFFF) { "payload ${payload.size}B exceeds the wire LENGTH field's 16-bit range" }
    val header = ByteArray(Protocol.HEADER_LEN)
    header[0] = Protocol.PROTOCOL_VERSION.toByte()
    header[1] = type.toByte()
    System.arraycopy(le16(sessionId and 0xFFFF), 0, header, 2, 2)
    System.arraycopy(le32(seq and 0xFFFFFFFFL), 0, header, 4, 4)
    System.arraycopy(le16(payload.size), 0, header, 8, 2)

    val body = header + payload
    val crc = crc32(body)
    val bodyWithCrc = body + le32(crc)
    val escaped = escape(bodyWithCrc)

    val out = ByteArray(escaped.size + 2)
    out[0] = Protocol.FLAG.toByte()
    System.arraycopy(escaped, 0, out, 1, escaped.size)
    out[out.size - 1] = Protocol.FLAG.toByte()
    return out
}

/**
 * Streaming decoder: feed() raw bytes as they arrive from the USB serial
 * port, get back zero or more successfully-validated packets. Any
 * corrupted/incomplete frame is silently dropped and the decoder
 * resynchronizes on the next FLAG byte -- same philosophy as
 * command_protocol.c's decoder_feed().
 */
class FrameDecoder {
    private var buf = ByteArray(Protocol.HEADER_LEN + Protocol.MAX_PAYLOAD + Protocol.CRC_LEN)
    private var len = 0
    private var inFrame = false
    private var escapeNext = false

    fun feed(data: ByteArray): List<Packet> {
        val out = ArrayList<Packet>()
        for (raw in data) {
            val b = raw.toInt() and 0xFF
            if (b == Protocol.FLAG) {
                if (inFrame && len > 0) {
                    tryParse()?.let { out.add(it) }
                }
                len = 0
                escapeNext = false
                inFrame = true
                continue
            }
            if (!inFrame) continue // garbage before the first FLAG; ignore

            if (escapeNext) {
                appendByte((b xor Protocol.ESC_XOR).toByte())
                escapeNext = false
            } else if (b == Protocol.ESC) {
                escapeNext = true
            } else {
                appendByte(b.toByte())
            }
        }
        return out
    }

    private fun appendByte(b: Byte) {
        if (len < buf.size) {
            buf[len] = b
            len++
        } else {
            // Body larger than any legal frame: definitely garbage. Drop the
            // whole thing and wait for the next FLAG to resync, matching the
            // "silently drop, resync on next FLAG" contract.
            inFrame = false
        }
    }

    private fun tryParse(): Packet? {
        if (len < Protocol.HEADER_LEN + Protocol.CRC_LEN) return null
        val ver = buf[0].toInt() and 0xFF
        val type = buf[1].toInt() and 0xFF
        val sessionId = (buf[2].toInt() and 0xFF) or ((buf[3].toInt() and 0xFF) shl 8)
        val seq = (buf[4].toLong() and 0xFF) or
            ((buf[5].toLong() and 0xFF) shl 8) or
            ((buf[6].toLong() and 0xFF) shl 16) or
            ((buf[7].toLong() and 0xFF) shl 24)
        val length = (buf[8].toInt() and 0xFF) or ((buf[9].toInt() and 0xFF) shl 8)

        val expectedLen = Protocol.HEADER_LEN + length + Protocol.CRC_LEN
        if (len != expectedLen) return null

        val payload = buf.copyOfRange(Protocol.HEADER_LEN, Protocol.HEADER_LEN + length)
        val header = buf.copyOfRange(0, Protocol.HEADER_LEN)
        val crcReceived = (buf[Protocol.HEADER_LEN + length].toLong() and 0xFF) or
            ((buf[Protocol.HEADER_LEN + length + 1].toLong() and 0xFF) shl 8) or
            ((buf[Protocol.HEADER_LEN + length + 2].toLong() and 0xFF) shl 16) or
            ((buf[Protocol.HEADER_LEN + length + 3].toLong() and 0xFF) shl 24)
        val crcComputed = crc32(header, payload)
        if (crcReceived != crcComputed) return null

        return Packet(ver = ver, type = type, sessionId = sessionId, seq = seq and 0xFFFFFFFFL, payload = payload)
    }
}
