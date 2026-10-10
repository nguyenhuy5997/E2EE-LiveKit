package com.evt2.board.link

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Build
import androidx.core.content.ContextCompat
import com.hoho.android.usbserial.driver.CdcAcmSerialDriver
import com.hoho.android.usbserial.driver.UsbSerialPort
import com.hoho.android.usbserial.util.SerialInputOutputManager
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/** Raised when the USB link is confirmed dead; caller should reconnect. */
class LinkDownException(message: String) : Exception(message)

/**
 * Raised when a single real-time (LIVE_AUDIO) chunk got no reply within its
 * short retry budget, OR the device rejected a DECRYPT_CHUNK's GCM tag --
 * the link itself is fine, this one audio/video/decrypt chunk is just being
 * skipped. Distinct from LinkDownException so callers (and anyone reading a
 * stack trace) don't confuse "drop one frame" with "reconnect the whole
 * session."
 */
class ChunkDroppedException(message: String) : Exception(message)

/**
 * Talks to EVT2's video-call media protocol (command_protocol.h's
 * CMD_TYPE_MEDIA_FIRST..CMD_TYPE_MEDIA_LAST, dispatched firmware-side by
 * media_protocol.c) over the device's USB CDC-ACM port.
 *
 * Ported from usb_encrypt_host/android's own link/DeviceLink.kt, but with
 * its transport rewritten from a single global `sendMutex` (strict
 * stop-and-wait: every request blocks ALL others, audio and video included,
 * until its own reply arrives) to fire-and-forget / windowed dispatch --
 * see tools/device_link.py's module doc comment for the full story: this
 * was measured on real EVT2 hardware (2026-09-18) to cost ~1.3-1.85x
 * throughput versus letting independent requests have overlapping
 * round-trips, and the reference's own comments already note in
 * VideoCallEngine.kt that stop-and-wait audio+video sharing one Mutex is
 * an actual constraint on achievable frame rate -- this rewrite removes
 * that constraint at the transport layer instead of just tuning bitrate/fps
 * around it.
 *
 * A background reader (SerialInputOutputManager's own read thread, same as
 * the reference) decodes frames and dispatches each one by (type,
 * correlation-seq) to whichever coroutine is awaiting it via a
 * CompletableDeferred registered in `pending` -- multiple encryptChunk()/
 * decryptChunk() calls, from different coroutines (e.g. AudioCallEngine's
 * uplink/downlink loops running concurrently with VideoCallEngine's own),
 * can have requests in flight on the wire at the same time. A byte-budget
 * (MAX_IN_FLIGHT_BYTES) throttles how much unacknowledged request data can
 * be outstanding at once, to stay under the firmware's single 32KB RX ring
 * (platform_usb_stm32lib.c's USB_RX_RING_SIZE) -- uncapped concurrency
 * measured real corrupted/dropped frames on real hardware in the Python
 * prototype (tools/device_link.py) before this budget was added; the same
 * risk applies here unchanged, since it is a property of the firmware's
 * RX ring, not the client language.
 *
 * decryptChunk() has NO reference counterpart -- usb_encrypt_host's own
 * DeviceLink.kt only ever sends DATA_CHUNK (encrypt-only device, see that
 * project's crypto/AesGcm.kt for its software-decrypt fallback). EVT2's
 * media_protocol.c added CMD_TYPE_DECRYPT_CHUNK/CMD_TYPE_DECRYPTED_CHUNK
 * specifically so this app never needs the AES key in its own process at
 * all -- both directions' crypto stay on the device's hardware.
 */
class DeviceLink(private val appContext: Context) {

    companion object {
        private const val ACTION_USB_PERMISSION = "com.evt2.board.USB_PERMISSION"
        private const val BAUD_RATE = 115_200
        // SerialInputOutputManager reads one max-packet (512 B at USB HS) per call by default. A host that drains the
        // board's IN endpoint one packet at a time is the slow-reader pattern behind the firmware's TXFE interrupt
        // storm and lost large replies (SDCARD-QRNG CLAUDE.md), so read up to 16 KB per request. 16384 is also the
        // largest bulk UsbRequest that Android 8 (API 26-27) accepts.
        private const val READ_BUFFER_BYTES = 16_384
        private const val HELLO_TIMEOUT_MS = 2_000L
        private const val HELLO_RETRIES = 5
        private const val ACK_TIMEOUT_MS = 1_000L // control-plane only: START_STREAM etc, via sendAndAwaitAck()
        private const val CONTROL_MAX_RETRIES = 5
        private const val BUSY_BACKOFF_MS = 500L

        // Real-time (LIVE_AUDIO) chunks -- audio, video, AND decrypt all go through
        // encryptChunk()/decryptChunk(). Deliberately much more aggressive than the
        // control-plane constants above: a dropped audio/video chunk is a non-event (the
        // call just skips one frame), and unlike the reference's Mutex-serialized design a
        // slow chunk here no longer blocks every other in-flight request either -- but the
        // retry budget itself is kept just as tight, since a genuinely stuck device should
        // still surface quickly rather than accumulate unbounded retries.
        private const val CHUNK_ACK_TIMEOUT_MS = 200L
        private const val CHUNK_MAX_RETRIES = 3
        private const val CHUNK_BUSY_BACKOFF_MS = 30L

        // Raised 20_000 -> 26_000 (2026-09-18) then -> 55_000 (2026-09-19), the second
        // time alongside command_protocol.h's CMD_PROTO_MAX_PAYLOAD going 32768 -> 49152
        // and USB_RX_RING_SIZE going 32768 -> 65536 (see both those constants' own doc
        // comments for the full story: a real keyframe measured up to ~30010B broke the
        // 26000B cap the same way a 22876B one broke the original 20000B cap -- a request
        // bigger than this cap can ONLY ever be admitted via acquireBudget()'s
        // "current == 0" escape hatch, never by fitting alongside other traffic, no matter
        // how much contention there is, so raising CMD_PROTO_MAX_PAYLOAD without ALSO
        // raising this cap would just move the same failure to a higher chunk size instead
        // of fixing it). MEDIA_MAX_DATA_CHUNK is now 49120B (49152 - 32B overhead) -- a
        // single max-size chunk plus roughly one more audio chunk (3200B) still fits under
        // 55000B without needing the escape hatch at all, unlike the old 26000B cap which
        // left a max-size (then ~30KB) chunk almost no room to share with anything.
        // 55000B leaves ~10.3KB (~16%) of headroom under the new 65536B ring -- narrower
        // proportionally than the original 12.7KB/32768B (~39%), but real ciphertext's
        // near-random escaping overhead stays close to its ~1.02x typical case (not the
        // adversarial 2x worst case), and the firmware drains its single main loop fast
        // enough that more than one request's worth of undrained ring data at a time isn't
        // expected in practice -- same reasoning the 26000B revision already relied on.
        // This cap, CMD_PROTO_MAX_PAYLOAD, USB_RX_RING_SIZE, and VideoCallEngine's own
        // fps/bitrate tuning are NOT independent levers -- they all bound on the same real
        // keyframe size. tools/device_link.py's MAX_IN_FLIGHT_BYTES must match this exactly.
        // internal, not private: VideoCallEngine.kt's own PIPELINE_DEPTH is computed
        // directly from these two (see that file's doc comment) so it can never silently
        // drift out of sync with them, mirroring tools/device_loopback_test.py importing
        // the same constants from tools/device_link.py rather than duplicating the numbers.
        // TESTED 2026-09-25 and reverted: temporarily cut to 4_000 to test an H7S3-RX-ring-drain-rate hypothesis
        // for the real-call video decrypt failures -- it made no difference (video still failed at the same
        // rate), which helped rule out concurrency/budget as the cause. The actual root cause was a hardware/HAL
        // bug (CRYP/SAES GCM, and even plain CTR mode, silently mishandling any length not a multiple of 16 bytes
        // -- see platform_crypto.c's aes256_gcm_run() doc comment), fixed on the firmware side; this budget was
        // never the problem, so it's back to its EVT2/H753-tuned value.
        internal const val MAX_IN_FLIGHT_BYTES = 55_000
        private const val BUDGET_POLL_MS = 2L

        // CA handshake (docs/key_exchange_ca_profile.md section 6) -- these are NOT
        // best-effort: a failure here means the handshake as a whole failed, so callers (CaHandshake.kt) see a real
        // exception, not null. BEGIN needs a live QRNG draw and VERIFY_PEER needs two SE052F imports + three ECDSA
        // verifies (measured ~1s on real hardware, "Test 4" in the 2026-09-22 CA review) -- both get extra margin.
        private const val CA_TIMEOUT_MS = 3_000L
        private const val CA_BEGIN_TIMEOUT_MS = 5_000L
        private const val CA_VERIFY_TIMEOUT_MS = 10_000L
        // Wire v3 (composite ML-DSA-65 + ECDSA-P256 identity, SDQRNG_V8Y 2026-10-04): the transcript signature runs
        // ML-DSA-65 on the MCU, and VERIFY_PEER does 4 ML-DSA-65 + 4 ECDSA verifies -- more margin.
        private const val CA_V3_SIGN_TIMEOUT_MS = 20_000L
        private const val CA_V3_VERIFY_TIMEOUT_MS = 30_000L
        // GET_IDENTITY's root public key: 65 B (v2, classical P-256 point) or 2017 B (v3, composite key)
        private const val CA_V2_ROOT_PK_LEN = 65
        private const val CA_V3_ROOT_PK_LEN = 2017

        private const val QRNG_CMD_DEVICE_STATUS = 0x11 // see deviceStatus()

        // PRIORITY EXPERIMENT (2026-09-19, ported from tools/device_link.py after real
        // measurement on the host tool showed audio chunks queueing behind video fragments
        // with no ordering between them -- see that file's own AUDIO_RESERVE_BYTES doc
        // comment for the full story). Video's own admission cap is MAX_IN_FLIGHT_BYTES
        // minus this reserve, so video can never consume the entire budget and lock audio
        // out even under a sustained video flood; video's acquire additionally yields to
        // any audio request currently trying to get admitted (pendingAudioWaiters > 0),
        // even if video's own request would otherwise fit right now -- this is what makes
        // audio actually jump the queue rather than merely have guaranteed headroom.
        internal const val AUDIO_RESERVE_BYTES = 8_000

        // Bounds writerLoop()'s audio-priority scheduling -- see that function's own doc
        // comment for the real starvation bug this caps. Small on purpose: audio chunks are
        // ~3.2KB (a few ms to write), so even the worst case of this many consecutive audio
        // writes ahead of one video write adds only a small, bounded delay to video, while
        // still giving audio a real, meaningful edge over video's much larger (up to ~49KB)
        // chunks the rest of the time.
        private const val MAX_CONSECUTIVE_AUDIO_WRITES = 4

        private val HEADER_SEQ_REPLY_TYPES = setOf(PacketType.HELLO_ACK.value, PacketType.PONG.value, PacketType.RESULT.value)
        private val PAYLOAD_SEQ_REPLY_TYPES = setOf(
            PacketType.ACK.value, PacketType.NACK.value,
            PacketType.ENCRYPTED_CHUNK.value, PacketType.DECRYPTED_CHUNK.value,
        )
    }

    private var port: UsbSerialPort? = null
    private var ioManager: SerialInputOutputManager? = null
    private val decoder = FrameDecoder()
    private var sessionId = 0

    /** CA wire version of the connected board: false = v2 (classical identity, 1-byte token/signature lengths),
     *  true = v3 (composite identity, 2-byte lengths, ca_protocol.c CA_PROTO_VERSION 3). Learned from the
     *  GET_IDENTITY layout (caWireV3()); reset on every connect(), since a different board may be plugged in. */
    private var caV3: Boolean? = null

    private val seqCounter = AtomicLong(0)
    private val inFlightBytes = AtomicInteger(0)
    private val pendingAudioWaiters = AtomicInteger(0) // see AUDIO_RESERVE_BYTES's doc comment

    // WRITER SCHEDULING (2026-09-19, real-hardware finding): UsbSerialPort.write() must still
    // be fully serialized -- this is a single USB CDC serial link, and interleaving two writes'
    // bytes on the wire would corrupt BOTH frames' framing, not just a lock-contention nuisance.
    // The PREVIOUS implementation serialized via a plain `synchronized(writeLock)`, which gave
    // audio and video writes no ordering relative to each other at all: real on-device logcat
    // caught `Long monitor contention ... waiters=5 ... for 320ms` on exactly this lock during a
    // real call, and in the SAME window MediaCodec itself reported its own encoder input feed
    // stalling for 600-1100ms+ at a time -- acquireBudget()'s AUDIO_RESERVE_BYTES/
    // pendingAudioWaiters scheme only prioritizes which request gets ADMITTED into the byte
    // budget first; it does nothing once a request is already past that point and just needs
    // its bytes physically written to the wire, where a large already-in-flight video write (up
    // to ~49KB) could make a freshly-admitted audio write wait behind it with no priority at
    // all. Replaced with a single dedicated writer coroutine draining two priority-ordered
    // queues (audio checked first every iteration) instead of raw lock contention -- this keeps
    // the same one-write-at-a-time hardware constraint but bounds audio's worst-case wait to
    // "whatever write is CURRENTLY in flight" (unavoidable -- a write can't be preempted
    // mid-flight without corrupting it) rather than "however many video writes happened to win
    // the lock race first".
    private class PendingWrite(val frame: ByteArray) {
        val completion = CompletableDeferred<Unit>()
    }
    private var audioWriteQueue = Channel<PendingWrite>(capacity = Channel.UNLIMITED)
    private var videoWriteQueue = Channel<PendingWrite>(capacity = Channel.UNLIMITED)
    private var writerScope: CoroutineScope? = null

    private data class PendingKey(val type: Int, val corrSeq: Long)
    private val pending = ConcurrentHashMap<PendingKey, CompletableDeferred<Packet>>()

    /** Scan for the device, request permission if needed, open the port, and handshake. */
    suspend fun connect(match: UsbDeviceMatch = UsbPortFinder.DEFAULT_MATCH) {
        caV3 = null
        val usbManager = appContext.getSystemService(Context.USB_SERVICE) as UsbManager
        val device = UsbPortFinder.findDevice(usbManager, match)
            ?: throw LinkDownException("no USB device matching VID=0x%04X PID=0x%04X".format(match.vid, match.pid))

        if (!usbManager.hasPermission(device)) {
            requestPermission(usbManager, device)
        }

        val connection = usbManager.openDevice(device)
            ?: throw LinkDownException("failed to open USB device (permission denied or device busy)")

        val driver = CdcAcmSerialDriver(device)
        val serialPort = driver.ports.firstOrNull()
            ?: throw LinkDownException("device exposes no CDC-ACM port")
        serialPort.open(connection)
        serialPort.setParameters(BAUD_RATE, 8, UsbSerialPort.STOPBITS_1, UsbSerialPort.PARITY_NONE)
        port = serialPort

        val manager = SerialInputOutputManager(serialPort, object : SerialInputOutputManager.Listener {
            override fun onNewData(data: ByteArray) {
                for (pkt in decoder.feed(data)) {
                    dispatch(pkt)
                }
            }

            override fun onRunError(e: Exception) {
                failAllPending(LinkDownException("USB read error: ${e.message}"))
            }
        })
        manager.readBufferSize = READ_BUFFER_BYTES
        ioManager = manager
        manager.start() // owns its own read/write threads -- no external Executor needed

        // Fresh queues per connect() (mirroring port/ioManager's own reset-on-reconnect
        // pattern) -- a kotlinx.coroutines Channel stays closed forever once closed, so a
        // previous session's (possibly-closed, from disconnect()) channels can't be reused.
        audioWriteQueue = Channel(capacity = Channel.UNLIMITED)
        videoWriteQueue = Channel(capacity = Channel.UNLIMITED)
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        writerScope = scope
        val audioQ = audioWriteQueue
        val videoQ = videoWriteQueue
        scope.launch { writerLoop(audioQ, videoQ) }

        resetAndHandshake()
    }

    suspend fun disconnect() {
        ioManager?.stop()
        ioManager = null
        try {
            port?.close()
        } catch (_: Exception) {
        }
        port = null
        writerScope?.cancel()
        writerScope = null
        audioWriteQueue.close()
        videoWriteQueue.close()
        // Fail anything left buffered so no caller is stuck awaiting a write that will now
        // never happen (the writer coroutine that would have drained it was just cancelled).
        while (true) {
            val leftover = audioWriteQueue.tryReceive().getOrNull()
                ?: videoWriteQueue.tryReceive().getOrNull()
                ?: break
            leftover.completion.completeExceptionally(LinkDownException("disconnected"))
        }
        failAllPending(LinkDownException("disconnected"))
    }

    /** Single writer for the whole USB link -- see PendingWrite's doc comment on why this
     *  exists instead of a plain lock. Audio is drained ahead of video whenever both have
     *  something waiting; within one lane, order is FIFO.
     *
     *  BOUNDED, not absolute, priority -- REAL BUG found on real hardware minutes after this
     *  was first written with a plain "always check audio first" rule: audio pipelines up to
     *  PIPELINE_DEPTH concurrent chunks across BOTH its uplink and downlink lanes, so during
     *  an active call this loop finds a freshly-queued audio item ready almost every single
     *  time it re-checks after finishing a write -- video never got picked AT ALL for 16+
     *  real seconds (captured kept climbing at 30fps, sent stayed pinned at 3-4, zero
     *  errors logged, since nothing was ever failing -- video was simply never being
     *  scheduled). Capping consecutive audio writes and forcing a video turn once the cap is
     *  hit bounds video's worst-case wait to a handful of small audio writes instead of "as
     *  long as audio keeps flowing, which is the entire call." */
    private suspend fun writerLoop(audioQueue: Channel<PendingWrite>, videoQueue: Channel<PendingWrite>) {
        var consecutiveAudio = 0
        while (true) {
            val item = try {
                if (consecutiveAudio < MAX_CONSECUTIVE_AUDIO_WRITES) {
                    audioQueue.tryReceive().getOrNull()?.also { consecutiveAudio++ }
                        ?: videoQueue.tryReceive().getOrNull()?.also { consecutiveAudio = 0 }
                        ?: select {
                            audioQueue.onReceive { consecutiveAudio++; it }
                            videoQueue.onReceive { consecutiveAudio = 0; it }
                        }
                } else {
                    // Cap hit: force video ahead of audio for this one pick, even if audio
                    // already has something waiting, then reset the counter.
                    videoQueue.tryReceive().getOrNull()?.also { consecutiveAudio = 0 }
                        ?: audioQueue.tryReceive().getOrNull()?.also { consecutiveAudio++ }
                        ?: select {
                            videoQueue.onReceive { consecutiveAudio = 0; it }
                            audioQueue.onReceive { consecutiveAudio++; it }
                        }
                }
            } catch (_: Exception) {
                return // both channels closed (disconnect()) -- nothing left to drain here
            }
            val currentPort = port
            if (currentPort == null) {
                item.completion.completeExceptionally(LinkDownException("port not open"))
                continue
            }
            try {
                currentPort.write(item.frame, 1000)
                item.completion.complete(Unit)
            } catch (e: Exception) {
                item.completion.completeExceptionally(LinkDownException("write failed: ${e.message}"))
            }
        }
    }

    private fun failAllPending(cause: Exception) {
        val keys = pending.keys.toList()
        for (k in keys) {
            pending.remove(k)?.completeExceptionally(cause)
        }
    }

    private suspend fun requestPermission(usbManager: UsbManager, device: UsbDevice) {
        val granted = CompletableDeferred<Boolean>()
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.action != ACTION_USB_PERMISSION) return
                val ok = intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)
                granted.complete(ok)
            }
        }
        val filter = IntentFilter(ACTION_USB_PERMISSION)
        ContextCompat.registerReceiver(appContext, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
        try {
            // MUTABLE + EXPLICIT intent (setPackage), NOT FLAG_IMMUTABLE: UsbManager fills
            // EXTRA_DEVICE / EXTRA_PERMISSION_GRANTED into this PendingIntent's intent when
            // it delivers the user's answer, so the system needs to be able to modify it -- an
            // immutable one is delivered without those extras and `granted` would read false
            // even after the user taps Allow. The Android 14+ (targetSdk 34+) rule that
            // broke the old code is narrower: a MUTABLE PendingIntent must not wrap an
            // IMPLICIT intent (SecurityException, seen on an Android 15 phone) -- the fix for
            // that is naming our own package on the intent, which is what usb-serial-for-
            // android's own example does too.
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0
            val pendingIntent = PendingIntent.getBroadcast(
                appContext, 0, Intent(ACTION_USB_PERMISSION).setPackage(appContext.packageName), flags,
            )
            usbManager.requestPermission(device, pendingIntent)
            val result = withTimeoutOrNull(30_000L) { granted.await() }
            if (result != true) {
                throw LinkDownException("USB permission denied or not granted in time")
            }
        } finally {
            appContext.unregisterReceiver(receiver)
        }
    }

    private suspend fun resetAndHandshake() {
        sendFireAndForget(PacketType.RESET.value, 0, 0, ByteArray(0))
        repeat(HELLO_RETRIES) {
            try {
                requestOnce(PacketType.HELLO.value, 0, byteArrayOf(Protocol.PROTOCOL_VERSION.toByte()),
                    PacketType.HELLO_ACK.value, HELLO_TIMEOUT_MS)
                return
            } catch (_: ChunkDroppedException) {
                // no reply within this attempt's timeout -- retry
            }
        }
        throw LinkDownException("device did not respond to HELLO after $HELLO_RETRIES attempts")
    }

    /** Opens one STREAM_MODE.LIVE_AUDIO session; call once per call, before encryptChunk()/decryptChunk(). */
    suspend fun startAudioSession(streamName: String = "android-call"): Int {
        sessionId = (sessionId + 1) and 0xFFFF
        val id = sessionId
        val nameBytes = streamName.toByteArray(Charsets.UTF_8).copyOf(32)
        val payload = le32(0) + nameBytes + byteArrayOf(StreamMode.LIVE_AUDIO.value.toByte())
        sendAndAwaitAck(PacketType.START_STREAM.value, id, payload)
        return id
    }

    fun abortSession(sessionIdToAbort: Int) {
        // Fire-and-forget: tells the device to drop any state for this session without
        // waiting for a reply (media_protocol.c's handle_abort_stream() sends none).
        sendFireAndForget(PacketType.ABORT_STREAM.value, sessionIdToAbort, 0, ByteArray(0))
    }

    /**
     * Sends one plaintext chunk to be AES-256-GCM encrypted by the device
     * (STREAM_MODE.LIVE_AUDIO), returns [nonce 12B][tag 16B][ciphertext].
     * Safe to call concurrently -- from multiple coroutines, and alongside
     * decryptChunk() -- see the class doc comment.
     */
    suspend fun encryptChunk(sessionId: Int, plaintext: ByteArray, isAudio: Boolean = false): ByteArray {
        var lastError: Exception? = null
        repeat(CHUNK_MAX_RETRIES) {
            val reply = try {
                requestOnce(PacketType.DATA_CHUNK.value, sessionId, plaintext,
                    PacketType.ENCRYPTED_CHUNK.value, CHUNK_ACK_TIMEOUT_MS, alsoAcceptType = PacketType.NACK.value,
                    isAudio = isAudio)
            } catch (e: ChunkDroppedException) {
                lastError = e
                return@repeat
            }
            if (reply.type == PacketType.ENCRYPTED_CHUNK.value) {
                return reply.payload.copyOfRange(4, reply.payload.size)
            }
            val reason = if (reply.payload.size > 4) reply.payload[4].toInt() and 0xFF else 0
            if (reason == NackReason.BUSY.value) delay(CHUNK_BUSY_BACKOFF_MS)
        }
        throw lastError ?: ChunkDroppedException("no reply for DATA_CHUNK after $CHUNK_MAX_RETRIES attempts")
    }

    /**
     * EVT2 extension (see class doc comment). Sends one
     * [nonce 12B][tag 16B][ciphertext] chunk from the peer's stream to be
     * AES-256-GCM decrypted+verified by the device, returns the plaintext.
     */
    suspend fun decryptChunk(sessionId: Int, nonceTagCiphertext: ByteArray, isAudio: Boolean = false): ByteArray {
        var lastError: Exception? = null
        repeat(CHUNK_MAX_RETRIES) {
            val reply = try {
                requestOnce(PacketType.DECRYPT_CHUNK.value, sessionId, nonceTagCiphertext,
                    PacketType.DECRYPTED_CHUNK.value, CHUNK_ACK_TIMEOUT_MS, isAudio = isAudio)
            } catch (e: ChunkDroppedException) {
                lastError = e
                return@repeat // no reply at all -- transient, worth retrying
            }
            val status = if (reply.payload.isNotEmpty()) reply.payload[4].toInt() and 0xFF else -1
            if (status != DecryptStatus.OK) {
                // Deterministic rejection (bad GCM tag) -- the sender doesn't re-encrypt the
                // same bytes on a retry, so retrying here can't succeed. Fail immediately
                // instead of burning the retry budget.
                throw ChunkDroppedException("device rejected ciphertext (status=$status) -- tampered/corrupted chunk")
            }
            return reply.payload.copyOfRange(5, reply.payload.size)
        }
        throw lastError ?: ChunkDroppedException("no reply for DECRYPT_CHUNK after $CHUNK_MAX_RETRIES attempts")
    }

    // ---- CA handshake (CMD_TYPE_CA) -- see docs/key_exchange_ca_profile.md section 6 for the wire format and the
    // full message flow; ca_protocol.c is the firmware side these mirror one for one. Every method here does ONE
    // request/response round trip; CaHandshake.kt strings them together into the actual 3-message-plus-confirmation
    // protocol over the relay. None of these retry on their own (unlike encryptChunk()/decryptChunk()): a dropped
    // reply here is surfaced as a real exception, since the handshake as a whole must be redone from BEGIN if any
    // single step fails, not silently retried mid-step.

    private fun caResultPayload(reply: Packet, what: String, minLen: Int): ByteArray {
        val p = reply.payload
        if (p.size < minLen) throw LinkDownException("CA $what: reply too short (${p.size} bytes)")
        return p
    }

    /** This device's own certificate chain + trust anchor -- send to the peer (M2/M3) and to import CA_CMD_VERIFY_PEER's
     *  chain-of-trust root locally is NOT needed since VERIFY_PEER already knows its own root; this is only for
     *  telling the OTHER side who we are. */
    suspend fun caGetIdentity(): CaIdentity {
        val reply = requestOnce(PacketType.CA.value, 0, byteArrayOf(CaCmd.GET_IDENTITY.toByte()), PacketType.RESULT.value, CA_TIMEOUT_MS)
        val p = caResultPayload(reply, "GET_IDENTITY", 2)
        if (p[1].toInt() != 0) throw LinkDownException("CA GET_IDENTITY failed, status=${p[1].toInt() and 0xFF}")
        var o = 2
        val idLen = p[o].toInt() and 0xFF; o += 1
        val id = p.copyOfRange(o, o + idLen); o += idLen
        val certLen = (p[o].toInt() and 0xFF) or ((p[o + 1].toInt() and 0xFF) shl 8); o += 2
        val cert = p.copyOfRange(o, o + certLen); o += certLen
        val issuingLen = (p[o].toInt() and 0xFF) or ((p[o + 1].toInt() and 0xFF) shl 8); o += 2
        val issuing = p.copyOfRange(o, o + issuingLen); o += issuingLen
        // The rest is [root_pk][root_subj_len:1][root_subj]; the root key's size tells the wire version (v2 65 B,
        // v3 2017 B). Only one of the two lengths makes the remaining bytes add up exactly.
        val rest = p.size - o
        val v3 = rest >= CA_V3_ROOT_PK_LEN + 1 &&
            rest == CA_V3_ROOT_PK_LEN + 1 + (p[o + CA_V3_ROOT_PK_LEN].toInt() and 0xFF)
        val v2 = rest >= CA_V2_ROOT_PK_LEN + 1 &&
            rest == CA_V2_ROOT_PK_LEN + 1 + (p[o + CA_V2_ROOT_PK_LEN].toInt() and 0xFF)
        if (v3 == v2) throw LinkDownException("CA GET_IDENTITY: cannot tell the root key size ($rest bytes left)")
        caV3 = v3
        val rootPkLen = if (v3) CA_V3_ROOT_PK_LEN else CA_V2_ROOT_PK_LEN
        val rootPk = p.copyOfRange(o, o + rootPkLen); o += rootPkLen
        val rootSubjLen = p[o].toInt() and 0xFF; o += 1
        val rootSubj = p.copyOfRange(o, o + rootSubjLen)
        return CaIdentity(id, cert, issuing, rootPk, rootSubj)
    }

    /** True if the board speaks CA wire v3 (see caV3); asks GET_IDENTITY once per connection to find out. */
    suspend fun caWireV3(): Boolean = caV3 ?: run { caGetIdentity(); caV3 ?: false }

    private fun le16(n: Int) = byteArrayOf((n and 0xFF).toByte(), ((n shr 8) and 0xFF).toByte())

    /** A length field of the size the board's wire version uses for tokens/signatures (v2 1 byte, v3 2 bytes LE). */
    private fun caLen(n: Int, v3: Boolean): ByteArray {
        if (!v3 && n > 0xFF) throw LinkDownException("CA: $n bytes do not fit a wire-v2 1-byte length")
        return if (v3) le16(n) else byteArrayOf(n.toByte())
    }

    /** Latest status token this device holds (revocation + trusted-time proof, docs/key_exchange_ca_profile.md
     *  section 3) -- send along with the certificate chain in M2/M3. */
    suspend fun caGetStatusToken(): ByteArray {
        val reply = requestOnce(PacketType.CA.value, 0, byteArrayOf(CaCmd.GET_STATUS_TOKEN.toByte()), PacketType.RESULT.value, CA_TIMEOUT_MS)
        val v3 = caWireV3()
        val p = caResultPayload(reply, "GET_STATUS_TOKEN", if (v3) 4 else 3)
        if (p[1].toInt() != 0) throw LinkDownException("CA GET_STATUS_TOKEN failed, status=${p[1].toInt() and 0xFF}")
        return if (v3) {
            val len = (p[2].toInt() and 0xFF) or ((p[3].toInt() and 0xFF) shl 8)
            p.copyOfRange(4, 4 + len)
        } else {
            val len = p[2].toInt() and 0xFF
            p.copyOfRange(3, 3 + len)
        }
    }

    /** Starts a fresh handshake session (ending any previous one first): a new ephemeral EC key pair (SE052F,
     *  transient, never written to flash), a fresh QRNG nonce, and (Giai đoạn 1/3, best-effort) a fresh ML-KEM-768
     *  keypair -- see CaBeginResult's doc comment. Call once per call, before anything else in this section. */
    suspend fun caBegin(): CaBeginResult {
        val reply = requestOnce(PacketType.CA.value, 0, byteArrayOf(CaCmd.BEGIN.toByte()), PacketType.RESULT.value, CA_BEGIN_TIMEOUT_MS)
        val p = caResultPayload(reply, "BEGIN", 2 + 32 + 65 + 2)
        if (p[1].toInt() != 0) throw LinkDownException("CA BEGIN failed, status=${p[1].toInt() and 0xFF}")
        val nMine = p.copyOfRange(2, 34)
        val epkMine = p.copyOfRange(34, 99)
        val pkLen = (p[99].toInt() and 0xFF) or ((p[100].toInt() and 0xFF) shl 8)
        val pkKemMine = if (pkLen != 0) p.copyOfRange(101, 101 + pkLen) else null
        return CaBeginResult(nMine, epkMine, pkKemMine)
    }

    /** Signs the handshake transcript (this device's role + both nonces + both ephemeral keys + the ML-KEM-768
     *  extension, if any) with the device identity key. `role` is MY role (CaCmd.ROLE_A if I sent nA/epkA, ROLE_B
     *  if I sent nB/epkB). `pkKemA`/`ctKemB` are `null` for a classical-only call. Returns (sig, ctKemBActual) --
     *  for role B with a valid `pkKemA` offered, ctKemBActual is a FRESHLY-COMPUTED ciphertext this device must
     *  relay onward to the peer (M2), cached on-chip and reused verbatim by every later call this session (see
     *  ca_protocol.c's s_kem_ct_b doc comment -- ML-KEM encapsulation is randomized, so it can only be computed
     *  once); for role A it is simply `ctKemB` echoed back. */
    suspend fun caSignTranscript(
        role: Int, nA: ByteArray, epkA: ByteArray, nB: ByteArray, epkB: ByteArray,
        pkKemA: ByteArray? = null, ctKemB: ByteArray? = null,
    ): Pair<ByteArray, ByteArray?> {
        val v3 = caWireV3()
        val extra = byteArrayOf(CaCmd.SIGN_TRANSCRIPT.toByte()) + caQuad(role, nA, epkA, nB, epkB) + caExt(pkKemA, ctKemB)
        val reply = requestOnce(PacketType.CA.value, 0, extra, PacketType.RESULT.value,
            if (v3) CA_V3_SIGN_TIMEOUT_MS else CA_TIMEOUT_MS)
        val p = caResultPayload(reply, "SIGN_TRANSCRIPT", if (v3) 4 else 3)
        if (p[1].toInt() != 0) throw LinkDownException("CA SIGN_TRANSCRIPT failed, status=${p[1].toInt() and 0xFF}")
        val sigLen = if (v3) (p[2].toInt() and 0xFF) or ((p[3].toInt() and 0xFF) shl 8) else p[2].toInt() and 0xFF
        val sigOff = if (v3) 4 else 3
        val sig = p.copyOfRange(sigOff, sigOff + sigLen)
        var o = sigOff + sigLen
        val ctLen = (p[o].toInt() and 0xFF) or ((p[o + 1].toInt() and 0xFF) shl 8); o += 2
        val ctActual = if (ctLen != 0) p.copyOfRange(o, o + ctLen) else null
        return sig to ctActual
    }

    /** Verifies the PEER's certificate chain (up to this device's trusted root), status token, and transcript
     *  signature -- everything a peer sent in M2 (or M3). `peerRole` is the peer's OWN role (the role they signed
     *  as: CaCmd.ROLE_A or ROLE_B), not mine. `pkKemA`/`ctKemB` are whatever the PEER claims to have signed over --
     *  trusted at face value for message reconstruction only (a lie in either just makes the signature check fail),
     *  mirrors ca_protocol.c's VERIFY_PEER exactly. See CaVerifyResult's doc comment for the result codes. */
    suspend fun caVerifyPeer(
        peerRole: Int, nA: ByteArray, epkA: ByteArray, nB: ByteArray, epkB: ByteArray,
        issuing: ByteArray, leaf: ByteArray, token: ByteArray, sig: ByteArray,
        pkKemA: ByteArray? = null, ctKemB: ByteArray? = null,
    ): CaVerifyResult {
        val v3 = caWireV3()
        val extra = byteArrayOf(CaCmd.VERIFY_PEER.toByte()) + caQuad(peerRole, nA, epkA, nB, epkB) + caExt(pkKemA, ctKemB) +
            le16(issuing.size) + issuing +
            le16(leaf.size) + leaf +
            caLen(token.size, v3) + token +
            caLen(sig.size, v3) + sig
        val reply = requestOnce(PacketType.CA.value, 0, extra, PacketType.RESULT.value,
            if (v3) CA_V3_VERIFY_TIMEOUT_MS else CA_VERIFY_TIMEOUT_MS)
        val p = caResultPayload(reply, "VERIFY_PEER", 3)
        val result = p[1].toInt() and 0xFF
        val status = p[2].toInt() and 0xFF
        var peerId: String? = null
        if (result == 0 && p.size > 3) {
            val idLen = p[3].toInt() and 0xFF
            peerId = String(p.copyOfRange(4, 4 + idLen), Charsets.US_ASCII)
        }
        return CaVerifyResult(result, status, peerId)
    }

    /** ECDH (this device's ephemeral key against the peer's, chosen by `role`) -- combined with ML-KEM-768 via a
     *  software HKDF when `pkKemA`/`ctKemB` are both non-null (hybrid, see ca_protocol.c's DERIVE_KEYS doc
     *  comment), otherwise the unchanged classical path entirely inside the SE052F -- the resulting AES-256-GCM
     *  session keys never cross USB either way; this call only reports success/failure. Requires caBegin() to have
     *  run in this session. `role` is MY role. */
    suspend fun caDeriveKeys(
        role: Int, nA: ByteArray, epkA: ByteArray, nB: ByteArray, epkB: ByteArray,
        pkKemA: ByteArray? = null, ctKemB: ByteArray? = null,
    ) {
        val extra = byteArrayOf(CaCmd.DERIVE_KEYS.toByte()) + caQuad(role, nA, epkA, nB, epkB) + caExt(pkKemA, ctKemB)
        val reply = requestOnce(PacketType.CA.value, 0, extra, PacketType.RESULT.value, CA_VERIFY_TIMEOUT_MS)
        val p = caResultPayload(reply, "DERIVE_KEYS", 2)
        if (p[1].toInt() != 0) throw LinkDownException("CA DERIVE_KEYS failed, status=${p[1].toInt() and 0xFF}")
    }

    /** HMAC-SHA256 confirmation tag over the transcript, using the confirmation key caDeriveKeys() derived. Send
     *  the result to the peer (M4); requires caDeriveKeys() to have already run. `role` is MY role. `pkKemA`/
     *  `ctKemB` must be the SAME values passed to caDeriveKeys() this session. */
    suspend fun caConfirm(
        role: Int, nA: ByteArray, epkA: ByteArray, nB: ByteArray, epkB: ByteArray,
        pkKemA: ByteArray? = null, ctKemB: ByteArray? = null,
    ): ByteArray {
        val extra = byteArrayOf(CaCmd.CONFIRM.toByte()) + caQuad(role, nA, epkA, nB, epkB) + caExt(pkKemA, ctKemB)
        val reply = requestOnce(PacketType.CA.value, 0, extra, PacketType.RESULT.value, CA_TIMEOUT_MS)
        val p = caResultPayload(reply, "CONFIRM", 2 + 32)
        if (p[1].toInt() != 0) throw LinkDownException("CA CONFIRM failed, status=${p[1].toInt() and 0xFF}")
        return p.copyOfRange(2, 34)
    }

    /** Checks the peer's own confirmation MAC (their M4) against what this device independently computes.
     *  `peerRole` is the peer's role. `pkKemA`/`ctKemB` must be the SAME values used throughout this session (no
     *  ownership substitution here, mirrors ca_protocol.c's VERIFY_CONFIRM). Returns 0 (match -- the handshake is
     *  complete and both sides derived the same session keys), 1 (mismatch -- ABORT, do not start the call), or 2
     *  (no confirmation key held, i.e. caDeriveKeys() was never called). */
    suspend fun caVerifyConfirm(
        peerRole: Int, nA: ByteArray, epkA: ByteArray, nB: ByteArray, epkB: ByteArray, mac: ByteArray,
        pkKemA: ByteArray? = null, ctKemB: ByteArray? = null,
    ): Int {
        val extra = byteArrayOf(CaCmd.VERIFY_CONFIRM.toByte()) + caQuad(peerRole, nA, epkA, nB, epkB) + caExt(pkKemA, ctKemB) + mac
        val reply = requestOnce(PacketType.CA.value, 0, extra, PacketType.RESULT.value, CA_TIMEOUT_MS)
        val p = caResultPayload(reply, "VERIFY_CONFIRM", 2)
        return p[1].toInt() and 0xFF
    }

    /** Ends the handshake session: deletes the ephemeral/confirmation SE052F objects and wipes the session keys
     *  media_protocol.c would otherwise have picked up. Best-effort -- a missed reply doesn't matter, the next
     *  caBegin() wipes any leftover state anyway. Safe to call even if no session is active. */
    suspend fun caEndSession() {
        try {
            requestOnce(PacketType.CA.value, 0, byteArrayOf(CaCmd.END_SESSION.toByte()), PacketType.RESULT.value, CA_TIMEOUT_MS)
        } catch (_: ChunkDroppedException) {
            // best-effort cleanup, see doc comment above
        }
    }

    /**
     * One CMD_TYPE_FW_UPDATE round trip (FirmwareUpdater.kt strings these together): sends [sub][params], returns the
     * RESULT payload ([sub][status][data]), or null if no well-formed reply arrived in time. No retry here -- the
     * updater decides, since some sub-commands (FW_DATA) are safe to resend and others (ENTER_UPDATE) reset the board.
     * Boot's updater answers HELLO too, so connect() works whether the board runs the application or the updater.
     */
    suspend fun fwRequest(subCmd: Int, params: ByteArray, timeoutMs: Long): ByteArray? {
        val reply = try {
            requestOnce(PacketType.FW_UPDATE.value, 0, byteArrayOf(subCmd.toByte()) + params,
                PacketType.RESULT.value, timeoutMs)
        } catch (_: ChunkDroppedException) {
            return null
        }
        val p = reply.payload
        return if (p.size >= 2 && (p[0].toInt() and 0xFF) == subCmd) p else null
    }

    /**
     * Die temperature and main-loop sleep share (CMD_TYPE_QRNG sub-command QRNG_CMD_DEVICE_STATUS 0x11, SDQRNG_V8Y's
     * qrng_protocol.c / app_power.c; the board refreshes the values once a second). Null if the board does not answer
     * it (Boot's updater, or a firmware without this sub-command).
     */
    suspend fun deviceStatus(): BoardStatus? {
        val reply = try {
            requestOnce(PacketType.QRNG.value, 0, byteArrayOf(QRNG_CMD_DEVICE_STATUS.toByte()), PacketType.RESULT.value, CA_TIMEOUT_MS)
        } catch (_: ChunkDroppedException) {
            return null
        }
        val p = reply.payload
        if (p.size < 18 || (p[0].toInt() and 0xFF) != QRNG_CMD_DEVICE_STATUS || p[1].toInt() != 0) return null
        fun u32(o: Int) = (p[o].toLong() and 0xFF) or ((p[o + 1].toLong() and 0xFF) shl 8) or
            ((p[o + 2].toLong() and 0xFF) shl 16) or ((p[o + 3].toLong() and 0xFF) shl 24)
        fun temp(o: Int): Int? = u32(o).toInt().takeIf { it != Int.MIN_VALUE } // INT32_MIN = no reading yet
        return BoardStatus(
            tempC = temp(2),
            tempMaxC = temp(6),
            sleepPermille = u32(10).toInt(),
            uptimeMs = if (p.size >= 30) u32(18) else null,
        )
    }

    private suspend fun sendAndAwaitAck(type: Int, sessionId: Int, payload: ByteArray) {
        repeat(CONTROL_MAX_RETRIES) {
            val reply = try {
                requestOnce(type, sessionId, payload, PacketType.ACK.value, ACK_TIMEOUT_MS,
                    alsoAcceptType = PacketType.NACK.value)
            } catch (_: ChunkDroppedException) {
                return@repeat
            }
            if (reply.type == PacketType.ACK.value) return
            val reason = if (reply.payload.size > 4) reply.payload[4].toInt() and 0xFF else 0
            if (reason == NackReason.BUSY.value) delay(BUSY_BACKOFF_MS)
        }
        throw LinkDownException("exceeded retries sending type=$type")
    }

    /**
     * Registers a waiter BEFORE writing a single byte to the wire (this
     * hardware round-trips small chunks in low-single-digit milliseconds --
     * see tools/device_link.py's identical comment for the real-hardware
     * race this ordering fixes: writing first let the reader thread decode
     * and dispatch the reply before the waiter was registered, silently
     * dropping it), sends the request, and waits for the matching reply
     * (or `alsoAcceptType`'s, e.g. NACK). Throws ChunkDroppedException on
     * timeout -- callers decide whether that means "retry" or "give up
     * loudly."
     */
    private suspend fun requestOnce(
        sendType: Int, sessionId: Int, payload: ByteArray,
        expectType: Int, timeoutMs: Long, alsoAcceptType: Int? = null, isAudio: Boolean = false,
    ): Packet {
        val nbytes = payload.size
        acquireBudget(nbytes, timeoutMs, isAudio)
        try {
            val seq = seqCounter.getAndIncrement() and 0xFFFFFFFFL
            val primaryKey = PendingKey(expectType, seq)
            val primary = CompletableDeferred<Packet>()
            pending[primaryKey] = primary
            val altKey = alsoAcceptType?.let { PendingKey(it, seq) }
            val alt = altKey?.let { CompletableDeferred<Packet>().also { d -> pending[it] = d } }
            try {
                writeFrame(sendType, sessionId, seq, payload, isAudio)
                val result = withTimeoutOrNull(timeoutMs) {
                    if (alt != null) {
                        select<Packet> {
                            primary.onAwait { it }
                            alt.onAwait { it }
                        }
                    } else {
                        primary.await()
                    }
                }
                return result
                    ?: throw ChunkDroppedException("no reply to type=$sendType (seq=$seq) within ${timeoutMs}ms")
            } finally {
                pending.remove(primaryKey)
                altKey?.let { pending.remove(it) }
            }
        } finally {
            releaseBudget(nbytes)
        }
    }

    /** See MAX_IN_FLIGHT_BYTES's doc comment. Lock-free CAS loop, polled at
     *  BUDGET_POLL_MS -- adequate at this scale (a handful of KB, a few ms),
     *  not worth a true condition-variable-style wakeup for it. */
    private suspend fun acquireBudget(nbytes: Int, timeoutMs: Long, isAudio: Boolean = false) {
        val deadline = System.currentTimeMillis() + timeoutMs
        // Tracks whether THIS call incremented pendingAudioWaiters, so `finally` only ever
        // decrements what it actually incremented -- see the loop body's own comment on why
        // this must NOT happen unconditionally at entry.
        var registeredAsWaiter = false
        try {
            val cap = if (isAudio) MAX_IN_FLIGHT_BYTES else (MAX_IN_FLIGHT_BYTES - AUDIO_RESERVE_BYTES)
            while (true) {
                val current = inFlightBytes.get()
                // `current == 0` admits a single oversized request (nbytes alone > cap) once
                // nothing else is competing -- confirmed as a REAL bug on real hardware
                // (2026-09-18): a 21104B video keyframe chunk against the 12000B cap deadlocked
                // this function until timeout even with 0B genuinely in flight, because
                // `0 + 21104 <= 12000` is false and the loop had no other way out. A real H.264
                // CBR encoder's keyframe/high-motion variance routinely exceeds this cap's size
                // even though the STEADY-STATE average chunk size does not -- refusing to ever
                // admit a single chunk bigger than the whole budget is strictly worse than
                // briefly letting one oversized chunk through alone, since the cap exists to
                // bound CONCURRENT in-flight bytes (the firmware RX ring), not to reject a
                // request the ring can perfectly well hold by itself.
                //
                // Video (isAudio=false) additionally waits while ANY audio request is
                // currently trying to get admitted (pendingAudioWaiters > 0), even if video's
                // own request would fit right now under `cap` -- see AUDIO_RESERVE_BYTES's
                // doc comment on why this is what actually makes audio jump the queue.
                val fits = current == 0 || current + nbytes <= cap
                val mustYieldToAudio = !isAudio && pendingAudioWaiters.get() > 0
                if (fits && !mustYieldToAudio) {
                    if (inFlightBytes.compareAndSet(current, current + nbytes)) return
                    continue // lost the CAS race to another caller -- retry immediately
                }
                // Only register as a genuinely-waiting audio request once we know we can't
                // proceed immediately -- REAL REGRESSION found on real hardware (2026-09-19):
                // an earlier version incremented pendingAudioWaiters unconditionally at
                // function entry, for the ENTIRE duration of every audio acquire call, even
                // the near-instant common case where audio was admitted on the very first
                // check (audio has a generous dedicated reserve, so this should be the
                // overwhelming majority of audio calls). Since audio pipelines up to
                // PIPELINE_DEPTH concurrent chunks across BOTH its uplink and downlink lanes,
                // that kept pendingAudioWaiters nonzero often enough that EVERY video acquire
                // was forced into at least one extra BUDGET_POLL_MS wait even when audio was
                // never actually contending for video's own budget -- measured as severe,
                // pervasive video lag independent of bitrate (reverting bitrate all the way
                // back to the previously-proven 640x480/700kbps did NOT fix it, which is what
                // pointed at this function rather than the encoder settings).
                if (isAudio && !registeredAsWaiter) {
                    pendingAudioWaiters.incrementAndGet()
                    registeredAsWaiter = true
                }
                if (System.currentTimeMillis() >= deadline) {
                    throw ChunkDroppedException(
                        "timed out waiting for RX budget (${nbytes}B request, ${current}B already " +
                            "in flight, cap=${cap}B)",
                    )
                }
                delay(BUDGET_POLL_MS)
            }
        } finally {
            if (registeredAsWaiter) pendingAudioWaiters.decrementAndGet()
        }
    }

    private fun releaseBudget(nbytes: Int) {
        inFlightBytes.addAndGet(-nbytes)
    }

    private fun dispatch(pkt: Packet) {
        val key = when (pkt.type) {
            in HEADER_SEQ_REPLY_TYPES -> PendingKey(pkt.type, pkt.seq)
            in PAYLOAD_SEQ_REPLY_TYPES -> {
                if (pkt.payload.size < 4) return
                val corrSeq = (pkt.payload[0].toLong() and 0xFF) or
                    ((pkt.payload[1].toLong() and 0xFF) shl 8) or
                    ((pkt.payload[2].toLong() and 0xFF) shl 16) or
                    ((pkt.payload[3].toLong() and 0xFF) shl 24)
                PendingKey(pkt.type, corrSeq)
            }
            else -> return // request-only types never arrive as a "reply" here
        }
        pending.remove(key)?.complete(pkt)
        // else: nobody waiting (already timed out, or an unsolicited push) -- silently
        // drop, matching command_protocol.c's own "no NACK for what it can't address" rule.
    }

    // Enqueues onto writerLoop()'s priority queues and suspends until that coroutine has
    // actually performed the blocking currentPort.write() call -- see PendingWrite's doc
    // comment for why this replaced a plain synchronized lock. The writer coroutine itself
    // runs on Dispatchers.IO (an elastic pool meant for blocking calls), never the small
    // CPU-core-sized Default pool that requestOnce() and everything else run on, so a slow
    // or stuck write still can't starve unrelated coroutines the way it could before this
    // was moved off Default (2026-09-19, extended real-hardware session).
    private suspend fun writeFrame(type: Int, sessionId: Int, seq: Long, payload: ByteArray, isAudio: Boolean = false) {
        val frame = encodePacket(type, sessionId, seq, payload)
        val item = PendingWrite(frame)
        val queue = if (isAudio) audioWriteQueue else videoWriteQueue
        try {
            queue.send(item)
        } catch (e: Exception) {
            throw LinkDownException("write queue closed: ${e.message}")
        }
        item.completion.await()
    }

    private fun sendFireAndForget(type: Int, sessionId: Int, seq: Long, payload: ByteArray) {
        if (port == null) return
        val item = PendingWrite(encodePacket(type, sessionId, seq, payload))
        videoWriteQueue.trySend(item) // best-effort, same as the old version's swallowed exceptions
    }
}

/** DeviceLink.deviceStatus()'s reply. Temperatures are null until the board has its first reading; CPU load is
 *  the share of the last second the main loop was NOT asleep (1000 - sleepPermille). */
data class BoardStatus(val tempC: Int?, val tempMaxC: Int?, val sleepPermille: Int, val uptimeMs: Long?) {
    val cpuLoadPercent: Double get() = (1000 - sleepPermille).coerceIn(0, 1000) / 10.0
}

private fun le32(v: Int): ByteArray = byteArrayOf(
    (v and 0xFF).toByte(), ((v shr 8) and 0xFF).toByte(),
    ((v shr 16) and 0xFF).toByte(), ((v shr 24) and 0xFF).toByte(),
)
