package com.evt2.board.rtc

import android.util.Log
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import livekit.org.webrtc.FrameDecryptor
import livekit.org.webrtc.FrameEncryptor

/**
 * Board encryption of the AUDIO stream (Opus packets), called synchronously by libwebrtc through the native
 * FrameEncryptor/FrameDecryptor in app/src/main/cpp/board_audio_crypto.cpp: [encrypt] on the audio encoder thread,
 * [decrypt] on libwebrtc's worker thread.
 *
 * Each call is one board round trip (~1 ms for an Opus packet, SDCARD-QRNG Tools/board_media_bench.py) with a
 * [TIMEOUT_MS] cap: the worker thread also runs ICE, RTCP and stats, so a slow board costs a dropped packet (NetEq
 * conceals it), never a stalled call. Frame format: [MediaFrameFormat] with no clear bytes.
 */
object BoardAudioCrypto {
    private const val TAG = "BoardAudioCrypto"
    private const val TIMEOUT_MS = 40L
    private const val REJECT_LOG_BURST = 5
    private const val REJECT_LOG_WINDOW_MS = 10_000L

    init {
        System.loadLibrary("boardaudiocrypto")
    }

    @Volatile private var cipher: BoardCipher? = null
    val sendStats = PipelineStats()
    val receiveStats = PipelineStats()

    fun attach(c: BoardCipher) {
        cipher = c
    }

    fun detach() {
        cipher = null
    }

    @JvmStatic
    fun encrypt(frame: ByteArray): ByteArray? = run(frame, Direction.SEND, sendStats)

    @JvmStatic
    fun decrypt(frame: ByteArray): ByteArray? = run(frame, Direction.RECEIVE, receiveStats)

    private fun run(frame: ByteArray, direction: Direction, stats: PipelineStats): ByteArray? {
        val c = cipher ?: return null
        val t0 = System.nanoTime()
        return try {
            val out = runBlocking { withTimeoutOrNull(TIMEOUT_MS) { sealOrOpen(MediaCodec.OPUS, direction, c, frame) } }
            if (out == null) {
                stats.droppedTimeout.incrementAndGet()
            } else {
                stats.ok.incrementAndGet()
                stats.record((System.nanoTime() - t0) / 1_000_000)
            }
            out
        } catch (e: Exception) {
            val n = stats.droppedError.incrementAndGet()
            logRejected(direction, frame, e, n)
            null
        }
    }

    @Volatile private var lastRejectLogMs = 0L
    private var rejectsLogged = 0

    /**
     * A rejected frame is logged with its size and first/last bytes (it is NOT one of our sealed frames, or it is
     * damaged), so frames inserted by someone else on the way (e.g. the SFU) can be identified. At most
     * [REJECT_LOG_BURST] lines per [REJECT_LOG_WINDOW_MS], plus the running total.
     */
    private fun logRejected(direction: Direction, frame: ByteArray, e: Exception, total: Long) {
        val now = System.currentTimeMillis()
        synchronized(this) {
            if (now - lastRejectLogMs > REJECT_LOG_WINDOW_MS) {
                lastRejectLogMs = now
                rejectsLogged = 0
            }
            if (rejectsLogged++ >= REJECT_LOG_BURST) return
        }
        fun hex(b: ByteArray) = b.joinToString(" ") { "%02x".format(it) }
        val head = frame.copyOfRange(0, minOf(8, frame.size))
        val tail = frame.copyOfRange(maxOf(0, frame.size - 4), frame.size)
        Log.w(TAG, "$direction rejected #$total: ${e.javaClass.simpleName}: ${e.message}; ${frame.size} B [${hex(head)} .. ${hex(tail)}]")
    }

    @JvmStatic private external fun nativeCreateEncryptor(): Long
    @JvmStatic private external fun nativeCreateDecryptor(): Long
    @JvmStatic private external fun nativeReleaseEncryptor(ptr: Long)
    @JvmStatic private external fun nativeReleaseDecryptor(ptr: Long)

    /** For RtpSender.setFrameEncryptor() of the audio sender. [release] after the PeerConnection is disposed. */
    class Encryptor : FrameEncryptor {
        private var ptr = nativeCreateEncryptor()
        override fun getNativeFrameEncryptor(): Long = ptr
        fun release() {
            nativeReleaseEncryptor(ptr)
            ptr = 0
        }
    }

    /** For RtpReceiver.setFrameDecryptor() of the audio receiver. [release] after the PeerConnection is disposed. */
    class Decryptor : FrameDecryptor {
        private var ptr = nativeCreateDecryptor()
        override fun getNativeFrameDecryptor(): Long = ptr
        fun release() {
            nativeReleaseDecryptor(ptr)
            ptr = 0
        }
    }
}
