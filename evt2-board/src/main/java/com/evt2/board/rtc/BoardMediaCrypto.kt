package com.evt2.board.rtc

import com.evt2.board.link.DeviceLink
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.atomic.AtomicLong

/** The board's AES-256-GCM, one sealed segment (nonce | tag | ciphertext) at a time. */
interface BoardCipher {
    suspend fun encrypt(plain: ByteArray, isAudio: Boolean): ByteArray
    suspend fun decrypt(sealed: ByteArray, isAudio: Boolean): ByteArray
}

/** [BoardCipher] over the USB link, inside the LIVE media session opened after the CA handshake. */
class DeviceLinkCipher(private val link: DeviceLink, private val sessionId: Int) : BoardCipher {
    override suspend fun encrypt(plain: ByteArray, isAudio: Boolean): ByteArray =
        link.encryptChunk(sessionId, plain, isAudio)

    override suspend fun decrypt(sealed: ByteArray, isAudio: Boolean): ByteArray =
        link.decryptChunk(sessionId, sealed, isAudio)
}

/**
 * A [BoardCipher] whose session is set once the CA handshake is done. Until then (and after [clear]) every call
 * fails, so media created before the handshake is dropped, never sent in clear.
 */
class SwitchableCipher : BoardCipher {
    @Volatile private var inner: BoardCipher? = null

    fun set(cipher: BoardCipher) {
        inner = cipher
    }

    fun clear() {
        inner = null
    }

    private fun current(): BoardCipher = inner ?: throw IllegalStateException("board media session not ready")

    override suspend fun encrypt(plain: ByteArray, isAudio: Boolean): ByteArray = current().encrypt(plain, isAudio)

    override suspend fun decrypt(sealed: ByteArray, isAudio: Boolean): ByteArray = current().decrypt(sealed, isAudio)
}

enum class Direction { SEND, RECEIVE }

/** Seals (send) or opens (receive) one frame of [codec] with the board, in the format of that codec. */
suspend fun sealOrOpen(codec: MediaCodec, direction: Direction, cipher: BoardCipher, frame: ByteArray): ByteArray {
    val isAudio = codec == MediaCodec.OPUS
    return when {
        codec == MediaCodec.H264 && direction == Direction.SEND -> H264FrameFormat.seal(frame) { cipher.encrypt(it, false) }
        codec == MediaCodec.H264 -> H264FrameFormat.open(frame) { cipher.decrypt(it, false) }
        direction == Direction.SEND -> MediaFrameFormat.seal(frame, codec) { cipher.encrypt(it, isAudio) }
        else -> MediaFrameFormat.open(frame) { cipher.decrypt(it, isAudio) }
    }
}

/** Monotonic milliseconds (plain JVM, so the pipeline runs in unit tests). */
private fun nowMs(): Long = System.nanoTime() / 1_000_000

/** Counters of one [FramePipeline]; read from any thread. */
class PipelineStats {
    val ok = AtomicLong(0)
    /** Dropped because the queue was full (the board fell behind). */
    val droppedQueue = AtomicLong(0)
    /** Dropped because the board did not finish in time. */
    val droppedTimeout = AtomicLong(0)
    /** Dropped because the board refused it (bad tag, replay) or the frame was malformed. */
    val droppedError = AtomicLong(0)
    /** Video delta frames not sent while waiting for a keyframe after a drop. */
    val droppedWaitingKeyframe = AtomicLong(0)
    private val times = ArrayDeque<Pair<Long, Long>>() // (when, board ms) over the last WINDOW_MS

    internal fun record(ms: Long) {
        val now = nowMs()
        synchronized(times) {
            times.addLast(now to ms)
            while (times.isNotEmpty() && now - times.first().first > WINDOW_MS) times.removeFirst()
        }
    }

    /** "n p50 p95 max" of the board time per frame over the last WINDOW_MS. */
    fun summary(): String {
        val now = nowMs()
        val v = synchronized(times) {
            while (times.isNotEmpty() && now - times.first().first > WINDOW_MS) times.removeFirst()
            times.map { it.second }.sorted()
        }
        if (v.isEmpty()) return "n=0"
        fun pct(p: Double) = v[minOf(v.size - 1, (p * v.size).toInt())]
        return "${v.size * 1000 / WINDOW_MS}/s p50=${pct(0.5)} p95=${pct(0.95)} max=${v.last()} ms"
    }

    fun drops(): Long =
        droppedQueue.get() + droppedTimeout.get() + droppedError.get() + droppedWaitingKeyframe.get()

    private companion object {
        const val WINDOW_MS = 5_000L
    }
}

/**
 * One media stream (audio or video, send or receive) between libwebrtc's FrameTransformer and the board.
 *
 * [submit] never blocks: frames are queued and handed back through their callback, in submission order, once the
 * board has sealed / opened them (a null result means "drop this frame"). Up to [maxInFlight] frames are worked on
 * at once; a frame's segments go to the board one after another, so another stream's request (audio) can get in
 * between two segments of a big video frame.
 *
 * When the board falls behind:
 * - more than [maxQueued] frames waiting: audio drops the oldest waiting packet (the jitter buffer conceals it),
 *   video drops the new frame;
 * - a frame not done within [frameTimeoutMs] is dropped.
 * After a video drop on the send side every delta frame is useless to the peer, so deltas are dropped until the next
 * keyframe and [onKeyframeNeeded] asks the encoder for one. The receive side only drops; libwebrtc's frame buffer
 * notices the gap and requests a keyframe itself.
 */
class FramePipeline(
    private val codec: MediaCodec,
    private val direction: Direction,
    private val cipher: BoardCipher,
    private val scope: CoroutineScope,
    private val maxInFlight: Int,
    private val maxQueued: Int,
    private val frameTimeoutMs: Long,
    private val onKeyframeNeeded: () -> Unit = {},
) {
    private class Slot(val frame: ByteArray, val isKeyframe: Boolean, val deliver: (ByteArray?) -> Unit) {
        var started = false
        var done = false
        var result: ByteArray? = null
    }

    val stats = PipelineStats()
    private val isAudio = codec == MediaCodec.OPUS
    private val lock = Any()
    private val deliverLock = Any()
    private val slots = ArrayDeque<Slot>() // submission order; the head is delivered first
    private var inFlight = 0
    private var waitingForKeyframe = false

    fun submit(frame: ByteArray, isKeyframe: Boolean, deliver: (ByteArray?) -> Unit) {
        var askKeyframe = false
        synchronized(lock) {
            if (!isAudio && direction == Direction.SEND && waitingForKeyframe) {
                if (!isKeyframe) {
                    stats.droppedWaitingKeyframe.incrementAndGet()
                    slots.addLast(Slot(frame, false, deliver).also { it.done = true; it.started = true })
                    askKeyframe = true
                } else {
                    waitingForKeyframe = false
                }
            }
            if (!askKeyframe) {
                val waiting = slots.count { !it.started }
                if (waiting >= maxQueued) {
                    stats.droppedQueue.incrementAndGet()
                    if (isAudio) {
                        slots.first { !it.started }.apply { started = true; done = true }
                        slots.addLast(Slot(frame, isKeyframe, deliver))
                    } else {
                        slots.addLast(Slot(frame, isKeyframe, deliver).also { it.started = true; it.done = true })
                        askKeyframe = markVideoLoss()
                    }
                } else {
                    slots.addLast(Slot(frame, isKeyframe, deliver))
                }
            }
            startWaiting()
        }
        if (askKeyframe) onKeyframeNeeded()
        flush()
    }

    /** Starts waiting slots while there is room. Caller holds [lock]. */
    private fun startWaiting() {
        while (inFlight < maxInFlight) {
            val slot = slots.firstOrNull { !it.started } ?: return
            slot.started = true
            inFlight++
            scope.launch { run(slot) }
        }
    }

    private suspend fun run(slot: Slot) {
        val t0 = nowMs()
        var result: ByteArray? = null
        try {
            result = withTimeoutOrNull(frameTimeoutMs) { transform(slot.frame) }
            if (result == null) stats.droppedTimeout.incrementAndGet()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            stats.droppedError.incrementAndGet()
        } finally {
            var askKeyframe = false
            synchronized(lock) {
                slot.result = result
                slot.done = true
                inFlight--
                if (result == null) askKeyframe = markVideoLoss()
                startWaiting()
            }
            if (result != null) {
                stats.ok.incrementAndGet()
                stats.record(nowMs() - t0)
            }
            if (askKeyframe) onKeyframeNeeded()
            flush()
        }
    }

    /** Send-side video lost a frame: wait for a keyframe. Returns true when one must be requested. Caller holds [lock]. */
    private fun markVideoLoss(): Boolean {
        if (isAudio || direction != Direction.SEND) return false
        waitingForKeyframe = true
        return true
    }

    private suspend fun transform(frame: ByteArray): ByteArray = sealOrOpen(codec, direction, cipher, frame)

    /** Hands finished frames at the head of the queue to their callbacks, in submission order. */
    private fun flush() {
        synchronized(deliverLock) {
            while (true) {
                val slot = synchronized(lock) {
                    if (slots.firstOrNull()?.done == true) slots.removeFirst() else null
                } ?: return
                slot.deliver(slot.result)
            }
        }
    }
}
