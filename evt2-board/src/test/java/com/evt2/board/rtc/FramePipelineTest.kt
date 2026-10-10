package com.evt2.board.rtc

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random

class FramePipelineTest {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @After
    fun tearDown() = scope.cancel()

    private fun vp8(size: Int, keyframe: Boolean): ByteArray =
        Random.nextBytes(size).also { it[0] = (if (keyframe) 0x10 else 0x11).toByte() }

    /** Submits [frames] and waits until every callback ran; returns the results in callback order (index, result). */
    private fun runAll(p: FramePipeline, frames: List<Pair<ByteArray, Boolean>>, gapMs: Long = 0): List<Pair<Int, ByteArray?>> {
        val out = Collections.synchronizedList(ArrayList<Pair<Int, ByteArray?>>())
        val latch = CountDownLatch(frames.size)
        frames.forEachIndexed { i, (f, key) ->
            p.submit(f, key) { r -> out.add(i to r); latch.countDown() }
            if (gapMs > 0) Thread.sleep(gapMs)
        }
        assertTrue("callbacks did not all run", latch.await(20, TimeUnit.SECONDS))
        return out
    }

    @Test
    fun `send then receive returns every frame, in order, with jittery board times`() {
        val board = SoftBoard(delayMs = { Random.nextLong(0, 8) })
        val send = FramePipeline(MediaCodec.VP8, Direction.SEND, board, scope, maxInFlight = 3, maxQueued = 100, frameTimeoutMs = 5_000)
        val recv = FramePipeline(MediaCodec.VP8, Direction.RECEIVE, board, scope, maxInFlight = 3, maxQueued = 100, frameTimeoutMs = 5_000)
        val frames = List(60) { vp8(Random.nextInt(50, 20_000), keyframe = it % 20 == 0) to (it % 20 == 0) }

        val sealed = runAll(send, frames)
        assertEquals((0 until 60).toList(), sealed.map { it.first })
        val opened = runAll(recv, sealed.map { it.second!! to false })
        assertEquals((0 until 60).toList(), opened.map { it.first })
        opened.forEach { (i, r) -> assertArrayEquals("frame $i", frames[i].first, r) }
        assertEquals(60, send.stats.ok.get())
        assertEquals(0, recv.stats.drops())
    }

    @Test
    fun `audio drops the oldest waiting packet when the board falls behind, and keeps the order`() {
        val board = SoftBoard(delayMs = { 40 })
        val p = FramePipeline(MediaCodec.OPUS, Direction.SEND, board, scope, maxInFlight = 1, maxQueued = 2, frameTimeoutMs = 5_000)
        val res = runAll(p, List(10) { Random.nextBytes(100) to false })
        assertEquals((0 until 10).toList(), res.map { it.first })
        val dropped = res.filter { it.second == null }.map { it.first }
        assertTrue("some packets dropped: $dropped", dropped.isNotEmpty())
        assertTrue("the newest packet survives", res.last().second != null)
        assertEquals(dropped.size.toLong(), p.stats.droppedQueue.get())
    }

    @Test
    fun `send video waits for a keyframe after a drop and asks the encoder for one`() {
        val board = SoftBoard()
        val asked = AtomicInteger(0)
        val p = FramePipeline(MediaCodec.VP8, Direction.SEND, board, scope, maxInFlight = 1, maxQueued = 10,
            frameTimeoutMs = 100, onKeyframeNeeded = { asked.incrementAndGet() })
        board.hang = true
        val first = runAll(p, listOf(vp8(500, keyframe = true) to true)) // times out
        assertNull(first.single().second)
        board.hang = false
        val after = runAll(p, listOf(vp8(500, false) to false, vp8(500, false) to false, vp8(500, true) to true, vp8(500, false) to false))
        assertEquals(listOf(null, null), after.take(2).map { it.second })
        assertTrue("keyframe and the delta after it are sent", after.drop(2).all { it.second != null })
        assertTrue("a keyframe was requested", asked.get() >= 1)
        assertEquals(1, p.stats.droppedTimeout.get())
        assertEquals(2, p.stats.droppedWaitingKeyframe.get())
    }

    @Test
    fun `a frame the board rejects is dropped without blocking the next ones`() {
        val board = SoftBoard()
        val send = FramePipeline(MediaCodec.OPUS, Direction.SEND, board, scope, 2, 10, 5_000)
        val recv = FramePipeline(MediaCodec.OPUS, Direction.RECEIVE, board, scope, 2, 10, 5_000)
        val sealed = runAll(send, List(3) { Random.nextBytes(80) to false }).map { it.second!! }
        val tampered = sealed[1].copyOf().also { it[5] = (it[5].toInt() xor 1).toByte() }
        val res = runAll(recv, listOf(sealed[0] to false, tampered to false, sealed[2] to false, sealed[0] to false))
        assertEquals(listOf(true, false, true, false), res.map { it.second != null }) // the last one is a replay
        assertEquals(2, recv.stats.droppedError.get())
    }

    @Test
    fun `submit never blocks while the board hangs`() {
        val board = SoftBoard().apply { hang = true }
        val p = FramePipeline(MediaCodec.VP8, Direction.RECEIVE, board, scope, 2, 4, 200)
        val t0 = System.nanoTime()
        repeat(50) { p.submit(vp8(3000, false), false) {} }
        assertTrue("submit took ${(System.nanoTime() - t0) / 1_000_000} ms", (System.nanoTime() - t0) / 1_000_000 < 200)
    }
}
