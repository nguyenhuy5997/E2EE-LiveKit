package com.evt2.board.rtc

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import kotlin.random.Random

class MediaFrameFormatTest {

    private val board = SoftBoard()

    private fun vp8(size: Int, keyframe: Boolean): ByteArray =
        Random.nextBytes(size).also { if (size > 0) it[0] = (if (keyframe) 0x10 else 0x11).toByte() }

    private fun seal(frame: ByteArray, codec: MediaCodec) = runBlocking { MediaFrameFormat.seal(frame, codec) { board.encrypt(it, false) } }
    private fun open(sealed: ByteArray) = runBlocking { MediaFrameFormat.open(sealed) { board.decrypt(it, false) } }

    @Test
    fun `clear bytes follow the VP8 keyframe flag and Opus is fully encrypted`() {
        assertEquals(10, MediaFrameFormat.clearBytes(MediaCodec.VP8, vp8(5000, keyframe = true)))
        assertEquals(3, MediaFrameFormat.clearBytes(MediaCodec.VP8, vp8(5000, keyframe = false)))
        assertEquals(0, MediaFrameFormat.clearBytes(MediaCodec.OPUS, Random.nextBytes(120)))
        assertEquals(4, MediaFrameFormat.clearBytes(MediaCodec.VP8, vp8(5, keyframe = true))) // at least one byte encrypted
        assertEquals(0, MediaFrameFormat.clearBytes(MediaCodec.VP8, vp8(1, keyframe = true)))
    }

    @Test
    fun `seal then open gives the frame back for every size around the segment boundaries`() {
        val seg = MediaFrameFormat.SEGMENT_BYTES
        val sizes = listOf(1, 2, 3, 11, 100, seg - 1, seg, seg + 1, seg + 10, seg + 11, 2 * seg + 10, 40_000, 120_000)
        for (codec in listOf(MediaCodec.OPUS, MediaCodec.VP8)) for (key in listOf(true, false)) for (size in sizes) {
            val frame = if (codec == MediaCodec.VP8) vp8(size, key) else Random.nextBytes(size)
            val sealed = seal(frame, codec)
            val clear = MediaFrameFormat.clearBytes(codec, frame)
            assertEquals("$codec $size", MediaFrameFormat.sealedSize(size, clear), sealed.size)
            assertArrayEquals("clear part of $codec $size", frame.copyOfRange(0, clear), sealed.copyOfRange(0, clear))
            assertArrayEquals("$codec key=$key $size", frame, open(sealed))
        }
    }

    @Test
    fun `segments are at most SEGMENT_BYTES`() {
        assertEquals(listOf(4096, 4096, 1808), MediaFrameFormat.segmentLengths(10_010, 10))
        assertEquals(emptyList<Int>(), MediaFrameFormat.segmentLengths(10, 10))
    }

    @Test
    fun `tampered or malformed frames are rejected`() {
        val sealed = seal(vp8(9000, keyframe = true), MediaCodec.VP8)
        for (pos in listOf(10, 10 + 12, 10 + 28 + 100, sealed.size - 40)) { // nonce, tag, ciphertext of 1st / last segment
            val bad = sealed.copyOf().also { it[pos] = (it[pos].toInt() xor 1).toByte() }
            expectFailure("flip at $pos") { open(bad) }
        }
        expectFailure("unknown version") { open(sealed.copyOf().also { it[it.size - 1] = 2 }) }
        expectFailure("wrong clear length") { open(sealed.copyOf().also { it[it.size - 2] = 0xFF.toByte() }) }
        expectFailure("clear length past the end") { open(byteArrayOf(1, 2, 3, 9, 1)) }
        expectFailure("truncated last segment") { open(sealed.copyOfRange(0, 10 + 2 * (28 + 4096) + 20) + byteArrayOf(10, 1)) }
        expectFailure("only clear bytes") { open(byteArrayOf(1, 2, 3, 3, 1)) }
        expectFailure("no trailer") { open(byteArrayOf(1)) }
    }

    private fun expectFailure(what: String, block: () -> Unit) {
        try {
            block()
        } catch (_: Exception) {
            return
        }
        fail("$what was accepted")
    }
}
