package com.evt2.board.rtc

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream
import kotlin.random.Random

class H264FrameFormatTest {

    /** A "board" whose seal is all zeros + the plaintext: forces long zero runs through the escaping. */
    private object ZeroBoard : BoardCipher {
        override suspend fun encrypt(plain: ByteArray, isAudio: Boolean) = ByteArray(28) + plain
        override suspend fun decrypt(sealed: ByteArray, isAudio: Boolean) = sealed.copyOfRange(28, sealed.size)
    }

    private val soft = SoftBoard()

    private fun nal(header: Int, body: ByteArray) = byteArrayOf(header.toByte()) + H264FrameFormat.escape(body)

    /** Annex-B frame from NAL units; [short] uses 3-byte start codes. */
    private fun annexB(vararg nals: ByteArray, short: Boolean = false): ByteArray {
        val out = ByteArrayOutputStream()
        for (n in nals) {
            out.write(if (short) byteArrayOf(0, 0, 1) else byteArrayOf(0, 0, 0, 1))
            out.write(n)
        }
        return out.toByteArray()
    }

    private fun nalBytes(frame: ByteArray) = H264FrameFormat.findNals(frame).map { frame.copyOfRange(it.start, it.end).toList() }

    private fun seal(frame: ByteArray, c: BoardCipher) = runBlocking { H264FrameFormat.seal(frame) { c.encrypt(it, false) } }
    private fun open(frame: ByteArray, c: BoardCipher) = runBlocking { H264FrameFormat.open(frame) { c.decrypt(it, false) } }

    private val sps = nal(0x67, byteArrayOf(0x42, 0xC0.toByte(), 0x1F, 0x8C.toByte(), 0x8D.toByte(), 0x40))
    private val pps = nal(0x68, byteArrayOf(0xCE.toByte(), 0x3C, 0x80.toByte()))

    @Test
    fun `keyframe and delta frames round-trip, SPS and PPS stay in clear, slices do not`() {
        for (c in listOf(soft, ZeroBoard)) for (size in listOf(2, 3, 5, 100, 4096, 4097, 9000, 40_000)) {
            val idr = nal(0x65, Random.nextBytes(size))
            val key = annexB(sps, pps, idr)
            val sealed = seal(key, c)
            val nals = nalBytes(sealed)
            assertEquals("NAL count stays, $size", 3, nals.size)
            assertEquals(sps.toList(), nals[0])
            assertEquals(pps.toList(), nals[1])
            assertFalse("slice body is not in clear", nals[2] == idr.toList())
            assertTrue(H264FrameFormat.isKeyframe(sealed))
            assertEquals(nalBytes(key), nalBytes(open(sealed, c)))

            val delta = annexB(nal(0x41, Random.nextBytes(size)), short = true)
            assertFalse(H264FrameFormat.isKeyframe(delta))
            assertEquals(nalBytes(delta), nalBytes(open(seal(delta, c), c)))
        }
    }

    @Test
    fun `zero-heavy data never produces a start code inside a sealed slice`() {
        val body = ByteArray(20_000) { if (it % 7 == 0) 1 else 0 } // 00 00 00 .. 01 patterns everywhere
        val frame = annexB(nal(0x65, body), nal(0x41, ByteArray(3000)))
        val sealed = seal(frame, ZeroBoard)
        assertEquals(2, H264FrameFormat.findNals(sealed).size)
        assertEquals(nalBytes(frame), nalBytes(open(sealed, ZeroBoard)))
    }

    @Test
    fun `start codes may change length on the way`() {
        val frame = annexB(sps, pps, nal(0x65, Random.nextBytes(5000)), nal(0x65, Random.nextBytes(800)))
        val sealed = seal(frame, soft)
        // What a depacketizer could hand back: 3-byte start codes and an extra zero before one of them.
        val rebuilt = ByteArrayOutputStream()
        for ((i, n) in H264FrameFormat.findNals(sealed).withIndex()) {
            rebuilt.write(if (i == 2) byteArrayOf(0, 0, 0, 0, 1) else byteArrayOf(0, 0, 1))
            rebuilt.write(sealed, n.start, n.size)
        }
        assertEquals(nalBytes(frame), nalBytes(open(rebuilt.toByteArray(), soft)))
    }

    @Test
    fun `escape and unescape are inverse, including the state carried in from the clear part`() {
        repeat(200) {
            val data = ByteArray(Random.nextInt(0, 300)) { if (Random.nextInt(3) == 0) Random.nextInt(4).toByte() else 0 }
            for (zeros in 0..2) {
                val e = H264FrameFormat.escape(data, zeros)
                assertArrayEquals(data, H264FrameFormat.unescape(e, 0, e.size, zeros))
            }
        }
    }

    @Test
    fun `tampered slices are rejected`() {
        val frame = annexB(sps, pps, nal(0x65, Random.nextBytes(6000)))
        val sealed = seal(frame, soft)
        val slice = H264FrameFormat.findNals(sealed)[2]
        for (pos in listOf(slice.start + 5, slice.start + 40, slice.end - 10, slice.end - 1)) {
            val bad = sealed.copyOf().also { it[pos] = (it[pos].toInt() xor 0x10).toByte() }
            try {
                open(bad, SoftBoard())
                fail("flip at $pos was accepted")
            } catch (_: Exception) {
            }
        }
        // a slice sent in clear (not sealed) is refused, never passed to the decoder
        try {
            open(frame, soft)
            fail("unsealed slice was accepted")
        } catch (_: Exception) {
        }
    }
}
