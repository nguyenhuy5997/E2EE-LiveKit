package com.evt2.board.rtc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.DataInputStream
import kotlin.random.Random

/**
 * Test streams in src/test/resources/h264: libx264 (PyAV) in constant-QP mode with ipratio = pbratio = 1, so every
 * slice of every frame has exactly the QP in the file name. File format: per frame, a 4-byte big-endian length and
 * the Annex-B access unit, in decode order.
 * - baseline_qp30: constrained baseline, CAVLC, no B frames (what Android hardware encoders produce), IDR every 6;
 * - baseline_qp22_slices: the same with 3 slices per frame;
 * - high_qp35_b_weightp: High profile, CABAC, B frames with pyramid, weighted P prediction, 3 references.
 */
class H264QpParserTest {

    private fun frames(name: String): List<ByteArray> {
        val stream = javaClass.classLoader!!.getResourceAsStream("h264/$name.bin") ?: error("missing $name")
        val input = DataInputStream(stream)
        val out = ArrayList<ByteArray>()
        while (input.available() > 0) {
            out.add(ByteArray(input.readInt()).also { input.readFully(it) })
        }
        return out
    }

    private fun assertAllQp(name: String, qp: Int) {
        val parser = H264QpParser()
        val f = frames(name)
        assertTrue(f.size >= 10)
        f.forEachIndexed { i, frame -> assertEquals("$name frame $i", qp, parser.parse(frame)) }
    }

    @Test fun baselineSingleSlice() = assertAllQp("baseline_qp30", 30)

    @Test fun baselineThreeSlices() = assertAllQp("baseline_qp22_slices", 22)

    @Test fun highProfileCabacBFramesWeightedPrediction() = assertAllQp("high_qp35_b_weightp", 35)

    @Test fun deltaFrameWithoutParameterSetsHasNoQp() {
        val f = frames("baseline_qp30")
        assertTrue(H264FrameFormat.isKeyframe(f[0]))
        assertTrue(!H264FrameFormat.isKeyframe(f[1]))
        assertNull(H264QpParser().parse(f[1])) // no SPS/PPS seen yet, as in libwebrtc
    }

    @Test fun garbageNeverThrows() {
        val rnd = Random(7)
        val parser = H264QpParser()
        repeat(2000) {
            val junk = rnd.nextBytes(rnd.nextInt(0, 300))
            // Random bytes with start codes and NAL headers of every type sprinkled in.
            if (junk.size > 8) {
                junk[0] = 0; junk[1] = 0; junk[2] = 1
                junk[3] = (rnd.nextInt(0, 32) or 0x60).toByte()
            }
            val qp = parser.parse(junk)
            assertTrue(qp == null || qp in 0..51)
        }
    }
}
