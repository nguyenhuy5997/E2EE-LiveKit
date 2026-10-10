package com.evt2.board.rtc

import java.io.ByteArrayOutputStream

/**
 * Board encryption of H.264 Annex-B frames that keeps them valid H.264 for libwebrtc's RTP packetizer/depacketizer.
 *
 * libwebrtc splits an H.264 frame at its start codes, reads every NAL header, parses SPS/PPS, and reads the start of
 * each slice header (pic_parameter_set_id) on the receive side. So per NAL unit:
 * - slices (type 1, 5) of N bytes: the first C = min([SLICE_CLEAR_BYTES], N - 1) bytes (NAL header + start of the
 *   slice header) stay in clear; the rest is sealed by the board in segments of <= [MediaFrameFormat.SEGMENT_BYTES]
 *   (nonce | tag | ciphertext each), followed by one end byte 0x80 | C. The sealed part gets H.264 emulation
 *   prevention (0x03 before any 00..03 that follows 00 00), so no start code can appear inside it; the end byte is
 *   never 0x00, so the NAL never ends in a zero byte either;
 * - every other NAL (SPS, PPS, SEI, AUD, ...) and a slice that is only its header stays in clear: libwebrtc parses
 *   them and may rewrite SPS/PPS.
 * The receiver finds the NALs by their start codes (the depacketizer rebuilds them with 4-byte ones), reads C from
 * the end byte, undoes the escaping and has the board open the segments. Start codes may change length on the way;
 * NAL contents do not.
 */
object H264FrameFormat {
    const val SLICE_CLEAR_BYTES = 4
    private const val END_FLAG = 0x80
    private val START_CODE = byteArrayOf(0, 0, 0, 1)

    /** One NAL unit of an Annex-B buffer: [start, end) without the start code. */
    data class Nal(val start: Int, val end: Int) {
        val size get() = end - start
    }

    private fun type(frame: ByteArray, nal: Nal): Int = frame[nal.start].toInt() and 0x1F

    private fun isSlice(frame: ByteArray, nal: Nal) = nal.size > 0 && type(frame, nal).let { it == 1 || it == 5 }

    /** True when the frame holds an IDR slice. */
    fun isKeyframe(frame: ByteArray): Boolean = findNals(frame).any { it.size > 0 && type(frame, it) == 5 }

    /** NAL units of an Annex-B buffer (3- or 4-byte start codes, trailing zero bytes dropped). */
    fun findNals(frame: ByteArray): List<Nal> {
        val payloads = ArrayList<Int>()
        val codeStarts = ArrayList<Int>()
        var i = 0
        while (i + 2 < frame.size) {
            if (frame[i].toInt() == 0 && frame[i + 1].toInt() == 0 && frame[i + 2].toInt() == 1) {
                codeStarts.add(i)
                payloads.add(i + 3)
                i += 3
            } else {
                i++
            }
        }
        return payloads.mapIndexed { k, payload ->
            var end = if (k + 1 < codeStarts.size) codeStarts[k + 1] else frame.size
            while (end > payload && frame[end - 1].toInt() == 0) end-- // zero_byte of the next start code, trailing zeros
            Nal(payload, end)
        }
    }

    suspend fun seal(frame: ByteArray, encrypt: suspend (ByteArray) -> ByteArray): ByteArray {
        val out = ByteArrayOutputStream(frame.size + frame.size / 64 + 64)
        for (nal in findNals(frame)) {
            out.write(START_CODE)
            if (!isSlice(frame, nal) || nal.size < 2) {
                out.write(frame, nal.start, nal.size)
                continue
            }
            val clear = minOf(SLICE_CLEAR_BYTES, nal.size - 1)
            out.write(frame, nal.start, clear)
            val sealed = ByteArrayOutputStream(nal.size + 64)
            var pos = nal.start + clear
            while (pos < nal.end) {
                val len = minOf(MediaFrameFormat.SEGMENT_BYTES, nal.end - pos)
                val seg = encrypt(frame.copyOfRange(pos, pos + len))
                if (seg.size != MediaFrameFormat.SEAL_OVERHEAD + len) {
                    throw FrameFormatException("board returned ${seg.size} B for a $len B segment")
                }
                sealed.write(seg)
                pos += len
            }
            sealed.write(END_FLAG or clear)
            out.write(escape(sealed.toByteArray(), zerosBefore(frame, nal.start, nal.start + clear)))
        }
        return out.toByteArray()
    }

    suspend fun open(frame: ByteArray, decrypt: suspend (ByteArray) -> ByteArray): ByteArray {
        val nals = findNals(frame)
        if (nals.isEmpty()) throw FrameFormatException("no NAL unit in the frame")
        val out = ByteArrayOutputStream(frame.size)
        for (nal in nals) {
            out.write(START_CODE)
            if (!isSlice(frame, nal) || nal.size < 2) {
                out.write(frame, nal.start, nal.size)
                continue
            }
            val endByte = frame[nal.end - 1].toInt() and 0xFF
            val clear = endByte and 0x7F
            if (endByte and END_FLAG == 0 || clear !in 1..SLICE_CLEAR_BYTES || nal.size < clear + 2) {
                throw FrameFormatException("slice without a valid end byte")
            }
            out.write(frame, nal.start, clear)
            val sealed = unescape(frame, nal.start + clear, nal.end, zerosBefore(frame, nal.start, nal.start + clear))
            val end = sealed.size - 1 // drop the end byte
            if (end <= 0) throw FrameFormatException("slice with an empty sealed part")
            val full = MediaFrameFormat.SEAL_OVERHEAD + MediaFrameFormat.SEGMENT_BYTES
            var pos = 0
            while (pos < end) {
                val len = minOf(full, end - pos)
                if (len <= MediaFrameFormat.SEAL_OVERHEAD) throw FrameFormatException("truncated segment of $len B")
                val plain = decrypt(sealed.copyOfRange(pos, pos + len))
                if (plain.size != len - MediaFrameFormat.SEAL_OVERHEAD) {
                    throw FrameFormatException("board returned ${plain.size} B for a $len B segment")
                }
                out.write(plain)
                pos += len
            }
        }
        return out.toByteArray()
    }

    /** Zero bytes (0..2) right before [pos], counting no further back than [from]: the escaping state at [pos]. */
    private fun zerosBefore(frame: ByteArray, from: Int, pos: Int): Int {
        var n = 0
        while (n < 2 && pos - 1 - n >= from && frame[pos - 1 - n].toInt() == 0) n++
        return n
    }

    /** H.264 emulation prevention: 0x03 before any byte <= 0x03 that follows two zero bytes. */
    fun escape(data: ByteArray, zerosBefore: Int = 0): ByteArray {
        val out = ByteArrayOutputStream(data.size + data.size / 100 + 4)
        var zeros = zerosBefore
        for (b in data) {
            val v = b.toInt() and 0xFF
            if (zeros >= 2 && v <= 3) {
                out.write(3)
                zeros = 0
            }
            out.write(v)
            zeros = if (v == 0) zeros + 1 else 0
        }
        return out.toByteArray()
    }

    /** Inverse of [escape] for frame[from, to). */
    fun unescape(frame: ByteArray, from: Int, to: Int, zerosBefore: Int = 0): ByteArray {
        val out = ByteArrayOutputStream(to - from)
        var zeros = zerosBefore
        for (i in from until to) {
            val v = frame[i].toInt() and 0xFF
            if (zeros >= 2) {
                if (v == 3) {
                    zeros = 0
                    continue
                }
                if (v < 3) throw FrameFormatException("start code inside a sealed slice")
            }
            out.write(v)
            zeros = if (v == 0) zeros + 1 else 0
        }
        return out.toByteArray()
    }
}
