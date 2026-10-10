package com.evt2.board.rtc

/** Codec of an encoded media frame; decides which bytes must stay readable (H.264: see [H264FrameFormat]). */
enum class MediaCodec { OPUS, VP8, H264 }

/** A received frame that is not a valid v1 board-sealed frame (wrong version, bad lengths). */
class FrameFormatException(message: String) : Exception(message)

/**
 * Wire format v1 of one board-encrypted WebRTC frame -- what the FrameTransformer hands to the RTP packetizer
 * (send side) and gets back from the depacketizer (receive side):
 *
 *   [clear: N bytes][segment 1] ... [segment k][N: 1 byte][VERSION: 1 byte]
 *   segment i = nonce 12 | tag 16 | ciphertext of the next <= SEGMENT_BYTES bytes after the clear part
 *
 * - The first N bytes stay readable because the RTP depacketizer parses them: the VP8 payload header (10 bytes on
 *   a keyframe, which carry the frame size; 3 otherwise). Opus needs none. At least one byte is always encrypted.
 * - Each segment is one DATA_CHUNK / DECRYPT_CHUNK on the board, with its own nonce and tag. The board handles one
 *   command at a time at ~1 ms per KB, so a whole 40 KB keyframe in one command held audio back for 60+ ms;
 *   4 KB segments let audio in between (SDCARD-QRNG Tools/board_media_bench.py, 2026-10-08).
 * - The trailer carries N, so the receiver splits the frame without knowing the codec.
 */
object MediaFrameFormat {
    const val VERSION = 1
    const val SEGMENT_BYTES = 4096
    const val SEAL_OVERHEAD = 28 // nonce 12 + tag 16
    const val TRAILER_BYTES = 2

    /** Leading bytes of [frame] that stay in clear. */
    fun clearBytes(codec: MediaCodec, frame: ByteArray): Int {
        if (frame.size <= 1) return 0
        val rule = when (codec) {
            MediaCodec.OPUS -> 0
            MediaCodec.H264 -> throw IllegalArgumentException("H.264 frames use H264FrameFormat")
            // VP8 payload header (RFC 6386 9.1): bit 0 of the first byte is the inverted keyframe flag.
            MediaCodec.VP8 -> if ((frame[0].toInt() and 0x01) == 0) 10 else 3
        }
        return minOf(rule, frame.size - 1)
    }

    /** Plaintext lengths of the segments that follow [clear] clear bytes of a [frameSize]-byte frame. */
    fun segmentLengths(frameSize: Int, clear: Int): List<Int> {
        val rest = frameSize - clear
        return (0 until rest step SEGMENT_BYTES).map { minOf(SEGMENT_BYTES, rest - it) }
    }

    /** Size of the sealed form of a [frameSize]-byte frame with [clear] clear bytes. */
    fun sealedSize(frameSize: Int, clear: Int): Int =
        frameSize + segmentLengths(frameSize, clear).size * SEAL_OVERHEAD + TRAILER_BYTES

    /**
     * Seals [frame]: [encrypt] is called once per segment, in order, and must return nonce | tag | ciphertext of
     * exactly SEAL_OVERHEAD + plaintext bytes.
     */
    suspend fun seal(frame: ByteArray, codec: MediaCodec, encrypt: suspend (ByteArray) -> ByteArray): ByteArray {
        val clear = clearBytes(codec, frame)
        val out = ByteArray(sealedSize(frame.size, clear))
        frame.copyInto(out, 0, 0, clear)
        var src = clear
        var dst = clear
        for (len in segmentLengths(frame.size, clear)) {
            val sealed = encrypt(frame.copyOfRange(src, src + len))
            if (sealed.size != SEAL_OVERHEAD + len) {
                throw FrameFormatException("board returned ${sealed.size} B for a $len B segment")
            }
            sealed.copyInto(out, dst)
            src += len
            dst += sealed.size
        }
        out[dst] = clear.toByte()
        out[dst + 1] = VERSION.toByte()
        return out
    }

    /** Opens a frame made by [seal]: [decrypt] gets each nonce | tag | ciphertext and returns the plaintext. */
    suspend fun open(sealed: ByteArray, decrypt: suspend (ByteArray) -> ByteArray): ByteArray {
        val segments = parse(sealed)
        val clear = sealed[sealed.size - 2].toInt() and 0xFF
        val plainSize = sealed.size - TRAILER_BYTES - segments.size * SEAL_OVERHEAD
        val out = ByteArray(plainSize)
        sealed.copyInto(out, 0, 0, clear)
        var dst = clear
        for (range in segments) {
            val plain = decrypt(sealed.copyOfRange(range.first, range.last + 1))
            if (plain.size != range.last + 1 - range.first - SEAL_OVERHEAD) {
                throw FrameFormatException("board returned ${plain.size} B for a ${range.last + 1 - range.first} B segment")
            }
            plain.copyInto(out, dst)
            dst += plain.size
        }
        return out
    }

    /** Byte ranges of the sealed segments of [sealed]; throws FrameFormatException when the layout is invalid. */
    fun parse(sealed: ByteArray): List<IntRange> {
        if (sealed.size < TRAILER_BYTES) throw FrameFormatException("frame of ${sealed.size} B has no trailer")
        val version = sealed[sealed.size - 1].toInt() and 0xFF
        if (version != VERSION) throw FrameFormatException("unknown frame format version $version")
        val clear = sealed[sealed.size - 2].toInt() and 0xFF
        val end = sealed.size - TRAILER_BYTES
        if (clear > end) throw FrameFormatException("clear length $clear exceeds the frame")
        val full = SEAL_OVERHEAD + SEGMENT_BYTES
        val ranges = ArrayList<IntRange>()
        var pos = clear
        while (pos < end) {
            val len = minOf(full, end - pos)
            if (len <= SEAL_OVERHEAD) throw FrameFormatException("truncated segment of $len B")
            ranges.add(pos until pos + len)
            pos += len
        }
        if (ranges.isEmpty() && clear > 0) throw FrameFormatException("frame has no encrypted part")
        return ranges
    }
}
