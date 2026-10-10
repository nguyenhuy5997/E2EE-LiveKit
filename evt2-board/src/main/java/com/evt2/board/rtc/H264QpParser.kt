package com.evt2.board.rtc

/**
 * Slice QP of H.264 Annex-B frames, computed exactly like libwebrtc's H264BitstreamParser (webrtc-sdk m144:
 * common_video/h264/h264_bitstream_parser.cc, sps_parser.cc, pps_parser.cc, h264_common.cc ParseRbsp,
 * rtc_base/bitstream_reader.cc), line for line.
 *
 * Why: libwebrtc's quality scaler lowers the resolution when the encoder's QP stays high (weak network). It reads
 * the QP from the encoded bitstream, but [BoardVideoEncoder] hands libwebrtc a bitstream sealed by the board, which
 * has no readable slice header. So the QP is read here from the PLAINTEXT frame and passed through
 * EncodedImage.qp (VideoEncoderWrapper only parses the bitstream when that is unset). A board-encrypted call then
 * adapts its resolution the same way as a call without the board.
 *
 * Stateful like libwebrtc's parser: the SPS/PPS of a keyframe are kept for the delta frames after it. One instance
 * per encoder; not thread-safe.
 */
class H264QpParser {
    private class Sps(
        val separateColourPlaneFlag: Int,
        val chromaFormatIdc: Int,
        val log2MaxFrameNum: Int,
        val picOrderCntType: Long,
        val log2MaxPicOrderCntLsb: Int,
        val deltaPicOrderAlwaysZeroFlag: Int,
        val frameMbsOnlyFlag: Int,
    )

    private class Pps(
        val entropyCodingModeFlag: Boolean,
        val bottomFieldPicOrderInFramePresentFlag: Boolean,
        val numRefIdxL0DefaultActiveMinus1: Long,
        val numRefIdxL1DefaultActiveMinus1: Long,
        val weightedPredFlag: Boolean,
        val weightedBipredIdc: Long,
        val picInitQpMinus26: Int,
        val redundantPicCntPresentFlag: Int,
    )

    private var sps: Sps? = null
    private var pps: Pps? = null
    private var lastSliceQpDelta: Int? = null

    /** Parses every NAL unit of [frame]; returns the QP of the last slice parsed so far, or null if unknown. */
    fun parse(frame: ByteArray): Int? {
        for (nal in H264FrameFormat.findNals(frame)) {
            if (nal.size > 0) parseNal(frame.copyOfRange(nal.start, nal.end))
        }
        return lastSliceQp()
    }

    /** GetLastSliceQp(). */
    fun lastSliceQp(): Int? {
        val delta = lastSliceQpDelta ?: return null
        val p = pps ?: return null
        val qp = 26 + p.picInitQpMinus26 + delta
        return if (qp in MIN_QP..MAX_QP) qp else null
    }

    /** ParseSlice(). */
    private fun parseNal(nal: ByteArray) {
        when (nal[0].toInt() and 0x1F) {
            NALU_SPS -> sps = parseSps(rbsp(nal, 1))
            NALU_PPS -> pps = parsePps(rbsp(nal, 1))
            NALU_AUD, NALU_FILLER, NALU_SEI, NALU_PREFIX -> {}
            else -> parseNonParameterSetNalu(nal)
        }
    }

    /** ParseNonParameterSetNalu(): reads the slice header up to slice_qp_delta. */
    private fun parseNonParameterSetNalu(source: ByteArray) {
        val s = sps ?: return
        val p = pps ?: return
        lastSliceQpDelta = null
        val sliceRbsp = rbsp(source, 0)
        if (sliceRbsp.isEmpty()) return
        val r = BitReader(sliceRbsp)
        r.consumeBits(8)

        val naluType = source[0].toInt() and 0x1F
        val isIdr = (source[0].toInt() and 0x0F) == NALU_IDR
        val nalRefIdc = (source[0].toInt() and 0x60) shr 5

        var numRefIdxL0ActiveMinus1 = p.numRefIdxL0DefaultActiveMinus1
        var numRefIdxL1ActiveMinus1 = p.numRefIdxL1DefaultActiveMinus1

        r.readExpGolomb() // first_mb_in_slice
        val sliceType = r.readExpGolomb() % 5
        r.readExpGolomb() // pic_parameter_set_id
        if (s.separateColourPlaneFlag == 1) r.consumeBits(2) // colour_plane_id
        r.consumeBits(s.log2MaxFrameNum) // frame_num
        var fieldPicFlag = false
        if (s.frameMbsOnlyFlag == 0) {
            fieldPicFlag = r.readBit() == 1
            if (fieldPicFlag) r.consumeBits(1) // bottom_field_flag
        }
        if (isIdr) r.readExpGolomb() // idr_pic_id
        if (s.picOrderCntType == 0L) {
            r.consumeBits(s.log2MaxPicOrderCntLsb) // pic_order_cnt_lsb
            if (p.bottomFieldPicOrderInFramePresentFlag && !fieldPicFlag) r.readExpGolomb() // delta_pic_order_cnt_bottom
        }
        if (s.picOrderCntType == 1L && s.deltaPicOrderAlwaysZeroFlag == 0) {
            r.readExpGolomb() // delta_pic_order_cnt[0]
            if (p.bottomFieldPicOrderInFramePresentFlag && !fieldPicFlag) r.readExpGolomb() // delta_pic_order_cnt[1]
        }
        if (p.redundantPicCntPresentFlag != 0) r.readExpGolomb() // redundant_pic_cnt
        if (sliceType == SLICE_B) r.consumeBits(1) // direct_spatial_mv_pred_flag
        if (sliceType == SLICE_P || sliceType == SLICE_B || sliceType == SLICE_SP) {
            if (r.readBit() == 1) { // num_ref_idx_active_override_flag
                numRefIdxL0ActiveMinus1 = r.readExpGolomb()
                if (!r.ok || numRefIdxL0ActiveMinus1 > MAX_REFERENCE_INDEX) return
                if (sliceType == SLICE_B) {
                    numRefIdxL1ActiveMinus1 = r.readExpGolomb()
                    if (!r.ok || numRefIdxL1ActiveMinus1 > MAX_REFERENCE_INDEX) return
                }
            }
        }
        if (!r.ok) return
        if (naluType == 20 || naluType == 21) return // MVC: unsupported, as in libwebrtc

        // ref_pic_list_modification()
        if (sliceType % 5 != 2L && sliceType % 5 != 4L) {
            if (r.readBit() == 1) skipRefPicListModification(r) // ref_pic_list_modification_flag_l0
        }
        if (sliceType % 5 == 1L) {
            if (r.readBit() == 1) skipRefPicListModification(r) // ref_pic_list_modification_flag_l1
        }
        if (!r.ok) return

        if ((p.weightedPredFlag && (sliceType == SLICE_P || sliceType == SLICE_SP)) ||
            (p.weightedBipredIdc == 1L && sliceType == SLICE_B)
        ) {
            // pred_weight_table()
            r.readExpGolomb() // luma_log2_weight_denom
            val chromaArrayType = if (s.separateColourPlaneFlag == 0) s.chromaFormatIdc else 0
            if (chromaArrayType != 0) r.readExpGolomb() // chroma_log2_weight_denom
            skipWeights(r, numRefIdxL0ActiveMinus1, chromaArrayType)
            if (sliceType % 5 == 1L) skipWeights(r, numRefIdxL1ActiveMinus1, chromaArrayType)
        }

        if (nalRefIdc != 0) {
            // dec_ref_pic_marking()
            if (isIdr) {
                r.consumeBits(2) // no_output_of_prior_pics_flag, long_term_reference_flag
            } else if (r.readBit() == 1) { // adaptive_ref_pic_marking_mode_flag
                do {
                    val op = r.readExpGolomb() // memory_management_control_operation
                    if (op == 1L || op == 3L) r.readExpGolomb() // difference_of_pic_nums_minus1
                    if (op == 2L) r.readExpGolomb() // long_term_pic_num
                    if (op == 3L || op == 6L) r.readExpGolomb() // long_term_frame_idx
                    if (op == 4L) r.readExpGolomb() // max_long_term_frame_idx_plus1
                } while (op != 0L && r.ok)
            }
        }
        if (p.entropyCodingModeFlag && sliceType != SLICE_I && sliceType != SLICE_SI) {
            r.readExpGolomb() // cabac_init_idc
        }

        val delta = r.readSignedExpGolomb() // slice_qp_delta
        if (!r.ok) return
        if (kotlin.math.abs(delta) > MAX_ABS_QP_DELTA) return
        lastSliceQpDelta = delta
    }

    private fun skipRefPicListModification(r: BitReader) {
        do {
            val idc = r.readExpGolomb() // modification_of_pic_nums_idc
            if (idc == 0L || idc == 1L) {
                r.readExpGolomb() // abs_diff_pic_num_minus1
            } else if (idc == 2L) {
                r.readExpGolomb() // long_term_pic_num
            }
        } while (idc != 3L && r.ok)
    }

    private fun skipWeights(r: BitReader, numRefIdxActiveMinus1: Long, chromaArrayType: Int) {
        var i = 0L
        while (i <= numRefIdxActiveMinus1) {
            if (r.readBit() == 1) { // luma_weight_lX_flag
                r.readExpGolomb() // luma_weight_lX[i]
                r.readExpGolomb() // luma_offset_lX[i]
            }
            if (chromaArrayType != 0 && r.readBit() == 1) { // chroma_weight_lX_flag
                repeat(2) {
                    r.readExpGolomb() // chroma_weight_lX[i][j]
                    r.readExpGolomb() // chroma_offset_lX[i][j]
                }
            }
            i++
        }
    }

    /** SpsParser::ParseSpsUpToVui(), only the fields the slice header needs. */
    private fun parseSps(buf: ByteArray): Sps? {
        val r = BitReader(buf)
        var chromaFormatIdc = 1
        var separateColourPlaneFlag = 0
        val profileIdc = r.readBits(8).toInt()
        r.consumeBits(16) // constraint flags, reserved bits, level_idc
        r.readExpGolomb() // seq_parameter_set_id
        if (profileIdc in HIGH_PROFILES) {
            chromaFormatIdc = r.readExpGolomb().toInt()
            if (chromaFormatIdc == 3) separateColourPlaneFlag = r.readBit()
            r.readExpGolomb() // bit_depth_luma_minus8
            r.readExpGolomb() // bit_depth_chroma_minus8
            r.consumeBits(1) // qpprime_y_zero_transform_bypass_flag
            if (r.readBit() == 1) { // seq_scaling_matrix_present_flag
                val count = if (chromaFormatIdc == 3) 12 else 8
                for (i in 0 until count) {
                    if (r.readBit() == 1) { // seq_scaling_list_present_flag[i]
                        var lastScale = 8
                        var nextScale = 8
                        val size = if (i < 6) 16 else 64
                        for (j in 0 until size) {
                            if (nextScale != 0) {
                                val deltaScale = r.readSignedExpGolomb()
                                if (!r.ok || deltaScale < -128 || deltaScale > 127) return null
                                nextScale = (lastScale + deltaScale + 256) % 256
                            }
                            if (nextScale != 0) lastScale = nextScale
                        }
                    }
                }
            }
        }
        val log2MaxFrameNumMinus4 = r.readExpGolomb()
        if (!r.ok || log2MaxFrameNumMinus4 > MAX_LOG2_MINUS4) return null
        val picOrderCntType = r.readExpGolomb()
        var log2MaxPicOrderCntLsb = 0
        var deltaPicOrderAlwaysZeroFlag = 0
        if (picOrderCntType == 0L) {
            val lsbMinus4 = r.readExpGolomb()
            if (!r.ok || lsbMinus4 > MAX_LOG2_MINUS4) return null
            log2MaxPicOrderCntLsb = lsbMinus4.toInt() + 4
        } else if (picOrderCntType == 1L) {
            deltaPicOrderAlwaysZeroFlag = r.readBit()
            r.readExpGolomb() // offset_for_non_ref_pic
            r.readExpGolomb() // offset_for_top_to_bottom_field
            val n = r.readExpGolomb() // num_ref_frames_in_pic_order_cnt_cycle
            var i = 0L
            while (i < n) {
                r.readExpGolomb() // offset_for_ref_frame[i]
                if (!r.ok) return null
                i++
            }
        }
        r.readExpGolomb() // max_num_ref_frames
        r.consumeBits(1) // gaps_in_frame_num_value_allowed_flag
        r.readExpGolomb() // pic_width_in_mbs_minus1
        r.readExpGolomb() // pic_height_in_map_units_minus1
        val frameMbsOnlyFlag = r.readBit()
        if (frameMbsOnlyFlag == 0) r.consumeBits(1) // mb_adaptive_frame_field_flag
        r.consumeBits(1) // direct_8x8_inference_flag
        if (r.readBit() == 1) repeat(4) { r.readExpGolomb() } // frame_cropping_flag + offsets
        r.readBit() // vui_parameters_present_flag
        if (!r.ok) return null
        return Sps(
            separateColourPlaneFlag, chromaFormatIdc, log2MaxFrameNumMinus4.toInt() + 4, picOrderCntType,
            log2MaxPicOrderCntLsb, deltaPicOrderAlwaysZeroFlag, frameMbsOnlyFlag,
        )
    }

    /** PpsParser::ParseInternal(). */
    private fun parsePps(buf: ByteArray): Pps? {
        val r = BitReader(buf)
        r.readExpGolomb() // pic_parameter_set_id
        r.readExpGolomb() // seq_parameter_set_id
        val entropyCodingModeFlag = r.readBit() == 1
        val bottomFieldPicOrderInFramePresentFlag = r.readBit() == 1
        val numSliceGroupsMinus1 = r.readExpGolomb()
        if (numSliceGroupsMinus1 > 0) {
            when (r.readExpGolomb()) { // slice_group_map_type
                0L -> {
                    var i = 0L
                    while (i <= numSliceGroupsMinus1 && r.ok) {
                        r.readExpGolomb() // run_length_minus1
                        i++
                    }
                }
                1L -> {} // not implemented in libwebrtc either
                2L -> {
                    var i = 0L
                    while (i <= numSliceGroupsMinus1 && r.ok) {
                        r.readExpGolomb() // top_left
                        r.readExpGolomb() // bottom_right
                        i++
                    }
                }
                3L, 4L, 5L -> {
                    r.consumeBits(1) // slice_group_change_direction_flag
                    r.readExpGolomb() // slice_group_change_rate_minus1
                }
                6L -> {
                    val picSizeInMapUnits = r.readExpGolomb() + 1
                    val idBits = 1 + (64 - java.lang.Long.numberOfLeadingZeros(numSliceGroupsMinus1))
                    val bits = idBits.toLong() * picSizeInMapUnits
                    if (!r.ok || bits > Int.MAX_VALUE) return null
                    r.consumeBits(bits.toInt())
                }
            }
        }
        val l0 = r.readExpGolomb()
        val l1 = r.readExpGolomb()
        if (!r.ok || l0 > MAX_REFERENCE_INDEX || l1 > MAX_REFERENCE_INDEX) return null
        val weightedPredFlag = r.readBit() == 1
        val weightedBipredIdc = r.readBits(2)
        val picInitQpMinus26 = r.readSignedExpGolomb()
        if (!r.ok || picInitQpMinus26 > 25 || picInitQpMinus26 < -26) return null
        r.readExpGolomb() // pic_init_qs_minus26
        r.readExpGolomb() // chroma_qp_index_offset
        r.consumeBits(2) // deblocking_filter_control_present_flag, constrained_intra_pred_flag
        val redundantPicCntPresentFlag = r.readBit()
        if (!r.ok) return null
        return Pps(
            entropyCodingModeFlag, bottomFieldPicOrderInFramePresentFlag, l0, l1, weightedPredFlag,
            weightedBipredIdc, picInitQpMinus26, redundantPicCntPresentFlag,
        )
    }

    /** rtc_base BitstreamReader: reading past the end makes it not [ok] and returns zeros. */
    private class BitReader(private val buf: ByteArray) {
        private var bit = 0L
        var ok = true
            private set

        fun readBit(): Int {
            if (!ok || bit >= buf.size * 8L) {
                ok = false
                return 0
            }
            val v = (buf[(bit ushr 3).toInt()].toInt() shr (7 - (bit and 7).toInt())) and 1
            bit++
            return v
        }

        fun readBits(n: Int): Long {
            var v = 0L
            repeat(n) { v = (v shl 1) or readBit().toLong() }
            return v
        }

        fun consumeBits(n: Int) {
            if (!ok || bit + n > buf.size * 8L) {
                ok = false
                return
            }
            bit += n
        }

        /** ReadExponentialGolomb(): unsigned, at most 32 leading zeros. */
        fun readExpGolomb(): Long {
            var zeros = 0
            while (readBit() == 0) {
                if (++zeros >= 32) {
                    ok = false
                    return 0
                }
            }
            return (1L shl zeros) + readBits(zeros) - 1
        }

        fun readSignedExpGolomb(): Int {
            val u = readExpGolomb()
            return if (u and 1L == 0L) -(u / 2).toInt() else ((u + 1) / 2).toInt()
        }
    }

    private companion object {
        const val NALU_IDR = 5
        const val NALU_SEI = 6
        const val NALU_SPS = 7
        const val NALU_PPS = 8
        const val NALU_AUD = 9
        const val NALU_FILLER = 12
        const val NALU_PREFIX = 14
        const val SLICE_P = 0L
        const val SLICE_B = 1L
        const val SLICE_I = 2L
        const val SLICE_SP = 3L
        const val SLICE_SI = 4L
        const val MAX_REFERENCE_INDEX = 31L
        const val MAX_LOG2_MINUS4 = 12L
        const val MAX_ABS_QP_DELTA = 51
        const val MIN_QP = 0
        const val MAX_QP = 51
        val HIGH_PROFILES = setOf(100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134)

        /** H264::ParseRbsp() of nal from index from: drops the emulation-prevention 0x03 of every 00 00 03. */
        fun rbsp(nal: ByteArray, from: Int): ByteArray {
            val out = java.io.ByteArrayOutputStream(nal.size)
            var i = from
            while (i < nal.size) {
                if (nal.size - i >= 3 && nal[i].toInt() == 0 && nal[i + 1].toInt() == 0 && nal[i + 2].toInt() == 3) {
                    out.write(0)
                    out.write(0)
                    i += 3
                } else {
                    out.write(nal[i].toInt())
                    i++
                }
            }
            return out.toByteArray()
        }
    }
}
