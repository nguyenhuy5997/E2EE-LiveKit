package com.evt2.board.rtc

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import livekit.org.webrtc.EglBase
import livekit.org.webrtc.EncodedImage
import livekit.org.webrtc.HardwareVideoDecoderFactory
import livekit.org.webrtc.HardwareVideoEncoderFactory
import livekit.org.webrtc.VideoCodecInfo
import livekit.org.webrtc.VideoCodecStatus
import livekit.org.webrtc.VideoDecoder
import livekit.org.webrtc.VideoDecoderFactory
import livekit.org.webrtc.VideoEncoder
import livekit.org.webrtc.VideoEncoderFactory
import livekit.org.webrtc.VideoFrame
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

/*
 * Video E2EE through the board, inside the codec instead of libwebrtc's synchronous FrameEncryptor (which would run
 * every video decrypt on libwebrtc's worker thread -- the ANR of the earlier prototype).
 *
 * Only Java codecs can be wrapped: libwebrtc's software VP8/VP9/AV1 encoders are WrappedNativeVideoEncoder, whose
 * methods are final and run in C++. So video is H.264 on the phone's hardware codec (every Android phone has one; on
 * Android 10+ libwebrtc accepts any hardware-accelerated MediaCodec). Frame format: [H264FrameFormat].
 */

/** Hardware H.264 encoders whose output is sealed by the board before RTP packetization. */
class BoardVideoEncoderFactory(
    eglContext: EglBase.Context?,
    private val cipher: BoardCipher,
    private val scope: CoroutineScope,
) : VideoEncoderFactory {
    // Constrained baseline only: both phones must agree on a profile the other's decoder takes.
    private val inner = HardwareVideoEncoderFactory(eglContext, /* enableIntelVp8Encoder = */ false, /* enableH264HighProfile = */ false)

    /** The encoder of the current call, for stats; null before the first one is created. */
    @Volatile var current: BoardVideoEncoder? = null
        private set

    override fun getSupportedCodecs(): Array<VideoCodecInfo> = inner.supportedCodecs.filter { it.name == "H264" }.toTypedArray()

    override fun createEncoder(info: VideoCodecInfo): VideoEncoder? {
        if (info.name != "H264") return null
        val enc = inner.createEncoder(info) ?: return null
        return BoardVideoEncoder(enc, cipher, scope).also { current = it }
    }
}

/**
 * Wraps a hardware H.264 [VideoEncoder]: every encoded frame goes through a [FramePipeline] (board seal, in order,
 * never blocking the encoder) before it reaches libwebrtc. After a dropped frame the next frame is forced to be a
 * keyframe, since the peer cannot decode deltas past a gap.
 */
class BoardVideoEncoder(
    private val inner: VideoEncoder,
    cipher: BoardCipher,
    scope: CoroutineScope,
) : VideoEncoder {
    private val forceKeyframe = AtomicBoolean(false)
    // Only the encoder's output thread uses it (one frame at a time), in encode order as libwebrtc's own parser.
    private val qpParser = H264QpParser()
    private var framesSeen = 0
    private var framesWithoutQp = 0
    val pipeline = FramePipeline(
        MediaCodec.H264, Direction.SEND, cipher, scope,
        maxInFlight = 2, maxQueued = 3, frameTimeoutMs = 300, onKeyframeNeeded = { forceKeyframe.set(true) },
    )

    override fun initEncode(settings: VideoEncoder.Settings, callback: VideoEncoder.Callback): VideoCodecStatus =
        inner.initEncode(settings) { image, info -> seal(image, info, callback) }

    private fun seal(image: EncodedImage, info: VideoEncoder.CodecSpecificInfo?, callback: VideoEncoder.Callback) = try {
        sealOrDrop(image, info, callback)
    } catch (e: Exception) {
        Log.e(TAG, "encoded frame dropped", e) // never throw back into the encoder's output thread
    }

    private fun sealOrDrop(image: EncodedImage, info: VideoEncoder.CodecSpecificInfo?, callback: VideoEncoder.Callback) {
        val src = image.buffer.duplicate()
        val bytes = ByteArray(src.remaining()).also { src.get(it) } // the encoder reuses its buffer after we return
        // QP read from the plaintext (the sealed frame has no readable slice header). Every frame goes through the
        // parser, even when the encoder reports a QP itself, so it always holds the latest SPS/PPS.
        val parsedQp = qpParser.parse(bytes)
        val qp = image.qp ?: parsedQp
        if (qp == null) framesWithoutQp++
        if (framesSeen++ % QP_LOG_EVERY == 0) {
            Log.i(TAG, "QP $qp (${image.encodedWidth}x${image.encodedHeight}), frames without QP: $framesWithoutQp/$framesSeen")
        }
        val width = image.encodedWidth
        val height = image.encodedHeight
        val captureNs = image.captureTimeNs
        val type = image.frameType
        val rotation = image.rotation
        pipeline.submit(bytes, type == EncodedImage.FrameType.VideoFrameKey) { sealed ->
            if (sealed == null) return@submit
            try {
                callback.onEncodedFrame(encodedImage(sealed, width, height, captureNs, type, rotation, qp), info)
            } catch (e: Exception) {
                Log.e(TAG, "onEncodedFrame failed", e)
            }
        }
    }

    override fun encode(frame: VideoFrame, info: VideoEncoder.EncodeInfo?): VideoCodecStatus = try {
        val askKey = forceKeyframe.getAndSet(false)
        val effective = if (askKey || info == null) VideoEncoder.EncodeInfo(arrayOf(
            if (askKey) EncodedImage.FrameType.VideoFrameKey else EncodedImage.FrameType.VideoFrameDelta)) else info
        inner.encode(frame, effective)
    } catch (e: Exception) {
        Log.e(TAG, "encode failed", e)
        VideoCodecStatus.ERROR
    }

    override fun release(): VideoCodecStatus = inner.release()

    override fun setRateAllocation(allocation: VideoEncoder.BitrateAllocation, framerate: Int): VideoCodecStatus =
        inner.setRateAllocation(allocation, framerate)

    override fun setRates(parameters: VideoEncoder.RateControlParameters): VideoCodecStatus = inner.setRates(parameters)

    // QP-based downscaling stays on, as without the board: libwebrtc takes the QP from EncodedImage.qp (read from
    // the plaintext above) and only parses the bitstream, which is sealed here, when that is unset.
    override fun getScalingSettings(): VideoEncoder.ScalingSettings = inner.scalingSettings

    override fun getResolutionBitrateLimits(): Array<VideoEncoder.ResolutionBitrateLimits> = inner.resolutionBitrateLimits

    override fun getEncoderInfo(): VideoEncoder.EncoderInfo = inner.encoderInfo

    override fun isHardwareEncoder(): Boolean = true

    override fun getImplementationName(): String = "board+" + inner.implementationName

    private companion object {
        const val TAG = "BoardVideoEncoder"
        const val QP_LOG_EVERY = 300 // about every 10 s at 30 fps
    }
}

/** Hardware H.264 decoders that get the board-opened frame. */
class BoardVideoDecoderFactory(eglContext: EglBase.Context?, private val cipher: BoardCipher) : VideoDecoderFactory {
    private val inner = HardwareVideoDecoderFactory(eglContext)

    @Volatile var current: BoardVideoDecoder? = null
        private set

    override fun getSupportedCodecs(): Array<VideoCodecInfo> = inner.supportedCodecs.filter { it.name == "H264" }.toTypedArray()

    override fun createDecoder(info: VideoCodecInfo): VideoDecoder? {
        if (info.name != "H264") return null
        val dec = inner.createDecoder(info) ?: return null
        return BoardVideoDecoder(dec, cipher).also { current = it }
    }
}

/**
 * Wraps a hardware H.264 [VideoDecoder]: [decode] has the board open the frame, then decodes it.
 *
 * This runs on libwebrtc's own decoder queue (not the worker thread), and the Android decoder must be called on
 * that thread, so the board call is made here synchronously. A frame that cannot be opened in [TIMEOUT_MS] is
 * reported as ERROR: libwebrtc then asks the sender for a keyframe.
 */
class BoardVideoDecoder(private val inner: VideoDecoder, private val cipher: BoardCipher) : VideoDecoder {
    val stats = PipelineStats()

    override fun initDecode(settings: VideoDecoder.Settings, callback: VideoDecoder.Callback): VideoCodecStatus =
        inner.initDecode(settings, callback)

    // libwebrtc passes a null DecodeInfo; every parameter that comes from Java is nullable here, and nothing may throw
    // back into JNI (libwebrtc aborts the whole app on a pending Java exception).
    override fun decode(image: EncodedImage, info: VideoDecoder.DecodeInfo?): VideoCodecStatus = try {
        val src = image.buffer.duplicate()
        val bytes = ByteArray(src.remaining()).also { src.get(it) }
        val t0 = System.nanoTime()
        val opened = try {
            runBlocking { withTimeoutOrNull(TIMEOUT_MS) { sealOrOpen(MediaCodec.H264, Direction.RECEIVE, cipher, bytes) } }
                .also { if (it == null) stats.droppedTimeout.incrementAndGet() }
        } catch (e: Exception) {
            stats.droppedError.incrementAndGet()
            Log.w(TAG, "frame not opened: ${e.javaClass.simpleName}: ${e.message}")
            null
        }
        if (opened == null) {
            VideoCodecStatus.ERROR
        } else {
            stats.ok.incrementAndGet()
            stats.record((System.nanoTime() - t0) / 1_000_000)
            val plain = encodedImage(opened, image.encodedWidth, image.encodedHeight, image.captureTimeNs, image.frameType, image.rotation)
            inner.decode(plain, info)
        }
    } catch (e: Exception) {
        Log.e(TAG, "decode failed", e)
        VideoCodecStatus.ERROR
    }

    override fun release(): VideoCodecStatus = inner.release()

    override fun getImplementationName(): String = "board+" + inner.implementationName

    private companion object {
        const val TAG = "BoardVideoDecoder"
        const val TIMEOUT_MS = 300L
    }
}

/** An EncodedImage over a fresh direct buffer (libwebrtc's JNI reads it with GetDirectBufferAddress). */
private fun encodedImage(
    bytes: ByteArray, width: Int, height: Int, captureNs: Long, type: EncodedImage.FrameType, rotation: Int,
    qp: Int? = null,
): EncodedImage {
    val buf = ByteBuffer.allocateDirect(bytes.size).put(bytes)
    buf.rewind()
    return EncodedImage.builder()
        .setBuffer(buf) {}
        .setEncodedWidth(width)
        .setEncodedHeight(height)
        .setCaptureTimeNs(captureNs)
        .setFrameType(type)
        .setRotation(rotation)
        .setQp(qp)
        .createEncodedImage()
}
