package io.livekit.android.evt2

import livekit.org.webrtc.MediaStreamTrack
import livekit.org.webrtc.RtpReceiver
import livekit.org.webrtc.RtpSender

/**
 * EVT2 fork addition: called when the SDK creates an RTP sender or receiver, before any media flows through it,
 * so an app can attach its own FrameEncryptor / FrameDecryptor with no packet slipping out unencrypted (the
 * TrackPublished / TrackSubscribed events come too late for that).
 *
 * - [onSenderCreated]: on the RTC thread, right after addTransceiver() and before the publish negotiation.
 * - [onReceiverCreated]: from the subscriber PeerConnection's onAddTrack, before the track is handed to the Room.
 *
 * Both are null (no effect) unless the app sets them; they must not throw or block.
 */
object Evt2RtpHooks {
    @Volatile
    var onSenderCreated: ((kind: String, sender: RtpSender) -> Unit)? = null

    @Volatile
    var onReceiverCreated: ((kind: String, receiver: RtpReceiver) -> Unit)? = null

    internal fun senderCreated(track: MediaStreamTrack, sender: RtpSender) {
        onSenderCreated?.invoke(track.kind(), sender)
    }

    internal fun receiverCreated(track: MediaStreamTrack, receiver: RtpReceiver) {
        onReceiverCreated?.invoke(track.kind(), receiver)
    }
}
