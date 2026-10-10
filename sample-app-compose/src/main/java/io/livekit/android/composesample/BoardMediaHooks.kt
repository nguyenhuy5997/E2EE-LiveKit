package io.livekit.android.composesample

import android.app.Application
import android.util.Log
import com.evt2.board.link.CaChannel
import com.evt2.board.link.CaHandshake
import com.evt2.board.link.DeviceLink
import com.evt2.board.rtc.BoardAudioCrypto
import com.evt2.board.rtc.BoardVideoDecoderFactory
import com.evt2.board.rtc.BoardVideoEncoderFactory
import com.evt2.board.rtc.DeviceLinkCipher
import com.evt2.board.rtc.SwitchableCipher
import io.livekit.android.LiveKitOverrides
import io.livekit.android.RoomOptions
import io.livekit.android.evt2.Evt2RtpHooks
import io.livekit.android.events.RoomEvent
import io.livekit.android.events.collect
import io.livekit.android.room.Room
import io.livekit.android.room.datastream.StreamTextOptions
import io.livekit.android.sample.CallMediaHooks
import io.livekit.android.util.flow
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import livekit.org.webrtc.EglBase

/** "E2EE on the board" mode: every audio and video frame is encrypted and decrypted by the EVT2 board on USB. */
fun createBoardMediaHooks(application: Application): CallMediaHooks = BoardMediaHooks(application)

/**
 * The call runs on LiveKit as usual, but:
 * - before connecting, the board is opened over USB and the RTP hooks attach the board's audio FrameEncryptor /
 *   FrameDecryptor to every audio sender / receiver the SDK creates;
 * - after connecting and before publishing, the two boards run the CA handshake over a LiveKit text stream (topic
 *   [TOPIC]) and the board opens its media session. Only then are the microphone and camera published;
 * - video is sealed inside the hardware H.264 encoder and opened before the decoder ([BoardVideoEncoderFactory]).
 * Until the session is open, [cipher] refuses every frame, so nothing leaves the phone unencrypted.
 * LiveKit's own software E2EE is off in this mode.
 */
private class BoardMediaHooks(application: Application) : CallMediaHooks {
    private val mutableStatus = MutableStateFlow("")
    override val status: StateFlow<String> = mutableStatus

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val link = DeviceLink(application)
    private val cipher = SwitchableCipher()
    private val eglBase = EglBase.create()
    private val audioEncryptor = BoardAudioCrypto.Encryptor()
    private val audioDecryptor = BoardAudioCrypto.Decryptor()

    /** Incoming CA messages, in the order their streams started (a big M3 must not be overtaken by M4). */
    private var inbox = Channel<Deferred<String>>(Channel.UNLIMITED)
    private var sessionId: Int? = null

    private fun status(text: String) {
        Log.i(TAG, text)
        mutableStatus.value = text
    }

    override fun roomOptions(base: RoomOptions): RoomOptions = base.copy(e2eeOptions = null)

    override fun overrides(base: LiveKitOverrides): LiveKitOverrides = base.copy(
        eglBase = eglBase,
        videoEncoderFactory = BoardVideoEncoderFactory(eglBase.eglBaseContext, cipher, scope),
        videoDecoderFactory = BoardVideoDecoderFactory(eglBase.eglBaseContext, cipher),
    )

    override suspend fun beforeConnect(room: Room) {
        Evt2RtpHooks.onSenderCreated = { kind, sender -> if (kind == "audio") sender.setFrameEncryptor(audioEncryptor) }
        Evt2RtpHooks.onReceiverCreated = { kind, receiver -> if (kind == "audio") receiver.setFrameDecryptor(audioDecryptor) }

        inbox = Channel(Channel.UNLIMITED)
        val box = inbox
        room.unregisterTextStreamHandler(TOPIC)
        room.registerTextStreamHandler(TOPIC) { reader, _ ->
            box.trySend(scope.async { reader.readAll().joinToString("") })
        }

        status("Đang kết nối board qua USB...")
        try {
            link.connect()
        } catch (e: Exception) {
            status("Không kết nối được board: ${e.message}")
            throw e
        }
    }

    override suspend fun beforePublish(room: Room) {
        status("Đang chờ đối tác vào phòng...")
        val peer = room::remoteParticipants.flow.map { it.values.firstOrNull() }.first { it != null }!!
        val me = room.localParticipant.identity?.value ?: throw IllegalStateException("no local identity")
        val peerIdentity = peer.identity ?: throw IllegalStateException("peer has no identity")
        if (me == peerIdentity.value) throw IllegalStateException("hai máy dùng cùng identity '$me'")

        val channel = object : CaChannel {
            override suspend fun send(message: String) {
                room.localParticipant.sendText(
                    message,
                    StreamTextOptions(topic = TOPIC, destinationIdentities = listOf(peerIdentity)),
                ).getOrThrow()
            }

            override suspend fun receive(): String = inbox.receive().await()
        }

        val result = try {
            // Role A (initiator) = the smaller identity, so both phones agree without an extra message.
            CaHandshake(link, channel, initiator = me < peerIdentity.value, onStatus = ::status).run()
        } catch (e: Exception) {
            status("Bắt tay CA thất bại: ${e.message}")
            throw e
        }

        val id = link.startAudioSession("livekit-call")
        sessionId = id
        val sessionCipher = DeviceLinkCipher(link, id)
        cipher.set(sessionCipher)
        BoardAudioCrypto.attach(sessionCipher)
        status("Mã hóa trên board · đối tác ${result.peerId}")

        scope.launch {
            room.events.collect {
                if (it is RoomEvent.ParticipantDisconnected && it.participant.identity == peerIdentity) {
                    status("Đối tác đã rời phòng: thoát cuộc gọi rồi gọi lại (cần bắt tay CA mới)")
                }
            }
        }
    }

    override fun release() {
        Evt2RtpHooks.onSenderCreated = null
        Evt2RtpHooks.onReceiverCreated = null
        BoardAudioCrypto.detach()
        cipher.clear()
        // libwebrtc keeps its own references to these; this drops ours.
        audioEncryptor.release()
        audioDecryptor.release()
        scope.cancel()
        runBlocking {
            sessionId?.let { runCatching { link.abortSession(it) } }
            runCatching { link.disconnect() }
        }
        eglBase.release()
    }

    private companion object {
        const val TAG = "BoardMediaHooks"
        const val TOPIC = "evt2.ca"
    }
}
