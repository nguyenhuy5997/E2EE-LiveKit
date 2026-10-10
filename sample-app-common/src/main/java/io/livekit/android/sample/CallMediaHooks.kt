package io.livekit.android.sample

import io.livekit.android.LiveKitOverrides
import io.livekit.android.RoomOptions
import io.livekit.android.room.Room
import kotlinx.coroutines.flow.StateFlow

/**
 * EVT2: lets the chosen E2EE mode change how a call protects its media ("Mã hóa qua QRNG-SDCARD" encrypts every
 * frame on the USB board). The other modes pass none: plain LiveKit, or LiveKit's software E2EE.
 */
interface CallMediaHooks {
    /** One status line for the call screen; empty = nothing to show. */
    val status: StateFlow<String>

    fun roomOptions(base: RoomOptions): RoomOptions = base

    fun overrides(base: LiveKitOverrides): LiveKitOverrides = base

    /** Before Room.connect(). Throw to abort the call. */
    suspend fun beforeConnect(room: Room) {}

    /** After Room.connect(), before the microphone and camera are published. Throw to abort the call. */
    suspend fun beforePublish(room: Room) {}

    /** After the room has been released. */
    fun release() {}
}
