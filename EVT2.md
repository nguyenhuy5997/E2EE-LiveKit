# EVT2 LiveKit

A fork of [LiveKit's Android SDK](https://github.com/livekit/client-sdk-android) (tag v2.29.0, branch `evt2/main`)
whose Compose sample app (`sample-app-compose`) makes 1-1 video calls in three E2EE modes, so the call quality with
and without the QRNG-SDCARD encryption board can be compared on the same network and the same server:

| Start screen | What encrypts the media |
|---|---|
| E2EE off | nothing end to end (LiveKit's DTLS-SRTP only) |
| Mã hóa qua App | LiveKit's software E2EE, shared key typed on both phones |
| Mã hóa qua QRNG-SDCARD | the board on USB: AES-256-GCM per frame, keys from a CA handshake between the two boards |

Both phones must pick the same mode; the call screen warns when they do not. Every mode uses H.264 without simulcast
and Opus without RED, so only the encryption differs.

## What was added to LiveKit

- `evt2-board/`: USB link to the board (`DeviceLink`), the CA handshake over a LiveKit text stream (`CaHandshake`),
  video sealed inside the hardware H.264 encoder/decoder (`BoardVideoCodecs`, `H264FrameFormat`), audio through a
  native FrameEncryptor/FrameDecryptor (`BoardAudioCrypto`, `cpp/board_audio_crypto.cpp`), and `H264QpParser` (the
  QP is read from the plaintext frame so libwebrtc still scales the resolution). Taken from E2EE-App
  (`com.evt2.call.link` / `.rtc`).
- `livekit-android-sdk/.../evt2/Evt2RtpHooks.kt`, called from `RTCEngine.createSenderTransceiver` and
  `SubscriberTransportObserver.onAddTrack`: attaches the audio FrameEncryptor/FrameDecryptor before any packet flows.
- `sample-app-common`: `CallMediaHooks` (the board mode plugs in here), E2EE mode choice, mode mismatch warning,
  the peer always in the big view (tap a thumbnail to show another participant).
- `sample-app-compose`: `BoardMediaHooks` (the QRNG-SDCARD mode), start screen options.

`board_audio_crypto.cpp` mirrors libwebrtc's C++ ABI (m144, arm64, relative vtables); re-check it whenever the
`webrtc` version in `gradle/libs.versions.toml` changes. The app is arm64-v8a only, minSdk 26.

## Build and run

```
set JAVA_HOME=C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot   (JDK 17; Android Studio's JDK 25 fails)
gradlew :sample-app-compose:assembleDebug
gradlew :evt2-board:testDebugUnitTest
```

Server: a LiveKit Cloud project. Tokens come from `tools/make_token.py` (API key and secret from the environment,
never from the repo):

```
set LIVEKIT_API_KEY=...
set LIVEKIT_API_SECRET=...
py -3 tools/make_token.py --room evt2-test phone1 phone2
```

Enter the project URL (`wss://<project>.livekit.cloud`) and a token per phone on the "URL & Token" tab.
