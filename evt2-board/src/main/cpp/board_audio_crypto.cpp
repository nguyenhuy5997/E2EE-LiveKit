// board_audio_crypto.cpp -- libwebrtc FrameEncryptor / FrameDecryptor for the AUDIO stream, backed by the board.
//
// Video does not come through here: it is encrypted inside the H.264 encoder/decoder wrappers (BoardVideoCodecs.kt)
// on the codec threads. Audio has no such hook in the Java API, so libwebrtc calls these objects synchronously:
// Encrypt() on its audio encoder thread, Decrypt() on its worker thread. Both call up into Kotlin
// (com.evt2.board.rtc.BoardAudioCrypto.encrypt/decrypt), which does one USB round trip to the board (~1 ms for an Opus
// packet) with a short timeout. This file holds no key and does no cryptography.
//
// ABI: LiveKit's AAR (io.github.webrtc-sdk:android-prefixed:144.7559.14, gradle/libs.versions.toml) ships no C++
// headers, so the interfaces below MIRROR webrtc-sdk/webrtc branch m144_release (api/ref_count.h,
// api/crypto/frame_encryptor_interface.h, api/crypto/frame_decryptor_interface.h). What must match:
//   - virtual function order: AddRef, Release, ~dtor (complete + deleting), then Encrypt, GetMaxCiphertextByteSize /
//     Decrypt, GetMaxPlaintextByteSize;
//   - argument passing: ArrayView<T> (dynamic size) = { T* data_, size_t size_ } (two registers; m150's std::span has
//     the same layout); MediaType (AUDIO, VIDEO, DATA, UNSUPPORTED, ANY) and Status are int enums;
//     FrameDecryptorInterface::Result = { Status, size_t } returned in registers;
//   - the vtable FORMAT: this libwebrtc is built the Chromium way with RELATIVE vtables (32-bit offsets), so this file
//     is compiled with -fexperimental-relative-c++-abi-vtables -fno-rtti (CMakeLists.txt). Normal vtables crash on
//     the first AddRef(). Checked on the m144 arm64 .so: every virtual call is ldrsw + add + blr (relative), none is
//     an absolute ldr + blr. Only arm64-v8a is checked, so the module builds for that ABI only.
// Re-check all of it whenever the WebRTC dependency version changes.

#include <jni.h>
#include <android/log.h>

#include <atomic>
#include <cstddef>
#include <cstdint>

#define LOG_TAG "BoardAudioCrypto"
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

namespace {

// ---- mirrored libwebrtc types (see ABI above) -------------------------------------------------------------------
enum class RefCountReleaseStatus { kDroppedLastRef, kOtherRefsRemained };
enum class MediaType { AUDIO, VIDEO, DATA, UNSUPPORTED, ANY };
enum class DecryptStatus { kOk, kRecoverable, kFailedToDecrypt, kUnknown };

struct ConstSpan {
    const uint8_t *data;
    size_t size;
};
struct MutSpan {
    uint8_t *data;
    size_t size;
};
struct DecryptResult {
    DecryptStatus status;
    size_t bytes_written;
};

class RefCountInterface {
public:
    virtual void AddRef() const = 0;
    virtual RefCountReleaseStatus Release() const = 0;

protected:
    virtual ~RefCountInterface() {}
};

class FrameEncryptorInterface : public RefCountInterface {
public:
    ~FrameEncryptorInterface() override {}
    virtual int Encrypt(MediaType media_type, uint32_t ssrc, ConstSpan additional_data, ConstSpan frame,
                        MutSpan encrypted_frame, size_t *bytes_written) = 0;
    virtual size_t GetMaxCiphertextByteSize(MediaType media_type, size_t frame_size) = 0;
};

class FrameDecryptorInterface : public RefCountInterface {
public:
    ~FrameDecryptorInterface() override {}
    virtual DecryptResult Decrypt(MediaType media_type, const void *csrcs, ConstSpan additional_data,
                                  ConstSpan encrypted_frame, MutSpan frame) = 0;
    virtual size_t GetMaxPlaintextByteSize(MediaType media_type, size_t encrypted_frame_size) = 0;
};

// ---- sizes: must match MediaFrameFormat (one 28-byte seal per started 4096 bytes, 2-byte trailer) ----------------
constexpr size_t kSegment = 4096;
constexpr size_t kSeal = 28;
constexpr size_t kTrailer = 2;

size_t sealed_size(size_t plain) { return plain + kSeal * ((plain + kSegment - 1) / kSegment) + kTrailer; }

// ---- JNI ----------------------------------------------------------------------------------------------------------
JavaVM *g_vm = nullptr;
jclass g_cls = nullptr;        // com.evt2.board.rtc.BoardAudioCrypto (global ref)
jmethodID g_encrypt = nullptr; // static byte[] encrypt(byte[])
jmethodID g_decrypt = nullptr; // static byte[] decrypt(byte[])

// libwebrtc's threads are native: attach once as daemons and stay attached (they live as long as the factory).
JNIEnv *env_for_this_thread() {
    JNIEnv *env = nullptr;
    if (g_vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) == JNI_OK) {
        return env;
    }
    if (g_vm->AttachCurrentThreadAsDaemon(&env, nullptr) != JNI_OK) {
        return nullptr;
    }
    return env;
}

// Calls BoardAudioCrypto.<method>(input) and copies the result into out. Returns the bytes written, or -1.
long call_up(jmethodID method, const uint8_t *input, size_t input_len, uint8_t *out, size_t out_cap) {
    JNIEnv *env = env_for_this_thread();
    if (env == nullptr || env->PushLocalFrame(4) != 0) {
        return -1;
    }
    long written = -1;
    jbyteArray in = env->NewByteArray(static_cast<jsize>(input_len));
    if (in != nullptr) {
        env->SetByteArrayRegion(in, 0, static_cast<jsize>(input_len), reinterpret_cast<const jbyte *>(input));
        auto result = static_cast<jbyteArray>(env->CallStaticObjectMethod(g_cls, method, in));
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        } else if (result != nullptr) {
            const jsize n = env->GetArrayLength(result);
            if (static_cast<size_t>(n) <= out_cap) {
                env->GetByteArrayRegion(result, 0, n, reinterpret_cast<jbyte *>(out));
                written = n;
            } else {
                LOGW("board result %d B does not fit the %zu B buffer", n, out_cap);
            }
        }
    }
    env->PopLocalFrame(nullptr);
    return written;
}

// ---- the objects handed to libwebrtc ------------------------------------------------------------------------------
// The ref count starts at 1: that reference belongs to the Kotlin wrapper and is dropped by nativeRelease() when the
// call ends. libwebrtc takes its own references through AddRef/Release.
template <class Base>
class RefCounted : public Base {
public:
    void AddRef() const override { refs_.fetch_add(1, std::memory_order_relaxed); }
    RefCountReleaseStatus Release() const override {
        if (refs_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            delete this;
            return RefCountReleaseStatus::kDroppedLastRef;
        }
        return RefCountReleaseStatus::kOtherRefsRemained;
    }

private:
    mutable std::atomic<int> refs_{1};
};

class BoardAudioEncryptor final : public RefCounted<FrameEncryptorInterface> {
public:
    int Encrypt(MediaType, uint32_t, ConstSpan, ConstSpan frame, MutSpan encrypted_frame,
                size_t *bytes_written) override {
        const long n = call_up(g_encrypt, frame.data, frame.size, encrypted_frame.data, encrypted_frame.size);
        *bytes_written = n < 0 ? 0 : static_cast<size_t>(n);
        return n < 0 ? 1 : 0; // non-zero: libwebrtc drops this packet
    }
    size_t GetMaxCiphertextByteSize(MediaType, size_t frame_size) override { return sealed_size(frame_size); }
};

class BoardAudioDecryptor final : public RefCounted<FrameDecryptorInterface> {
public:
    DecryptResult Decrypt(MediaType, const void *, ConstSpan, ConstSpan encrypted_frame, MutSpan frame) override {
        const long n = call_up(g_decrypt, encrypted_frame.data, encrypted_frame.size, frame.data, frame.size);
        if (n < 0) {
            return {DecryptStatus::kFailedToDecrypt, 0};
        }
        return {DecryptStatus::kOk, static_cast<size_t>(n)};
    }
    // Must not exceed the encrypted size (libwebrtc decrypts in place and checks it).
    size_t GetMaxPlaintextByteSize(MediaType, size_t encrypted_frame_size) override {
        return encrypted_frame_size > kSeal + kTrailer ? encrypted_frame_size - kSeal - kTrailer : 0;
    }
};

} // namespace

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *) {
    g_vm = vm;
    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    // Resolved on the loading thread (it has the app class loader); libwebrtc's threads only see the system one.
    jclass local = env->FindClass("com/evt2/board/rtc/BoardAudioCrypto");
    if (local == nullptr) {
        return JNI_ERR;
    }
    g_cls = static_cast<jclass>(env->NewGlobalRef(local));
    env->DeleteLocalRef(local);
    g_encrypt = env->GetStaticMethodID(g_cls, "encrypt", "([B)[B");
    g_decrypt = env->GetStaticMethodID(g_cls, "decrypt", "([B)[B");
    if (g_encrypt == nullptr || g_decrypt == nullptr) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_evt2_board_rtc_BoardAudioCrypto_nativeCreateEncryptor(JNIEnv *, jclass) {
    FrameEncryptorInterface *p = new BoardAudioEncryptor(); // libwebrtc gets the interface pointer
    return reinterpret_cast<jlong>(p);
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_evt2_board_rtc_BoardAudioCrypto_nativeCreateDecryptor(JNIEnv *, jclass) {
    FrameDecryptorInterface *p = new BoardAudioDecryptor();
    return reinterpret_cast<jlong>(p);
}

extern "C" JNIEXPORT void JNICALL
Java_com_evt2_board_rtc_BoardAudioCrypto_nativeReleaseEncryptor(JNIEnv *, jclass, jlong ptr) {
    if (ptr != 0) reinterpret_cast<FrameEncryptorInterface *>(ptr)->Release();
}

extern "C" JNIEXPORT void JNICALL
Java_com_evt2_board_rtc_BoardAudioCrypto_nativeReleaseDecryptor(JNIEnv *, jclass, jlong ptr) {
    if (ptr != 0) reinterpret_cast<FrameDecryptorInterface *>(ptr)->Release();
}
