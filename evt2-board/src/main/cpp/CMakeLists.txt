cmake_minimum_required(VERSION 3.22.1)
project(boardaudiocrypto CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Not linked against libwebrtc (libjingle_peerconnection_so.so from the AAR): the objects are handed to it as raw
# pointers (RtpSender.setFrameEncryptor / RtpReceiver.setFrameDecryptor) and only called through their vtables.
add_library(boardaudiocrypto SHARED board_audio_crypto.cpp)
target_link_libraries(boardaudiocrypto log)

# libwebrtc in the AAR uses Chromium's RELATIVE vtables (32-bit offsets from the vtable); objects we hand it must use
# the same layout, or its first AddRef() jumps to garbage. -fno-rtti: no typeinfo, so nothing refers to the NDK's
# (absolute-vtable) type_info classes.
target_compile_options(boardaudiocrypto PRIVATE -fexperimental-relative-c++-abi-vtables -fno-rtti)
