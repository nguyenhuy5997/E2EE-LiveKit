package com.evt2.board.rtc

import kotlinx.coroutines.delay
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

/**
 * Test stand-in for the board: AES-256-GCM with one key for both directions (so what it seals it can open), the
 * board's nonce | tag | ciphertext layout, a replay check, and an optional delay per call.
 */
class SoftBoard(private val replayCheck: Boolean = true, private val delayMs: () -> Long = { 0L }) : BoardCipher {
    private val key = SecretKeySpec(Random.nextBytes(32), "AES")
    private val counter = AtomicLong(0)
    private val seen = HashSet<String>()
    val calls = AtomicLong(0)
    @Volatile var hang = false

    override suspend fun encrypt(plain: ByteArray, isAudio: Boolean): ByteArray {
        work()
        val nonce = ByteArray(12).also { n -> val c = counter.incrementAndGet(); for (i in 0 until 8) n[4 + i] = (c shr (56 - 8 * i)).toByte() }
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce)) }
        val out = c.doFinal(plain) // ciphertext || tag
        return nonce + out.copyOfRange(out.size - 16, out.size) + out.copyOfRange(0, out.size - 16)
    }

    override suspend fun decrypt(sealed: ByteArray, isAudio: Boolean): ByteArray {
        work()
        require(sealed.size >= 28)
        val nonce = sealed.copyOfRange(0, 12)
        if (replayCheck) synchronized(seen) { require(seen.add(nonce.joinToString(","))) { "replayed nonce" } }
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, nonce)) }
        return c.doFinal(sealed.copyOfRange(28, sealed.size) + sealed.copyOfRange(12, 28))
    }

    private suspend fun work() {
        calls.incrementAndGet()
        while (hang) delay(5)
        val d = delayMs()
        if (d > 0) delay(d)
    }
}
