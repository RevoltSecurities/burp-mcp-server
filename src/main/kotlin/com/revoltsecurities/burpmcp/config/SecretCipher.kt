package com.revoltsecurities.burpmcp.config

import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-256-GCM encryption for secrets (the bearer token) stored in Burp Preferences.
 *
 * Caveat (documented, same class of limitation as the reference project): the master key is stored in
 * Burp Preferences beside the ciphertext, so this protects against casual preference inspection / export,
 * not against a local attacker who can read the preference store. It is obfuscation at rest, not a vault.
 */
class SecretCipher private constructor(private val key: SecretKey) {

    /** Returns base64(iv || ciphertext || tag), or empty string for blank input. */
    fun encrypt(plaintext: String): String {
        if (plaintext.isEmpty()) return ""
        val iv = ByteArray(IV_BYTES).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        }
        val ct = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(iv + ct)
    }

    /** Inverse of [encrypt]. Returns empty string for blank input; throws on tampered ciphertext. */
    fun decrypt(encoded: String): String {
        if (encoded.isEmpty()) return ""
        val all = Base64.getDecoder().decode(encoded)
        val iv = all.copyOfRange(0, IV_BYTES)
        val ct = all.copyOfRange(IV_BYTES, all.size)
        val cipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        }
        return String(cipher.doFinal(ct), Charsets.UTF_8)
    }

    companion object {
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_BYTES = 12
        private const val TAG_BITS = 128
        private const val KEY_BITS = 256

        /** Load the per-install master key from [provided], or generate + persist a new one via [persist]. */
        fun loadOrCreate(provided: String?, persist: (String) -> Unit): SecretCipher {
            val keyBytes = if (!provided.isNullOrEmpty()) {
                Base64.getDecoder().decode(provided)
            } else {
                val generated = KeyGenerator.getInstance("AES").apply { init(KEY_BITS) }.generateKey().encoded
                persist(Base64.getEncoder().encodeToString(generated))
                generated
            }
            return SecretCipher(SecretKeySpec(keyBytes, "AES"))
        }
    }
}
