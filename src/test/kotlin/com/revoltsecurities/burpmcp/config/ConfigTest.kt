package com.revoltsecurities.burpmcp.config

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SecretCipherTest {

    private fun newCipher() = SecretCipher.loadOrCreate(null) { /* persist no-op */ }

    @Test
    fun `encrypt then decrypt round trips`() {
        val cipher = newCipher()
        val secret = "bearer-token-123"
        val enc = cipher.encrypt(secret)
        assertNotEquals(secret, enc)
        assertEquals(secret, cipher.decrypt(enc))
    }

    @Test
    fun `empty input stays empty`() {
        val cipher = newCipher()
        assertEquals("", cipher.encrypt(""))
        assertEquals("", cipher.decrypt(""))
    }

    @Test
    fun `tampered ciphertext fails to decrypt`() {
        val cipher = newCipher()
        val enc = cipher.encrypt("secret")
        val tampered = enc.dropLast(2) + "AA"
        assertThrows(Exception::class.java) { cipher.decrypt(tampered) }
    }

    @Test
    fun `a persisted key is reused for decryption`() {
        var stored: String? = null
        val c1 = SecretCipher.loadOrCreate(null) { stored = it }
        val enc = c1.encrypt("x")
        val c2 = SecretCipher.loadOrCreate(stored) { }
        assertEquals("x", c2.decrypt(enc))
    }
}

class McpSettingsTest {

    @Test
    fun `sanitized coerces port and limits`() {
        val s = McpSettings(port = 99_999, maxConcurrentRequests = 1000, maxToolResultBytes = 1).sanitized()
        assertEquals(65_535, s.port)
        assertEquals(64, s.maxConcurrentRequests)
        assertTrue(s.maxToolResultBytes >= 4_096)
    }

    @Test
    fun `generated token is strong`() {
        val t = McpSettings.generateToken()
        assertTrue(t.length >= Defaults.MIN_TOKEN_BYTES)
        assertFalse(McpSettings(token = t).tokenIsWeak)
        assertTrue(McpSettings(token = "short").tokenIsWeak)
    }
}
