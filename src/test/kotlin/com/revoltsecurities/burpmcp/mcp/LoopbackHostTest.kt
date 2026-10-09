package com.revoltsecurities.burpmcp.mcp

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Regression tests for [isLoopbackHost]. This is a security boundary: it gates the tokenless loopback server's
 * Origin/Host checks (DNS-rebinding defense). A previous `startsWith("127.")` implementation misclassified
 * attacker-registered names like `127.0.0.1.evil.com` as loopback, bypassing the gate — these tests pin the
 * strict dotted-quad parse that closed it.
 */
class LoopbackHostTest {

    @Test
    fun `genuine loopback literals and names are loopback`() {
        assertTrue(isLoopbackHost("127.0.0.1"))
        assertTrue(isLoopbackHost("127.1.2.3"))
        assertTrue(isLoopbackHost("127.255.255.255"))
        assertTrue(isLoopbackHost("localhost"))
        assertTrue(isLoopbackHost("::1"))
        assertTrue(isLoopbackHost("0:0:0:0:0:0:0:1"))
        assertTrue(isLoopbackHost("[::1]"))
        assertTrue(isLoopbackHost("  127.0.0.1  "))
    }

    @Test
    fun `rebinding names that merely start with 127 are NOT loopback`() {
        assertFalse(isLoopbackHost("127.0.0.1.evil.com"))
        assertFalse(isLoopbackHost("127.foo.attacker.com"))
        assertFalse(isLoopbackHost("127.0.0.1x"))
        assertFalse(isLoopbackHost("127.0.0.1.nip.io"))
        assertFalse(isLoopbackHost("1270.0.0.1"))
        assertFalse(isLoopbackHost("127"))
        assertFalse(isLoopbackHost("127.0.0"))
        assertFalse(isLoopbackHost("127.0.0.256"))
        assertFalse(isLoopbackHost("127.0.0.1.1"))
        assertFalse(isLoopbackHost("evil127.0.0.1"))
        assertFalse(isLoopbackHost("example.com"))
        assertFalse(isLoopbackHost("10.0.0.1"))
    }
}
