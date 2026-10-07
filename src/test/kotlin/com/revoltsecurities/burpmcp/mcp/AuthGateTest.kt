package com.revoltsecurities.burpmcp.mcp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class AuthGateTest {

    @Test
    fun `blank required token allows everything (unauthenticated-local)`() {
        val gate = AuthGate("")
        assertNull(gate.evaluate(null))
        assertNull(gate.evaluate("Bearer anything"))
    }

    @Test
    fun `missing header is rejected when a token is required`() {
        val denial = AuthGate("secret-token").evaluate(null)
        assertEquals(401, denial?.status)
    }

    @Test
    fun `malformed header without Bearer prefix is rejected`() {
        val denial = AuthGate("secret-token").evaluate("secret-token")
        assertEquals(401, denial?.status)
    }

    @Test
    fun `wrong token is rejected`() {
        val denial = AuthGate("secret-token").evaluate("Bearer nope")
        assertEquals(401, denial?.status)
    }

    @Test
    fun `correct token is allowed`() {
        assertNull(AuthGate("secret-token").evaluate("Bearer secret-token"))
    }

    @Test
    fun `bearer prefix is case-insensitive`() {
        assertNull(AuthGate("secret-token").evaluate("bearer secret-token"))
    }
}
