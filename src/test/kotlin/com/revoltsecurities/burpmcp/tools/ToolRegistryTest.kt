package com.revoltsecurities.burpmcp.tools

import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Verifies the wire-path registration gating: Professional-only and disabled tools are never registered on
 * the MCP server. (The mutating/unsafe gate at dispatch is proven live — http_send returns an "unsafe
 * disabled" error against a real Burp.)
 */
class ToolRegistryTest {

    private fun spec(id: String, mutating: Boolean = false, proOnly: Boolean = false) =
        ToolSpec(id, id, "desc", "Test", SchemaBuilder.empty(), mutating = mutating, proOnly = proOnly) { Results.text("ok") }

    private fun newServer() = Server(
        Implementation("t", "0"),
        ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false))),
    )

    @Test
    fun `pro-only tools are hidden in community edition`() {
        val server = newServer()
        ToolRegistry(
            specs = listOf(spec("read"), spec("scan", proOnly = true)),
            isProfessional = false,
            isEnabled = { true },
            unsafeEnabled = { true },
            log = {},
        ).registerOn(server)
        assertTrue(server.tools.containsKey("read"))
        assertFalse(server.tools.containsKey("scan"))
    }

    @Test
    fun `pro-only tools appear in professional edition`() {
        val server = newServer()
        ToolRegistry(
            specs = listOf(spec("scan", proOnly = true)),
            isProfessional = true,
            isEnabled = { true },
            unsafeEnabled = { true },
            log = {},
        ).registerOn(server)
        assertTrue(server.tools.containsKey("scan"))
    }

    @Test
    fun `disabled tools are not registered`() {
        val server = newServer()
        ToolRegistry(
            specs = listOf(spec("a"), spec("b")),
            isProfessional = true,
            isEnabled = { it.id == "a" },
            unsafeEnabled = { true },
            log = {},
        ).registerOn(server)
        assertTrue(server.tools.containsKey("a"))
        assertFalse(server.tools.containsKey("b"))
    }
}
