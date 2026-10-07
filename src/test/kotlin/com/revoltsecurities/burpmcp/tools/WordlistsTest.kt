package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.output.MessageRegistry
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class WordlistsTest {

    @Test
    fun `read parses lines skipping blanks and comments`(@TempDir dir: Path) {
        Files.writeString(dir.resolve("words.txt"), "admin\n# comment\n\n  root  \nbackup\n")
        assertEquals(listOf("admin", "root", "backup"), Wordlists.read("words.txt", dir))
    }

    @Test
    fun `resolve strips directory traversal to a filename under base`(@TempDir dir: Path) {
        val p = Wordlists.resolve("../../etc/passwd", dir)
        assertTrue(p.startsWith(dir.toAbsolutePath().normalize()))
        assertEquals("passwd", p.fileName.toString())
    }

    @Test
    fun `read of a missing file throws`(@TempDir dir: Path) {
        assertThrows(IllegalArgumentException::class.java) { Wordlists.read("nope.txt", dir) }
    }

    @Test
    fun `list reports files with line counts`(@TempDir dir: Path) {
        Files.writeString(dir.resolve("a.txt"), "x\ny\n")
        val files = Wordlists.list(dir)
        assertEquals(1, files.size)
        assertEquals("a.txt", files.first().name)
        assertEquals(2, files.first().lines)
    }

    @Test
    fun `list of a missing dir is empty`(@TempDir dir: Path) {
        assertTrue(Wordlists.list(dir.resolve("does-not-exist")).isEmpty())
    }
}

/** Minimal BurpActions double (relies on interface defaults for everything not needed here). */
private class SendOnlyActions : BurpActions {
    override fun sendRequest(raw: String, host: String, port: Int, secure: Boolean, mode: String) =
        SentExchange(200, null, raw.toByteArray(), "ok".toByteArray())
    override fun sendToRepeater(raw: String, host: String, port: Int, secure: Boolean, name: String?) {}
    override fun sendToIntruder(raw: String, host: String, port: Int, secure: Boolean, name: String?) {}
    override fun includeInScope(url: String) {}
    override fun excludeFromScope(url: String) {}
    override fun setIntercept(enabled: Boolean) {}
    override fun isInterceptEnabled() = false
    override fun cookies() = emptyList<CookieDTO>()
    override fun setCookie(name: String, value: String, domain: String, path: String?, expiresEpochSec: Long?) {}
    override fun createIssue(issue: NewIssue) = true
    override fun addToSiteMap(raw: String, host: String, port: Int, secure: Boolean, responseRaw: String?) {}
    override fun sendParallel(requests: List<RawTarget>, mode: String) =
        requests.map { SentExchange(200, null, it.raw.toByteArray(), it.raw.toByteArray()) }
    override fun managedEngineAvailable() = false
}

class IntruderFilePayloadsTest {

    @Test
    fun `sniper loads payloads from a sandboxed wordlist file`(@TempDir dir: Path) {
        Files.writeString(dir.resolve("users.txt"), "admin\nroot\nguest\n")
        val tools = IntruderTools(SendOnlyActions(), MessageRegistry(), ScopeGuard({ false }, { true }), { dir.toString() })
            .build().associateBy { it.id }

        val res = runBlocking {
            tools.getValue("intruder_attack").handler(
                Args(
                    buildJsonObject {
                        put("template", JsonPrimitive("GET /u/§FUZZ§ HTTP/1.1\r\nHost: t\r\n\r\n"))
                        put("attackType", JsonPrimitive("sniper"))
                        put("payloadFile", JsonPrimitive("users.txt"))
                        put("host", JsonPrimitive("t.com"))
                    },
                ),
            )
        }
        val r = Results.json.decodeFromJsonElement(IntruderResult.serializer(), res.structuredContent!!)
        assertEquals(3, r.sent) // one request per wordlist entry
    }

    @Test
    fun `list_wordlists reports the configured directory files`(@TempDir dir: Path) {
        Files.writeString(dir.resolve("w.txt"), "a\nb\n")
        val tools = IntruderTools(SendOnlyActions(), MessageRegistry(), ScopeGuard({ false }, { true }), { dir.toString() })
            .build().associateBy { it.id }
        val res = runBlocking { tools.getValue("list_wordlists").handler(Args(buildJsonObject {})) }
        val r = Results.json.decodeFromJsonElement(WordlistsResult.serializer(), res.structuredContent!!)
        assertEquals(1, r.files.size)
        assertEquals("w.txt", r.files.first().name)
    }
}
