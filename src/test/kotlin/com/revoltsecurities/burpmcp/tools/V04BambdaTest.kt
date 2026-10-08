package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.output.PageEnvelope
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.file.Files

class BambdaDocTest {

    @Test
    fun `assemble builds a header and indented source block`() {
        val doc = BambdaDoc.assemble("My filter", "VIEW_FILTER", "PROXY_HTTP_HISTORY", "return requestResponse.hasResponse();")
        assertTrue(doc.contains("function: VIEW_FILTER"))
        assertTrue(doc.contains("location: PROXY_HTTP_HISTORY"))
        assertTrue(doc.contains("source: |+"))
        assertTrue(doc.contains("\n  return requestResponse.hasResponse();")) // body indented 2 spaces
        assertTrue(doc.contains("id: ")) // generated uuid
    }

    @Test
    fun `parseMeta reads the header of a document`() {
        val doc = BambdaDoc.assemble("JWT alg", "CUSTOM_COLUMN", "PROXY_HTTP_HISTORY", "return \"\";")
        val meta = BambdaDoc.parseMeta(doc)
        assertEquals("JWT alg", meta.name)
        assertEquals("CUSTOM_COLUMN", meta.function)
        assertEquals("PROXY_HTTP_HISTORY", meta.location)
        assertNotNull(meta.id)
    }

    @Test
    fun `looksLikeDocument distinguishes a full doc from a snippet`() {
        assertTrue(BambdaDoc.looksLikeDocument(BambdaDoc.assemble("n", "VIEW_FILTER", "SCANNER", "return true;")))
        assertFalse(BambdaDoc.looksLikeDocument("return requestResponse.hasResponse();"))
    }

    @Test
    fun `enum lists are populated`() {
        assertTrue(BambdaDoc.FUNCTIONS.contains("SCAN_CHECK_PASSIVE_PER_REQUEST"))
        assertTrue(BambdaDoc.LOCATIONS.contains("PROXY_WEBSOCKET"))
    }
}

class BambdaDocsTest {

    @Test
    fun `every topic has non-empty content and the index lists them`() {
        assertTrue(BambdaDocs.topics.isNotEmpty())
        BambdaDocs.topics.forEach { assertTrue(it.content.isNotBlank(), "topic ${it.key} empty") }
        val idx = BambdaDocs.index()
        assertTrue(idx.contains("format") && idx.contains("functions") && idx.contains("locations"))
        assertNotNull(BambdaDocs.topic("writing-filter"))
    }
}

class BambdaStoreTest {

    private val base = Files.createTempDirectory("bambda-test")

    @Test
    fun `save forces extension, lists, reads and deletes`() {
        BambdaStore.save("myfilter", "id: x\nfunction: VIEW_FILTER\n", base)
        val files = BambdaStore.list(base)
        assertEquals(listOf("myfilter.bambda"), files.map { it.name })
        assertTrue(BambdaStore.read("myfilter", base).contains("VIEW_FILTER"))
        assertTrue(BambdaStore.delete("myfilter.bambda", base))
        assertTrue(BambdaStore.list(base).isEmpty())
    }

    @Test
    fun `traversal is neutralized to a filename under the base`() {
        // directory parts are stripped, so a traversal name resolves to a plain file inside the sandbox
        val resolved = BambdaStore.resolve("../../escape", base)
        assertTrue(resolved.startsWith(base.toAbsolutePath().normalize()))
        assertEquals("escape.bambda", resolved.fileName.toString())
        // a pure dot name is rejected outright
        assertThrows(IllegalArgumentException::class.java) { BambdaStore.resolve("..", base) }
    }
}

class BambdaRepoPathTest {

    @Test
    fun `safePath accepts a bambda path and rejects bad ones`() {
        assertEquals("Filter/Proxy/HTTP/X.bambda", BambdaRepo.safePath("Filter/Proxy/HTTP/X.bambda"))
        assertEquals("a/b.bambda", BambdaRepo.safePath("/a/b.bambda")) // leading slash trimmed
        assertThrows(IllegalArgumentException::class.java) { BambdaRepo.safePath("../../etc/passwd.bambda") }
        assertThrows(IllegalArgumentException::class.java) { BambdaRepo.safePath("Filter/X.java") }
        assertThrows(IllegalArgumentException::class.java) { BambdaRepo.safePath("https://evil/x.bambda") }
    }

    @Test
    fun `categoryOf returns the top folder`() {
        assertEquals("Filter", BambdaRepo.categoryOf("Filter/Proxy/HTTP/X.bambda"))
        assertEquals("CustomAction", BambdaRepo.categoryOf("CustomAction/Y.bambda"))
    }
}

private class FakeBambdaActions(var outcome: ImportOutcome = ImportOutcome("LOADED_WITHOUT_ERRORS", ok = true)) : BurpActions {
    var lastImported: String? = null
    override fun sendRequest(raw: String, host: String, port: Int, secure: Boolean, mode: String) =
        SentExchange(200, null, raw.toByteArray(), ByteArray(0))
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
    override fun sendParallel(requests: List<RawTarget>, mode: String) = emptyList<SentExchange>()
    override fun managedEngineAvailable() = false
    override fun importBambda(script: String): ImportOutcome { lastImported = script; return outcome }
}

private class FakeRepo : BambdaRepo {
    override suspend fun listScripts() = listOf(
        BambdaRepoEntry("Filter/Proxy/HTTP/DetectSQLErrors.bambda", "DetectSQLErrors.bambda", "Filter"),
        BambdaRepoEntry("CustomAction/RetryUntilSuccess.bambda", "RetryUntilSuccess.bambda", "CustomAction"),
    )
    override suspend fun fetch(path: String): String =
        BambdaDoc.assemble("Detect SQL Errors", "VIEW_FILTER", "PROXY_HTTP_HISTORY", "/** @author x **/\nreturn true;")
}

class BambdaToolsTest {

    private val actions = FakeBambdaActions()
    private val dir = Files.createTempDirectory("bambda-tools").toString()
    private fun tools(docChunk: Int = 6_000) =
        BambdaTools(actions, { dir }, FakeRepo(), 96_000, docChunk).build().associateBy { it.id }

    private fun call(id: String, docChunk: Int = 6_000, build: kotlinx.serialization.json.JsonObjectBuilder.() -> Unit = {}) =
        runBlocking { tools(docChunk).getValue(id).handler(Args(buildJsonObject(build))) }

    @Test
    fun `bambda_import assembles a document from structured fields`() {
        call("bambda_import") {
            put("name", JsonPrimitive("t"))
            put("function", JsonPrimitive("VIEW_FILTER"))
            put("location", JsonPrimitive("PROXY_HTTP_HISTORY"))
            put("source", JsonPrimitive("return requestResponse.hasResponse();"))
        }
        val doc = actions.lastImported!!
        assertTrue(doc.contains("function: VIEW_FILTER") && doc.contains("location: PROXY_HTTP_HISTORY"))
        assertTrue(doc.contains("source: |+"))
    }

    @Test
    fun `bambda_import rejects a bare snippet with guidance`() {
        val res = call("bambda_import") { put("document", JsonPrimitive("return true;")) }
        assertTrue(res.isError == true) // not a full document, no structured fields → error
    }

    @Test
    fun `bambda_import surfaces parser errors as an error result`() {
        actions.outcome = ImportOutcome("LOADED_WITH_ERRORS", listOf("line 2: bad"), ok = false)
        val res = call("bambda_import") {
            put("function", JsonPrimitive("VIEW_FILTER")); put("location", JsonPrimitive("SCANNER")); put("source", JsonPrimitive("x"))
        }
        assertTrue(res.isError == true)
    }

    @Test
    fun `bambda_script_doc returns index then topic content with pagination`() {
        val idx = Results.json.decodeFromJsonElement(BambdaDocResult.serializer(), call("bambda_script_doc").structuredContent!!)
        assertNotNull(idx.topics); assertTrue(idx.topics!!.contains("format"))

        val p1 = Results.json.decodeFromJsonElement(BambdaDocResult.serializer(), call("bambda_script_doc", docChunk = 40) { put("topic", JsonPrimitive("format")) }.structuredContent!!)
        assertEquals(0, p1.offset); assertTrue(p1.truncated); assertNotNull(p1.nextOffset)
        val p2 = Results.json.decodeFromJsonElement(BambdaDocResult.serializer(), call("bambda_script_doc", docChunk = 40) { put("topic", JsonPrimitive("format")); put("offset", JsonPrimitive(p1.nextOffset!!)) }.structuredContent!!)
        assertEquals(p1.nextOffset, p2.offset)

        assertTrue(call("bambda_script_doc") { put("topic", JsonPrimitive("nope")) }.isError == true)
    }

    @Test
    fun `bambda_repo_list filters by category and bambda_fetch returns content`() {
        val env = Results.json.decodeFromJsonElement(
            PageEnvelope.serializer(BambdaRepoEntry.serializer()),
            call("bambda_repo_list") { put("category", JsonPrimitive("CustomAction")) }.structuredContent!!,
        )
        assertEquals(listOf("CustomAction/RetryUntilSuccess.bambda"), env.items.map { it.path })

        val fetched = Results.json.decodeFromJsonElement(
            BambdaFetchResult.serializer(),
            call("bambda_fetch") { put("path", JsonPrimitive("Filter/Proxy/HTTP/DetectSQLErrors.bambda")) }.structuredContent!!,
        )
        assertEquals("VIEW_FILTER", fetched.meta.function)
        assertTrue(fetched.content.contains("source: |+"))
    }

    @Test
    fun `save list get delete round trip through the tools`() {
        call("bambda_save") { put("name", JsonPrimitive("mine")); put("content", JsonPrimitive("function: VIEW_FILTER\n")) }
        val listed = Results.json.decodeFromJsonElement(BambdaListResult.serializer(), call("bambda_list").structuredContent!!)
        assertEquals(listOf("mine.bambda"), listed.files.map { it.name })
        val got = Results.json.decodeFromJsonElement(BambdaFile.serializer(), call("bambda_get") { put("name", JsonPrimitive("mine")) }.structuredContent!!)
        assertTrue(got.content.contains("VIEW_FILTER"))
        assertFalse(call("bambda_delete") { put("name", JsonPrimitive("mine")) }.isError == true)
    }

    @Test
    fun `mutating flags`() {
        val t = tools()
        assertTrue(t.getValue("bambda_import").mutating)
        assertTrue(t.getValue("bambda_save").mutating)
        assertTrue(t.getValue("bambda_delete").mutating)
        assertFalse(t.getValue("bambda_list").mutating)
        assertFalse(t.getValue("bambda_repo_list").mutating)
        assertFalse(t.getValue("bambda_fetch").mutating)
        assertFalse(t.getValue("bambda_script_doc").mutating)
    }
}
