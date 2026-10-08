package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.output.CursorCodec
import com.revoltsecurities.burpmcp.output.PageEnvelope
import kotlinx.serialization.Serializable

@Serializable
data class BambdaDocResult(
    val topic: String? = null,
    val topics: List<String>? = null,
    val content: String,
    val offset: Int = 0,
    val nextOffset: Int? = null,
    val truncated: Boolean = false,
)

@Serializable
data class BambdaFetchResult(val path: String, val meta: BambdaMeta, val content: String, val note: String)

/**
 * Bambda authoring + library tools: import (assemble a valid document for the agent), a paginated DSL doc,
 * a sandboxed local `.bambda` store, and read-only browse/fetch from the official PortSwigger/bambdas repo.
 * See [BambdaDoc], [BambdaDocs], [BambdaStore], [BambdaRepo].
 */
class BambdaTools(
    private val actions: BurpActions,
    private val bambdasDir: () -> String,
    private val repo: BambdaRepo,
    private val maxBytes: Int,
    private val docChunk: Int = 6_000,
) {
    fun build(): List<ToolSpec> = listOf(
        bambdaImport(), bambdaScriptDoc(),
        bambdaSave(), bambdaList(), bambdaGet(), bambdaDelete(),
        bambdaRepoList(), bambdaFetch(),
    )

    // ---- import (the fix) ----

    private fun bambdaImport(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("document", "A COMPLETE .bambda document (id/name/function/location + a `source: |+` block). " +
                "Provide this OR the structured fields below. Get one from bambda_fetch, or see bambda_script_doc topic=format.")
            string("name", "Display name (structured form).")
            string("function", "What the body returns/does. See bambda_script_doc topic=functions.", enum = BambdaDoc.FUNCTIONS)
            string("location", "The Burp context it runs in. See bambda_script_doc topic=locations.", enum = BambdaDoc.LOCATIONS)
            string("source", "The Java body only (no import lines; Montoya API is in scope). Shape depends on 'function' — see bambda_script_doc topic=writing-filter etc.")
        }
        return ToolSpec("bambda_import", "Import Bambda", DESC_IMPORT, "Bambda", schema, mutating = true) { args ->
            val document = args.str("document")?.takeIf { BambdaDoc.looksLikeDocument(it) }
                ?: run {
                    val fn = args.str("function") ?: return@ToolSpec Results.error("Provide a full 'document', OR 'function'+'location'+'source'. See bambda_script_doc topic=format.")
                    val loc = args.str("location") ?: return@ToolSpec Results.error("'location' is required with the structured form (see bambda_script_doc topic=locations).")
                    val src = args.str("source") ?: return@ToolSpec Results.error("'source' (the Java body) is required with the structured form.")
                    if (fn !in BambdaDoc.FUNCTIONS) return@ToolSpec Results.error("Invalid function '$fn'. One of: ${BambdaDoc.FUNCTIONS}")
                    if (loc !in BambdaDoc.LOCATIONS) return@ToolSpec Results.error("Invalid location '$loc'. One of: ${BambdaDoc.LOCATIONS}")
                    BambdaDoc.assemble(args.strOr("name", "Untitled"), fn, loc, src)
                }
            val outcome = actions.importBambda(document)
            if (outcome.ok) Results.structured(ImportOutcome.serializer(), outcome)
            else Results.structuredError(ImportOutcome.serializer(), outcome)
        }
    }

    // ---- DSL docs ----

    private fun bambdaScriptDoc(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("topic", "A topic key (omit to get the index). See bambda_script_doc with no args for keys.")
            integer("offset", "Char offset for paging a long topic; use nextOffset from a prior call.", default = 0, minimum = 0)
        }
        return ToolSpec("bambda_script_doc", "Bambda docs", "Paginated Bambda DSL reference: format, function/location enums, in-scope variables, helpers, enums, and per-function examples. Call with no args for the topic index.", "Bambda", schema) { args ->
            val topic = args.str("topic")
            if (topic == null) {
                return@ToolSpec Results.structured(BambdaDocResult.serializer(), BambdaDocResult(topics = BambdaDocs.topics.map { it.key }, content = BambdaDocs.index()))
            }
            val t = BambdaDocs.topic(topic)
                ?: return@ToolSpec Results.error("Unknown topic '$topic'. Call bambda_script_doc with no args for the list of keys.")
            val offset = args.intOr("offset", 0).coerceIn(0, t.content.length)
            val end = minOf(offset + docChunk, t.content.length)
            val slice = t.content.substring(offset, end)
            val more = end < t.content.length
            Results.structured(BambdaDocResult.serializer(), BambdaDocResult(topic = topic, content = slice, offset = offset, nextOffset = if (more) end else null, truncated = more))
        }
    }

    // ---- local store ----

    private fun bambdaSave(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("name", "Filename (a .bambda extension is added if missing).", required = true)
            string("content", "The full .bambda document to save.", required = true)
        }
        return ToolSpec("bambda_save", "Save Bambda", "Save a .bambda document to the local sandboxed library (create/overwrite).", "Bambda", schema, mutating = true) { args ->
            val info = BambdaStore.save(args.require("name"), args.require("content"), BambdaStore.baseDir(bambdasDir()))
            Results.structured(BambdaFileInfo.serializer(), info)
        }
    }

    private fun bambdaList(): ToolSpec =
        ToolSpec("bambda_list", "List saved Bambdas", "List .bambda files in the local sandboxed library.", "Bambda", SchemaBuilder.empty()) {
            val base = BambdaStore.baseDir(bambdasDir())
            Results.structured(BambdaListResult.serializer(), BambdaListResult(base.toAbsolutePath().toString(), BambdaStore.list(base)))
        }

    private fun bambdaGet(): ToolSpec {
        val schema = SchemaBuilder.build { string("name", "Filename to read (from bambda_list).", required = true) }
        return ToolSpec("bambda_get", "Get saved Bambda", "Read a .bambda document from the local library.", "Bambda", schema) { args ->
            val name = args.require("name")
            val content = BambdaStore.read(name, BambdaStore.baseDir(bambdasDir()))
            if (content.length > MAX_SCRIPT_CHARS) return@ToolSpec Results.error("Bambda '$name' is ${content.length} chars (> $MAX_SCRIPT_CHARS); too large to return.")
            Results.structured(BambdaFile.serializer(), BambdaFile(name, content))
        }
    }

    private fun bambdaDelete(): ToolSpec {
        val schema = SchemaBuilder.build { string("name", "Filename to delete.", required = true) }
        return ToolSpec("bambda_delete", "Delete saved Bambda", "Delete a .bambda file from the local library.", "Bambda", schema, mutating = true) { args ->
            val name = args.require("name")
            if (BambdaStore.delete(name, BambdaStore.baseDir(bambdasDir()))) Results.text("Deleted '$name'.") else Results.error("No such bambda '$name'.")
        }
    }

    // ---- official repo (read-only, host-pinned) ----

    private fun bambdaRepoList(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("category", "Filter by top-level category, e.g. \"Filter\", \"CustomColumn\", \"CustomAction\", \"CustomScanChecks\", \"MatchAndReplace\". Omit for all.")
            string("search", "Optional regex matched against the file path.")
            integer("limit", "Max rows per page.", default = 50, minimum = 1, maximum = 200)
            string("cursor", Descriptions.CURSOR)
        }
        return ToolSpec("bambda_repo_list", "List repo Bambdas", "Browse .bambda scripts in the official PortSwigger/bambdas repo (read-only). Fetch one with bambda_fetch. Scripts are LGPL-3.0 with per-file @author.", "Bambda", schema) { args ->
            val category = args.str("category"); val search = args.str("search")
            val all = runCatching { repo.listScripts() }.getOrElse { return@ToolSpec Results.error("Could not reach the bambdas repo: ${it.message}") }
                .filter { (category.isNullOrEmpty() || it.category.equals(category, ignoreCase = true)) && Filters.matchSearch(it.path, search) }
            val filterHash = CursorCodec.filterHash(mapOf("category" to category, "search" to search))
            val page = Pager.page(
                all = all, keyOf = { it.path }, ordering = "path",
                cursor = args.str("cursor"), filterHash = filterHash, limit = args.intOr("limit", 50).coerceIn(1, 200),
                maxBytes = maxBytes, toRow = { it }, measure = { Results.json.encodeToString(BambdaRepoEntry.serializer(), it).toByteArray().size },
            )
            Results.structured(PageEnvelope.serializer(BambdaRepoEntry.serializer()), page)
        }
    }

    private fun bambdaFetch(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("path", "Repo-relative path of a .bambda file (from bambda_repo_list), e.g. \"Filter/Proxy/HTTP/DetectSQLErrors.bambda\".", required = true)
        }
        return ToolSpec("bambda_fetch", "Fetch repo Bambda", "Fetch one .bambda script's raw text from the official PortSwigger/bambdas repo (read-only). Then bambda_import it or bambda_save it. Preserve its LGPL-3.0 @author header.", "Bambda", schema) { args ->
            val path = args.require("path")
            val text = runCatching { repo.fetch(path) }.getOrElse { return@ToolSpec Results.error("Fetch failed for '$path': ${it.message}") }
            if (text.length > MAX_SCRIPT_CHARS) return@ToolSpec Results.error("Fetched '$path' is ${text.length} chars (> $MAX_SCRIPT_CHARS); too large to return.")
            Results.structured(BambdaFetchResult.serializer(), BambdaFetchResult(path, BambdaDoc.parseMeta(text), text, "LGPL-3.0; keep the @author header. Import with bambda_import document=<this>."))
        }
    }

    companion object {
        // Bambdas are small; cap returned text so a pathological file can't blow the tool-result budget.
        private const val MAX_SCRIPT_CHARS = 262_144
        private const val DESC_IMPORT =
            "Import a Bambda into Burp. A Bambda is a full document (id/name/function/location + a Java `source` " +
                "block), NOT a bare snippet — passing a snippet fails with \"function/location required\". Easiest: " +
                "pass name+function+location+source and the server assembles a valid document; or pass a full " +
                "`document`. Browse real examples with bambda_repo_list/bambda_fetch; learn the format with " +
                "bambda_script_doc. Returns ok=false + parser errors on a bad script."
    }
}
