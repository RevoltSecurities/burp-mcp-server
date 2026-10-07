package com.revoltsecurities.burpmcp.tools

import kotlinx.serialization.Serializable
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

@Serializable
data class WordlistInfo(val name: String, val lines: Int, val bytes: Long)

@Serializable
data class WordlistsResult(val dir: String, val files: List<WordlistInfo>)

/**
 * Sandboxed wordlist access so agents can reference USER-CONFIGURED payload files by name instead of
 * generating payloads inline — without ever reading arbitrary host files. Only the filename component is
 * honoured (directories/traversal stripped) and the result must stay under the configured base dir.
 */
object Wordlists {

    const val MAX_LINES = 200_000

    fun baseDir(configured: String): Path =
        if (configured.isNotBlank()) Paths.get(configured) else Paths.get(System.getProperty("user.home"), ".revolt-mcp", "wordlists")

    /** Resolve a bare filename under [base]; throws if it escapes the sandbox. */
    fun resolve(name: String, base: Path): Path {
        val fileName = Paths.get(name.trim()).fileName?.toString()
            ?: throw IllegalArgumentException("Invalid wordlist name")
        require(fileName.isNotEmpty() && fileName != "." && fileName != "..") { "Invalid wordlist name" }
        val root = base.toAbsolutePath().normalize()
        val resolved = root.resolve(fileName).normalize()
        require(resolved.startsWith(root)) { "Wordlist path escapes the wordlists directory" }
        return resolved
    }

    /** Read a wordlist's entries: trimmed lines, skipping blanks and '#' comments, capped at [MAX_LINES]. */
    fun read(name: String, base: Path): List<String> {
        val path = resolve(name, base)
        require(Files.isRegularFile(path)) { "Wordlist '$name' not found under ${base.toAbsolutePath()}" }
        return Files.newBufferedReader(path).useLines { seq ->
            seq.map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
                .take(MAX_LINES)
                .toList()
        }
    }

    fun list(base: Path): List<WordlistInfo> {
        val root = base.toAbsolutePath().normalize()
        if (!Files.isDirectory(root)) return emptyList()
        return Files.list(root).use { stream ->
            stream.filter { Files.isRegularFile(it) }
                .map {
                    WordlistInfo(
                        name = it.fileName.toString(),
                        lines = runCatching { Files.newBufferedReader(it).useLines { s -> s.count() } }.getOrDefault(0),
                        bytes = runCatching { Files.size(it) }.getOrDefault(0),
                    )
                }
                .sorted(compareBy { it.name })
                .toList()
        }
    }
}
