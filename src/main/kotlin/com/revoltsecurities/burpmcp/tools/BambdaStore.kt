package com.revoltsecurities.burpmcp.tools

import kotlinx.serialization.Serializable
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

@Serializable
data class BambdaFileInfo(val name: String, val bytes: Long)

@Serializable
data class BambdaListResult(val dir: String, val files: List<BambdaFileInfo>)

@Serializable
data class BambdaFile(val name: String, val content: String)

/**
 * Sandboxed store for `.bambda` script files, so an agent can save/list/read/delete reusable Bambdas without
 * touching arbitrary host files. Only the filename component is honoured (directories/traversal stripped), a
 * `.bambda` extension is enforced, and the result must stay under the configured base dir. Mirrors [Wordlists].
 */
object BambdaStore {

    const val EXT = ".bambda"
    const val MAX_BYTES = 1_000_000

    fun baseDir(configured: String): Path =
        if (configured.isNotBlank()) Paths.get(configured) else Paths.get(System.getProperty("user.home"), ".revolt-mcp", "bambdas")

    /** Resolve a bare filename under [base], forcing a `.bambda` extension; throws if it escapes the sandbox. */
    fun resolve(name: String, base: Path): Path {
        var fileName = Paths.get(name.trim()).fileName?.toString()
            ?: throw IllegalArgumentException("Invalid bambda name")
        require(fileName.isNotEmpty() && fileName != "." && fileName != "..") { "Invalid bambda name" }
        if (!fileName.endsWith(EXT)) fileName += EXT
        val root = base.toAbsolutePath().normalize()
        val resolved = root.resolve(fileName).normalize()
        require(resolved.startsWith(root)) { "Bambda path escapes the bambdas directory" }
        // Defense-in-depth: reject a pre-planted symlink entry that resolves (reads/writes/deletes) outside
        // the sandbox even though its string path is contained.
        val realRoot = runCatching { root.toRealPath() }.getOrNull()
        val realResolved = runCatching { resolved.toRealPath() }.getOrNull()
        if (realRoot != null && realResolved != null) {
            require(realResolved.startsWith(realRoot)) { "Bambda path escapes the bambdas directory (symlink)" }
        }
        return resolved
    }

    fun save(name: String, content: String, base: Path): BambdaFileInfo {
        require(content.toByteArray(Charsets.UTF_8).size <= MAX_BYTES) { "Bambda exceeds ${MAX_BYTES} bytes" }
        val root = base.toAbsolutePath().normalize()
        Files.createDirectories(root)
        val path = resolve(name, base)
        Files.writeString(path, content)
        return BambdaFileInfo(path.fileName.toString(), runCatching { Files.size(path) }.getOrDefault(0))
    }

    fun read(name: String, base: Path): String {
        val path = resolve(name, base)
        require(Files.isRegularFile(path)) { "Bambda '$name' not found in the bambdas directory (see bambda_list)" }
        return Files.readString(path)
    }

    fun delete(name: String, base: Path): Boolean {
        val path = resolve(name, base)
        return runCatching { Files.deleteIfExists(path) }.getOrDefault(false)
    }

    fun list(base: Path): List<BambdaFileInfo> {
        val root = base.toAbsolutePath().normalize()
        if (!Files.isDirectory(root)) return emptyList()
        return Files.list(root).use { stream ->
            stream.filter { Files.isRegularFile(it) && !Files.isSymbolicLink(it) && it.fileName.toString().endsWith(EXT) }
                .map { BambdaFileInfo(it.fileName.toString(), runCatching { Files.size(it) }.getOrDefault(0)) }
                .sorted(compareBy { it.name })
                .toList()
        }
    }
}
