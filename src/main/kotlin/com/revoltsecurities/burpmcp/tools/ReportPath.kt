package com.revoltsecurities.burpmcp.tools

import java.nio.file.Path
import java.nio.file.Paths

/**
 * Sandboxes a user-supplied scan-report path. Only the filename component is honoured (directories and
 * traversal are stripped), the extension is forced to match the format, and the result must stay under
 * [baseDir] — so an agent can never write outside the reports directory.
 */
object ReportPath {

    fun resolve(userPath: String, format: String, baseDir: Path): Path {
        val requested = userPath.trim().ifEmpty { "report" }
        val name = Paths.get(requested).fileName?.toString()
            ?: throw IllegalArgumentException("Invalid report path")
        require(name.isNotEmpty() && name != "." && name != "..") { "Invalid report filename" }

        val ext = when (format.lowercase()) {
            "xml" -> ".xml"
            else -> ".html"
        }
        val withExt = if (name.endsWith(ext, ignoreCase = true)) name else name.substringBeforeLast('.', name) + ext

        val base = baseDir.toAbsolutePath().normalize()
        val resolved = base.resolve(withExt).normalize()
        require(resolved.startsWith(base)) { "Report path escapes the reports directory" }
        return resolved
    }

    /** Default reports directory: <user-home>/.revolt-mcp/reports */
    fun defaultBaseDir(): Path = Paths.get(System.getProperty("user.home"), ".revolt-mcp", "reports")
}
