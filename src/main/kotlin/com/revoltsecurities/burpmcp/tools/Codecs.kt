package com.revoltsecurities.burpmcp.tools

import java.io.ByteArrayInputStream
import java.net.URLDecoder
import java.net.URLEncoder
import java.security.MessageDigest
import java.util.Base64
import java.util.zip.GZIPInputStream
import java.util.zip.Inflater

/** Pure encoding/decoding helpers backing the utility tools. No Montoya, fully unit-testable. */
object Codecs {

    fun urlEncode(s: String): String = URLEncoder.encode(s, Charsets.UTF_8)
    fun urlDecode(s: String): String = URLDecoder.decode(s, Charsets.UTF_8)

    fun base64Encode(s: String): String = Base64.getEncoder().encodeToString(s.toByteArray(Charsets.UTF_8))
    fun base64Decode(s: String): String = String(Base64.getDecoder().decode(s), Charsets.UTF_8)

    fun hash(algorithm: String, content: String): String {
        val algo = when (algorithm.lowercase().replace("-", "")) {
            "md5" -> "MD5"
            "sha1" -> "SHA-1"
            "sha256" -> "SHA-256"
            "sha384" -> "SHA-384"
            "sha512" -> "SHA-512"
            else -> throw IllegalArgumentException("Unsupported hash algorithm '$algorithm' (use md5|sha1|sha256|sha384|sha512)")
        }
        val digest = MessageDigest.getInstance(algo).digest(content.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    /** Decode a JWT's header and payload (no signature verification). */
    fun jwtDecode(token: String): String {
        val parts = token.split(".")
        require(parts.size >= 2) { "Not a JWT (expected at least header.payload)" }
        val dec = Base64.getUrlDecoder()
        fun seg(i: Int) = runCatching { String(dec.decode(pad(parts[i])), Charsets.UTF_8) }.getOrDefault("<undecodable>")
        return buildString {
            appendLine("header: ${seg(0)}")
            appendLine("payload: ${seg(1)}")
            append("signature: ${if (parts.size > 2) parts[2] else "<none>"}")
        }
    }

    /** Decode base64 input under the given [encoding]: gzip | deflate | none. */
    fun decodeAs(base64: String, encoding: String): String {
        val raw = Base64.getDecoder().decode(base64)
        val bytes = when (encoding.lowercase()) {
            "gzip" -> GZIPInputStream(ByteArrayInputStream(raw)).readBytes()
            "deflate" -> inflate(raw)
            "none", "" -> raw
            else -> throw IllegalArgumentException("Unsupported encoding '$encoding' (use gzip|deflate|none)")
        }
        return String(bytes, Charsets.UTF_8)
    }

    private fun inflate(data: ByteArray): ByteArray {
        val inflater = Inflater()
        inflater.setInput(data)
        val out = ByteArray(8_192)
        val sink = java.io.ByteArrayOutputStream()
        try {
            while (!inflater.finished()) {
                val n = inflater.inflate(out)
                if (n == 0 && inflater.needsInput()) break
                sink.write(out, 0, n)
            }
        } finally {
            inflater.end()
        }
        return sink.toByteArray()
    }

    private fun pad(s: String): String = when (s.length % 4) {
        2 -> "$s=="
        3 -> "$s="
        else -> s
    }
}
