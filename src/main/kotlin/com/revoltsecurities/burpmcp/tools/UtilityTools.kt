package com.revoltsecurities.burpmcp.tools

/** Pure encoding/decoding utility tools (no Montoya, always available). */
object UtilityTools {

    fun build(): List<ToolSpec> = listOf(
        simple("url_encode", "URL-encode a string.") { Codecs.urlEncode(it.require("content")) },
        simple("url_decode", "URL-decode a string.") { Codecs.urlDecode(it.require("content")) },
        simple("base64_encode", "Base64-encode a UTF-8 string.") { Codecs.base64Encode(it.require("content")) },
        simple("base64_decode", "Base64-decode to a UTF-8 string.") { Codecs.base64Decode(it.require("content")) },
        hashTool(),
        jwtTool(),
        decodeAsTool(),
    )

    private fun simple(id: String, description: String, fn: (Args) -> String): ToolSpec {
        val schema = SchemaBuilder.build { string("content", "Input string.", required = true) }
        return ToolSpec(id, id, description, "Utilities", schema) { args -> Results.text(fn(args)) }
    }

    private fun hashTool(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("content", "Input string.", required = true)
            string("algorithm", "Digest algorithm.", enum = listOf("md5", "sha1", "sha256", "sha384", "sha512"), default = "sha256")
        }
        return ToolSpec("hash_compute", "Compute hash", "Compute a hex digest of a string.", "Utilities", schema) { args ->
            Results.text(Codecs.hash(args.strOr("algorithm", "sha256"), args.require("content")))
        }
    }

    private fun jwtTool(): ToolSpec {
        val schema = SchemaBuilder.build { string("token", "JWT (header.payload.signature).", required = true) }
        return ToolSpec("jwt_decode", "Decode JWT", "Decode a JWT's header and payload (no signature verification).", "Utilities", schema) { args ->
            Results.text(Codecs.jwtDecode(args.require("token")))
        }
    }

    private fun decodeAsTool(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("base64", "Base64-encoded bytes to decode.", required = true)
            string("encoding", "Content encoding to reverse.", enum = listOf("gzip", "deflate", "none"), default = "none")
        }
        return ToolSpec("decode_as", "Decode encoded bytes", "Base64-decode then gunzip/inflate to a UTF-8 string.", "Utilities", schema) { args ->
            Results.text(Codecs.decodeAs(args.require("base64"), args.strOr("encoding", "none")))
        }
    }
}
