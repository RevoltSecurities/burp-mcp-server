package com.revoltsecurities.burpmcp.tools

import kotlinx.serialization.Serializable

@Serializable
private data class DiffResult(val diff: String)

@Serializable
private data class ReflectedResult(val reflected: List<ReflectedParam>)

@Serializable
private data class ParamsResult(val params: List<ReflectedParam>)

/** Pure HTTP analysis tools (no Montoya). Operate on request/response text supplied by the caller. */
object AnalysisTools {

    fun build(): List<ToolSpec> = listOf(
        requestParse(),
        responseParse(),
        paramsExtract(),
        findReflected(),
        diffRequests(),
    )

    private fun requestParse(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("content", Descriptions.RAW_REQUEST, required = true)
            boolean("includeBody", "Include the decoded body in the output (default false = metadata only).", default = false)
        }
        return ToolSpec("request_parse", "Parse request", "Parse a raw HTTP request into method/target/headers/body metadata.", "Requests", schema) { args ->
            Results.structured(ParsedRequest.serializer(), HttpParse.parseRequest(args.require("content"), args.boolOr("includeBody", false)))
        }
    }

    private fun responseParse(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("content", Descriptions.RAW_RESPONSE, required = true)
            boolean("includeBody", "Include the decoded body in the output (default false = metadata only).", default = false)
        }
        return ToolSpec("response_parse", "Parse response", "Parse a raw HTTP response into status/headers/body metadata.", "Requests", schema) { args ->
            Results.structured(ParsedResponse.serializer(), HttpParse.parseResponse(args.require("content"), args.boolOr("includeBody", false)))
        }
    }

    private fun paramsExtract(): ToolSpec {
        val schema = SchemaBuilder.build { string("content", Descriptions.RAW_REQUEST, required = true) }
        return ToolSpec("params_extract", "Extract parameters", "Extract query and form parameters from a raw HTTP request.", "Requests", schema) { args ->
            Results.structured(ParamsResult.serializer(), ParamsResult(HttpParse.extractParams(args.require("content"))))
        }
    }

    private fun findReflected(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("request", Descriptions.RAW_REQUEST, required = true)
            string("response", Descriptions.RAW_RESPONSE, required = true)
        }
        return ToolSpec("find_reflected", "Find reflected params", "Count how often each request parameter value appears in the response body.", "Requests", schema) { args ->
            Results.structured(ReflectedResult.serializer(), ReflectedResult(HttpParse.findReflected(args.require("request"), args.require("response"))))
        }
    }

    private fun diffRequests(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("a", "First message/text to compare.", required = true)
            string("b", "Second message/text to compare.", required = true)
        }
        return ToolSpec("diff_requests", "Diff two messages", "Line-oriented added/removed diff between two HTTP messages.", "Requests", schema) { args ->
            Results.structured(DiffResult.serializer(), DiffResult(HttpParse.diff(args.require("a"), args.require("b"))))
        }
    }
}
