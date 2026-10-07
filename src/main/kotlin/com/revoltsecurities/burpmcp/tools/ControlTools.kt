package com.revoltsecurities.burpmcp.tools

import kotlinx.serialization.Serializable

@Serializable
data class TaskEngineResult(val state: String)

@Serializable
data class PersistedValue(val key: String, val value: String? = null)

@Serializable
data class PersistenceKeys(val keys: List<String>)

/**
 * Burp control-plane tools: project/user options export-import, task-engine state, and the extension's own
 * persisted key/value store. Options export is marked mutating because the JSON can contain credentials
 * (upstream proxy, platform auth) — so it's behind the unsafe switch.
 */
class ControlTools(private val actions: BurpActions) {

    fun build(): List<ToolSpec> = listOf(
        projectInfo(), projectOptionsGet(), projectOptionsSet(), userOptionsGet(), userOptionsSet(),
        taskEngineState(), persistenceGet(), persistenceSet(), persistenceKeys(),
    )

    private fun projectInfo(): ToolSpec =
        ToolSpec("project_info", "Project info", "Return the current Burp project's name and id.", "Config", SchemaBuilder.empty()) {
            Results.structured(ProjectInfo.serializer(), actions.projectInfo())
        }

    private fun projectOptionsGet(): ToolSpec =
        ToolSpec("project_options_get", "Get project options", "Export Burp PROJECT options as JSON. Sensitive: may contain credentials.", "Config", SchemaBuilder.empty(), mutating = true) {
            Results.text(actions.exportProjectOptions())
        }

    private fun projectOptionsSet(): ToolSpec {
        val schema = SchemaBuilder.build { string("json", "Project-options JSON (partial allowed) to import.", required = true) }
        return ToolSpec("project_options_set", "Set project options", "Import Burp PROJECT options from JSON.", "Config", schema, mutating = true) { args ->
            actions.importProjectOptions(args.require("json")); Results.text("Project options imported.")
        }
    }

    private fun userOptionsGet(): ToolSpec =
        ToolSpec("user_options_get", "Get user options", "Export Burp USER options as JSON. Sensitive: may contain credentials.", "Config", SchemaBuilder.empty(), mutating = true) {
            Results.text(actions.exportUserOptions())
        }

    private fun userOptionsSet(): ToolSpec {
        val schema = SchemaBuilder.build { string("json", "User-options JSON (partial allowed) to import.", required = true) }
        return ToolSpec("user_options_set", "Set user options", "Import Burp USER options from JSON.", "Config", schema, mutating = true) { args ->
            actions.importUserOptions(args.require("json")); Results.text("User options imported.")
        }
    }

    private fun taskEngineState(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("state", "Set the global task engine state; omit to just read it.", enum = listOf("running", "paused"))
        }
        return ToolSpec("task_engine_state", "Task engine state", "Get or set Burp's global task execution engine state (running/paused).", "Config", schema, mutating = true) { args ->
            val state = args.str("state")
            val current = if (state != null) actions.taskEngineSet(state) else actions.taskEngineGet()
            Results.structured(TaskEngineResult.serializer(), TaskEngineResult(current))
        }
    }

    private fun persistenceGet(): ToolSpec {
        val schema = SchemaBuilder.build { string("key", "Key to read from the extension's persisted store.", required = true) }
        return ToolSpec("persistence_get", "Get persisted value", "Read a string from the extension's project-persisted store.", "Config", schema) { args ->
            val key = args.require("key")
            Results.structured(PersistedValue.serializer(), PersistedValue(key, actions.persistenceGet(key)))
        }
    }

    private fun persistenceSet(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("key", "Key to write.", required = true)
            string("value", "String value to store.", required = true)
        }
        return ToolSpec("persistence_set", "Set persisted value", "Write a string to the extension's project-persisted store.", "Config", schema, mutating = true) { args ->
            actions.persistenceSet(args.require("key"), args.require("value")); Results.text("Stored '${args.require("key")}'.")
        }
    }

    private fun persistenceKeys(): ToolSpec =
        ToolSpec("persistence_keys", "List persisted keys", "List keys in the extension's project-persisted store.", "Config", SchemaBuilder.empty()) {
            Results.structured(PersistenceKeys.serializer(), PersistenceKeys(actions.persistenceKeys()))
        }
}
