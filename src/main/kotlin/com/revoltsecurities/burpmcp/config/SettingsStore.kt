package com.revoltsecurities.burpmcp.config

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.Preferences
import kotlinx.serialization.json.Json

/**
 * Loads/saves [McpSettings] to Burp Preferences as a single JSON blob.
 * The bearer token is encrypted at rest via [SecretCipher]; everything else is stored in the clear.
 */
class SettingsStore private constructor(
    private val prefs: Preferences,
    private val cipher: SecretCipher,
    private val log: (String) -> Unit,
) {
    @Volatile
    var current: McpSettings = McpSettings()
        private set

    fun load(): McpSettings {
        val raw = prefs.getString(Defaults.PREF_SETTINGS)
        current = if (raw.isNullOrBlank()) {
            McpSettings()
        } else {
            runCatching {
                val stored = json.decodeFromString(McpSettings.serializer(), raw)
                // token fields in storage are ciphertext → decrypt back to plaintext in memory
                stored.copy(
                    token = cipher.decrypt(stored.token),
                    externalMcpServers = stored.externalMcpServers.map {
                        it.copy(token = runCatching { cipher.decrypt(it.token) }.getOrDefault(it.token))
                    },
                    sessionProfile = stored.sessionProfile.copy(
                        cookies = stored.sessionProfile.cookies.mapValues { runCatching { cipher.decrypt(it.value) }.getOrDefault(it.value) },
                        headers = stored.sessionProfile.headers.mapValues { runCatching { cipher.decrypt(it.value) }.getOrDefault(it.value) },
                    ),
                ).sanitized()
            }.getOrElse {
                log("Failed to parse stored settings, using defaults: ${it.message}")
                McpSettings()
            }
        }
        return current
    }

    fun save(settings: McpSettings): McpSettings {
        val clean = settings.sanitized()
        current = clean
        val toStore = clean.copy(
            token = cipher.encrypt(clean.token),
            externalMcpServers = clean.externalMcpServers.map { it.copy(token = cipher.encrypt(it.token)) },
            sessionProfile = clean.sessionProfile.copy(
                cookies = clean.sessionProfile.cookies.mapValues { cipher.encrypt(it.value) },
                headers = clean.sessionProfile.headers.mapValues { cipher.encrypt(it.value) },
            ),
        )
        prefs.setString(Defaults.PREF_SETTINGS, json.encodeToString(McpSettings.serializer(), toStore))
        return clean
    }

    companion object {
        private val json = Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }

        fun create(api: MontoyaApi): SettingsStore {
            val prefs = api.persistence().preferences()
            val cipher = SecretCipher.loadOrCreate(
                provided = prefs.getString(Defaults.PREF_MASTER_KEY),
                persist = { prefs.setString(Defaults.PREF_MASTER_KEY, it) },
            )
            return SettingsStore(prefs, cipher) { api.logging().logToError(it) }.also { it.load() }
        }
    }
}
