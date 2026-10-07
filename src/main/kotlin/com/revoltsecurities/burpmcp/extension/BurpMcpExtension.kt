package com.revoltsecurities.burpmcp.extension

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi

/**
 * Montoya entry point. Burp discovers this class by its implementation of [BurpExtension] when the JAR
 * is added — no manifest main-class or META-INF/services entry is required.
 */
@Suppress("unused")
class BurpMcpExtension : BurpExtension {
    override fun initialize(api: MontoyaApi) {
        val app = App(api)
        app.initialize()
        api.extension().registerUnloadingHandler { app.shutdown() }
    }
}
