package com.revoltsecurities.burpmcp.config

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition

/**
 * Edition / version detection. Scanner and Collaborator tools are Professional-only; we detect the
 * edition once at startup so Pro-only tools can be gated and degrade gracefully in Community.
 */
class BurpEnv(api: MontoyaApi) {
    private val version = api.burpSuite().version()

    val edition: BurpSuiteEdition = version.edition()
    val isProfessional: Boolean = edition != BurpSuiteEdition.COMMUNITY_EDITION
    val versionString: String = "${version.name()} ${version.major()}.${version.minor()} (build ${version.build()})"

    fun describe(): String = "$versionString — edition=$edition (professional=$isProfessional)"
}
