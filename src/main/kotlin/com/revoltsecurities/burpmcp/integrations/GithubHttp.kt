package com.revoltsecurities.burpmcp.integrations

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.HttpTimeout

/**
 * One place that builds the GitHub-facing HTTP client, so both [GithubReleases] and [GithubBambdaRepo] share the
 * same hardening and can't drift: redirects OFF (host stays pinned) and explicit connect/request/socket timeouts
 * so a half-open socket can never hang a background thread (or freeze the dashboard update check) indefinitely.
 */
object GithubHttp {
    fun newClient(): HttpClient = HttpClient(CIO) {
        followRedirects = false
        install(HttpTimeout) {
            connectTimeoutMillis = 5_000
            requestTimeoutMillis = 10_000
            socketTimeoutMillis = 10_000
        }
    }
}
