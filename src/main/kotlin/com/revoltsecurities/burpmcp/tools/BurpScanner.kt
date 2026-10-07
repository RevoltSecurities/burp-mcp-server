package com.revoltsecurities.burpmcp.tools

import kotlinx.serialization.Serializable

@Serializable
data class ScanStartResult(val taskId: String, val type: String, val note: String)

@Serializable
data class ScanTaskStatus(
    val taskId: String,
    val type: String,
    val requestCount: Int,
    val errorCount: Int,
    val insertionPointCount: Int? = null,
    val issuesFound: Int,
    val statusMessage: String,
)

@Serializable
data class ScanTaskInfo(val taskId: String, val type: String, val target: String)

@Serializable
data class ScanTaskList(val tasks: List<ScanTaskInfo>)

@Serializable
data class ReportResult(val path: String, val issues: Int, val format: String)

/** A raw request to seed an audit with. */
data class RawTarget(val raw: String, val host: String, val port: Int, val secure: Boolean)

/** Burp Scanner operations (Professional). Seam over Montoya; impl holds the live Crawl/Audit tasks. */
interface BurpScanner {
    fun startCrawl(seedUrls: List<String>): ScanStartResult
    fun startAudit(active: Boolean, requests: List<RawTarget>): ScanStartResult
    fun taskStatus(taskId: String): ScanTaskStatus?
    fun listTasks(): List<ScanTaskInfo>
    fun deleteTask(taskId: String): Boolean
    /** @param taskId null/"all" → all site-map issues; otherwise that audit's issues. Returns the written path. */
    fun generateReport(taskId: String?, format: String, userPath: String): ReportResult
}
