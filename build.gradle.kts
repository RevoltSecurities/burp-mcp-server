import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.4.20"
    kotlin("plugin.serialization") version "2.4.20"
    id("com.gradleup.shadow") version "8.3.5"
}

group = providers.gradleProperty("group").get()
version = providers.gradleProperty("version").get()

repositories {
    mavenCentral()
}

// ---- Versions ----
val montoyaVersion = "2026.7"
val mcpSdkVersion = "0.15.0"
val ktorVersion = "3.1.3"
val serializationVersion = "1.11.0"
val coroutinesVersion = "1.11.0"
val slf4jVersion = "2.0.16"

dependencies {
    // Burp Montoya API — provided by Burp at runtime
    compileOnly("net.portswigger.burp.extensions:montoya-api:$montoyaVersion")
    testImplementation("net.portswigger.burp.extensions:montoya-api:$montoyaVersion")

    // MCP Kotlin SDK (streamable-HTTP + SSE + stdio)
    implementation("io.modelcontextprotocol:kotlin-sdk:$mcpSdkVersion")

    // Ktor server (embedded) + client (federation)
    implementation("io.ktor:ktor-server-core:$ktorVersion")
    implementation("io.ktor:ktor-server-netty:$ktorVersion")
    implementation("io.ktor:ktor-server-sse:$ktorVersion")
    implementation("io.ktor:ktor-server-auth:$ktorVersion")
    implementation("io.ktor:ktor-server-cors:$ktorVersion")
    implementation("io.ktor:ktor-server-status-pages:$ktorVersion")
    implementation("io.ktor:ktor-server-content-negotiation:$ktorVersion")
    implementation("io.ktor:ktor-serialization-kotlinx-json:$ktorVersion")
    implementation("io.ktor:ktor-client-core:$ktorVersion")
    implementation("io.ktor:ktor-client-cio:$ktorVersion")
    // SSE client plugin (io.ktor.client.plugins.sse.SSE) comes transitively via the MCP Kotlin SDK client.

    // Kotlin runtime libs
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:$serializationVersion")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:$coroutinesVersion")

    // Logging (slf4j backend so the SDK/Ktor logs don't go unbound)
    implementation("org.slf4j:slf4j-simple:$slf4jVersion")

    // Test
    testImplementation(platform("org.junit:junit-bom:5.11.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_21)
        freeCompilerArgs.add("-Xjsr305=strict")
    }
}

tasks.test {
    useJUnitPlatform()
}

// Burp loads a single fat JAR; disable the thin jar and build the shadow jar.
tasks.jar {
    enabled = false
}

tasks.shadowJar {
    archiveClassifier.set("")
    // Critical: Ktor and the MCP SDK ship META-INF/services entries that must survive shading.
    mergeServiceFiles()
    isZip64 = true
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
