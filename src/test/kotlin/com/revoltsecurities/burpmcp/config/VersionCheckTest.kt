package com.revoltsecurities.burpmcp.config

import com.revoltsecurities.burpmcp.integrations.GithubReleaseParse
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VersionCheckTest {

    @Test
    fun `newer is detected across major minor patch, v-prefix tolerant`() {
        assertTrue(VersionCheck.isNewer("1.0.0", "1.1.0"))
        assertTrue(VersionCheck.isNewer("1.1.0", "2.0.0"))
        assertTrue(VersionCheck.isNewer("v1.0.9", "v1.1.0"))
        assertTrue(VersionCheck.isNewer("1.1.0", "1.1.1"))
    }

    @Test
    fun `same or older is not newer`() {
        assertFalse(VersionCheck.isNewer("1.1.0", "1.1.0"))
        assertFalse(VersionCheck.isNewer("1.1.0", "1.0.9"))
        assertFalse(VersionCheck.isNewer("2.0.0", "1.9.9"))
    }

    @Test
    fun `pre-release and build suffixes are ignored`() {
        assertFalse(VersionCheck.isNewer("1.2.0-beta1", "1.2.0")) // same core → not newer
        assertTrue(VersionCheck.isNewer("1.1.0", "1.2.0-rc1+build7"))
    }

    @Test
    fun `unparseable versions never report an update`() {
        assertFalse(VersionCheck.isNewer("nightly", "1.0.0"))
        assertFalse(VersionCheck.isNewer("1.0.0", "latest"))
        assertNull(VersionCheck.parse("abc"))
    }
}

class GithubReleaseParseTest {

    @Test
    fun `parses tag, version, notes and url`() {
        val json = """{"tag_name":"v1.2.0","name":"Revolt MCP Server v1.2.0","body":"- fix A\n- fix B","html_url":"https://github.com/x/y/releases/tag/v1.2.0","prerelease":false}"""
        val r = GithubReleaseParse.parse(json)!!
        assertEquals("v1.2.0", r.tag)
        assertEquals("1.2.0", r.version)
        assertTrue(r.notes.contains("fix A"))
        assertEquals("https://github.com/x/y/releases/tag/v1.2.0", r.url)
    }

    @Test
    fun `returns null on missing tag or garbage`() {
        assertNull(GithubReleaseParse.parse("""{"message":"Not Found"}"""))
        assertNull(GithubReleaseParse.parse("not json"))
    }
}
