package com.revoltsecurities.burpmcp.ui.design

import java.awt.Color
import java.awt.Font
import javax.swing.UIManager

/**
 * Theme tokens resolved from Burp's active FlatLaf at paint time (never cached), so the UI auto-themes in
 * light and dark and reacts to a live theme switch. Every token has a literal fallback for headless tests.
 */
object DesignTokens {

    val surface: Color get() = color("Panel.background", Color(0x2B2B2B))
    val card: Color get() = if (isDark()) lighten(surface, 0.06f) else darken(surface, 0.03f)
    val text: Color get() = color("Label.foreground", Color(0xDDDDDD))
    val textMuted: Color get() = blend(text, surface, 0.45f)
    val border: Color get() = UIManager.getColor("Component.borderColor") ?: UIManager.getColor("Separator.foreground") ?: Color(0x555555)

    val accent: Color get() = color("Burp.primaryButtonBackground", Color(0xE8, 0x74, 0x3B))
    val onAccent: Color get() = color("Burp.primaryButtonForeground", Color.WHITE)
    val success: Color get() = color("Burp.successColor", Color(0x4C, 0xAF, 0x50))
    val warning: Color get() = color("Burp.warningColor", Color(0xFB, 0x8C, 0x00))
    val error: Color get() = color("Burp.errorColor", Color(0xE5, 0x39, 0x35))

    val baseFont: Font get() = UIManager.getFont("Label.font") ?: Font(Font.SANS_SERIF, Font.PLAIN, 12)
    fun heading(sizeDelta: Float = 6f): Font = baseFont.deriveFont(Font.BOLD, baseFont.size2D + sizeDelta)

    // spacing (4px grid)
    const val S1 = 4
    const val S2 = 8
    const val S3 = 12
    const val S4 = 16
    const val RADIUS = 10

    fun isDark(): Boolean = luminance(surface) < 0.5

    private fun color(key: String, fallback: Color): Color = UIManager.getColor(key) ?: fallback

    private fun luminance(c: Color): Double = (0.299 * c.red + 0.587 * c.green + 0.114 * c.blue) / 255.0

    private fun lighten(c: Color, amount: Float): Color = blend(Color.WHITE, c, amount)
    private fun darken(c: Color, amount: Float): Color = blend(Color.BLACK, c, amount)

    fun blend(a: Color, b: Color, ratioOfA: Float): Color {
        val r = (a.red * ratioOfA + b.red * (1 - ratioOfA)).toInt().coerceIn(0, 255)
        val g = (a.green * ratioOfA + b.green * (1 - ratioOfA)).toInt().coerceIn(0, 255)
        val bl = (a.blue * ratioOfA + b.blue * (1 - ratioOfA)).toInt().coerceIn(0, 255)
        return Color(r, g, bl)
    }
}
