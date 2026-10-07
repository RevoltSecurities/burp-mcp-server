package com.revoltsecurities.burpmcp.ui.components

import com.revoltsecurities.burpmcp.ui.design.DesignTokens
import java.awt.Color
import java.awt.Dimension
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.RenderingHints
import javax.swing.JToggleButton
import javax.swing.Timer

/**
 * A modern animated on/off switch. Extends [JToggleButton], so `isSelected`/`addActionListener` work exactly
 * like a checkbox even if custom painting is unavailable in some environment. Colors come from theme tokens.
 */
class ToggleSwitch : JToggleButton() {

    private var thumb = 0f // 0 = off, 1 = on
    private val timer = Timer(15) { step() }

    init {
        isOpaque = false
        isBorderPainted = false
        isContentAreaFilled = false
        isFocusPainted = false
        preferredSize = Dimension(WIDTH, HEIGHT)
        thumb = if (isSelected) 1f else 0f
        addItemListener { animate() }
    }

    private fun animate() {
        if (!isShowing) { thumb = if (isSelected) 1f else 0f; repaint(); return }
        if (!timer.isRunning) timer.start()
    }

    private fun step() {
        val target = if (isSelected) 1f else 0f
        thumb += (target - thumb) * 0.3f
        if (kotlin.math.abs(target - thumb) < 0.02f) { thumb = target; timer.stop() }
        repaint()
    }

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            val off = DesignTokens.blend(DesignTokens.textMuted, DesignTokens.surface, 0.5f)
            val on = DesignTokens.accent
            g2.color = blend(off, on, thumb)
            g2.fillRoundRect(0, (height - TRACK_H) / 2, TRACK_W, TRACK_H, TRACK_H, TRACK_H)
            val x = (2 + thumb * (TRACK_W - THUMB - 2)).toInt()
            g2.color = Color.WHITE
            g2.fillOval(x, (height - THUMB) / 2, THUMB, THUMB)
        } finally {
            g2.dispose()
        }
    }

    private fun blend(a: Color, b: Color, t: Float): Color {
        val r = (a.red + (b.red - a.red) * t).toInt().coerceIn(0, 255)
        val g = (a.green + (b.green - a.green) * t).toInt().coerceIn(0, 255)
        val bl = (a.blue + (b.blue - a.blue) * t).toInt().coerceIn(0, 255)
        return Color(r, g, bl)
    }

    companion object {
        private const val WIDTH = 46
        private const val HEIGHT = 24
        private const val TRACK_W = 44
        private const val TRACK_H = 20
        private const val THUMB = 16
    }
}
