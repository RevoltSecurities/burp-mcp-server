package com.revoltsecurities.burpmcp.ui.components

import com.revoltsecurities.burpmcp.ui.design.DesignTokens
import java.awt.Color
import java.awt.Dimension
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.RenderingHints
import javax.swing.JLabel

/** A rounded status pill whose colors are re-read from theme tokens at paint time. */
class StatusBadge(text: String = "") : JLabel(text) {

    private var pill: Color = DesignTokens.textMuted

    init {
        isOpaque = false
        border = javax.swing.BorderFactory.createEmptyBorder(3, 10, 3, 10)
        foreground = Color.WHITE
    }

    fun set(text: String, color: Color) {
        this.text = text
        this.pill = color
        repaint()
    }

    override fun getPreferredSize(): Dimension {
        val d = super.getPreferredSize()
        return Dimension(d.width, d.height)
    }

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g2.color = pill
            g2.fillRoundRect(0, 0, width, height, height, height)
        } finally {
            g2.dispose()
        }
        super.paintComponent(g)
    }
}
