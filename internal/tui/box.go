package tui

import (
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"
)

// Layout geometry. Everything that sizes content derives from these, so the
// table, the boxes and the empty states can't drift apart.
const (
	marginX   = 1 // blank columns between the terminal edge and the boxes
	boxBorder = 1 // border cells on each side
	boxPad    = 1 // blank columns inside the border on each side

	chromeRows      = 5                        // top blank, header, blank, status, help
	detailLines     = 6                        // content rows in the details box
	detailBoxHeight = detailLines + 2          // plus top and bottom border
	promptBoxHeight = 3                        // one input row plus borders
	boxInset        = 2 * (boxBorder + boxPad) // width lost to border + padding
)

// boxWidth is the outer width of every box.
func (m *Model) boxWidth() int { return max(m.width-2*marginX, 24) }

// innerWidth is the usable width inside a box.
func (m *Model) innerWidth() int { return m.boxWidth() - boxInset }

// box draws a rounded, padded box with a title in the top border and an optional
// label in the top-right corner:
//
//	╭─ title ───────── right ─╮
//	│ body                    │
//	╰─────────────────────────╯
//
// lipgloss borders can't carry a title, so the top edge is drawn by hand. Widths
// are measured with lipgloss.Width, which skips ANSI codes, so styled titles align.
func box(title, right, body string, width, height int, active bool) string {
	bc := colorDim
	if active {
		bc = colorAccent
	}
	edge := func(s string) string { return lipgloss.NewStyle().Foreground(bc).Render(s) }

	inner := width - 2*boxBorder - 2*boxPad
	if inner < 1 || height < 2 {
		return ""
	}

	// Top border: "╭─" title fill right "─╮". Drop the right label first, then
	// shorten the title, when the box is too narrow for both.
	if right != "" {
		right = " " + right + " "
	}
	fill := width - 4 - lipgloss.Width(title) - lipgloss.Width(right)
	if fill < 1 {
		right = ""
		fill = width - 4 - lipgloss.Width(title)
	}
	if fill < 1 {
		title = truncate(title, width-5)
		fill = width - 4 - lipgloss.Width(title)
	}
	top := edge("╭─") + title + edge(strings.Repeat("─", max(fill, 0))) + right + edge("─╮")

	lines := strings.Split(body, "\n")
	rows := make([]string, 0, height)
	rows = append(rows, top)
	side := edge("│") + strings.Repeat(" ", boxPad)
	for i := range height - 2 {
		line := ""
		if i < len(lines) {
			line = truncate(lines[i], inner)
		}
		pad := strings.Repeat(" ", max(inner-lipgloss.Width(line), 0))
		rows = append(rows, side+line+pad+strings.Repeat(" ", boxPad)+edge("│"))
	}
	rows = append(rows, edge("╰"+strings.Repeat("─", width-2)+"╯"))
	return strings.Join(rows, "\n")
}

// boxTitle renders a plain box title. Tabs build their own.
func boxTitle(s string, c color.Color) string {
	return lipgloss.NewStyle().Foreground(c).Bold(true).Padding(0, 1).Render(s)
}
