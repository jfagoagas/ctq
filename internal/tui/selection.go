package tui

import (
	"strings"
	"time"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// Copy and paste.
//
// The TUI captures the mouse, so the terminal's own selection no longer works
// without a modifier. In exchange the selection here knows the layout: it copies
// on release and leaves the box borders out of the text.

const (
	// boxChars are cut from both ends of every copied line: the margin and the
	// border cells a selection picks up when it crosses a box edge.
	boxChars = " │─╭╮╰╯"
	// wordBreaks end the word a double click selects.
	wordBreaks = boxChars + ",()"

	multiClick  = 400 * time.Millisecond // longest gap between the clicks of a double click
	noticeFor   = 2 * time.Second        // how long "copied" stays in the status line
	wheelStride = 3                      // rows per wheel notch
)

var styleSelection = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("24"))

// point is a screen cell, 0-based.
type point struct{ x, y int }

func (p point) before(q point) bool { return p.y < q.y || (p.y == q.y && p.x < q.x) }

// selection runs from anchor to head like a terminal's: the rest of the first
// line, every line in between, and the last line up to head. Both ends are inclusive.
type selection struct {
	anchor, head point
	active       bool // there is something to highlight and copy
	dragging     bool // the left button is down
}

// span is the selected cell range [from, to) on line y, which is w cells wide.
func (s selection) span(y, w int) (from, to int, ok bool) {
	if !s.active {
		return 0, 0, false
	}
	start, end := s.anchor, s.head
	if end.before(start) {
		start, end = end, start
	}
	if y < start.y || y > end.y {
		return 0, 0, false
	}
	from, to = 0, w
	if y == start.y {
		from = start.x
	}
	if y == end.y {
		to = min(end.x+1, w)
	}
	return from, to, from < to
}

// highlight restyles cells [from, to) of a styled line. The selected cells lose
// their own colors: a cell's SGR reset would punch holes in the selection background.
func highlight(line string, from, to int) string {
	w := ansi.StringWidth(line)
	return ansi.Cut(line, 0, from) + styleSelection.Render(ansi.Strip(ansi.Cut(line, from, to))) + ansi.Cut(line, to, w)
}

// selectedText is the selection as plain text, without box borders or the lines
// that held nothing else.
func (m *Model) selectedText() string {
	var out []string
	for y, l := range m.frame() {
		l = ansi.Strip(l)
		from, to, ok := m.sel.span(y, ansi.StringWidth(l))
		if !ok {
			continue
		}
		if t := strings.Trim(ansi.Cut(l, from, to), boxChars); t != "" {
			out = append(out, t)
		}
	}
	return strings.Join(out, "\n")
}

// selectWord selects the word under p. It reports whether there is one.
func (m *Model) selectWord(p point) bool {
	lines := m.frame()
	if p.y >= len(lines) {
		return false
	}
	l := ansi.Strip(lines[p.y])
	w := ansi.StringWidth(l)
	// An empty cut is the second half of a wide character.
	sep := func(x int) bool {
		c := ansi.Cut(l, x, x+1)
		return c == "" || strings.ContainsAny(c, wordBreaks)
	}
	if p.x >= w || sep(p.x) {
		return false
	}
	from, to := p.x, p.x
	for from > 0 && !sep(from-1) {
		from--
	}
	for to < w-1 && !sep(to+1) {
		to++
	}
	m.sel = selection{anchor: point{from, p.y}, head: point{to, p.y}, active: true}
	return true
}

// selectLine selects line y between its borders. It reports whether the line has text.
func (m *Model) selectLine(y int) bool {
	lines := m.frame()
	if y >= len(lines) {
		return false
	}
	l := ansi.Strip(lines[y])
	from := ansi.StringWidth(l) - ansi.StringWidth(strings.TrimLeft(l, boxChars))
	to := ansi.StringWidth(strings.TrimRight(l, boxChars)) - 1
	if from > to {
		return false
	}
	m.sel = selection{anchor: point{from, y}, head: point{to, y}, active: true}
	return true
}

func (m *Model) handleClick(msg tea.MouseClickMsg) tea.Cmd {
	if msg.Button != tea.MouseLeft {
		return nil
	}
	p := point{max(msg.X, 0), max(msg.Y, 0)}
	now := m.now()
	if p == m.lastClick && now.Sub(m.lastClickAt) <= multiClick {
		m.clicks++
	} else {
		m.clicks = 1
	}
	m.lastClick, m.lastClickAt = p, now

	// A plain click starts a drag, and clears the old selection if it goes nowhere.
	m.sel = selection{anchor: p, head: p, dragging: m.clicks == 1}
	switch {
	case m.clicks == 1:
		return nil
	case m.clicks == 2 && !m.selectWord(p), m.clicks > 2 && !m.selectLine(p.y):
		return nil
	}
	return m.copyText(m.selectedText())
}

func (m *Model) handleMotion(msg tea.MouseMotionMsg) {
	if !m.sel.dragging {
		return
	}
	m.sel.head = point{max(msg.X, 0), max(msg.Y, 0)}
	m.sel.active = m.sel.head != m.sel.anchor
}

// handleRelease copies what the drag selected. The highlight stays until the
// next key or click, so it's clear what went to the clipboard.
func (m *Model) handleRelease() tea.Cmd {
	if !m.sel.dragging {
		return nil
	}
	m.sel.dragging = false
	if !m.sel.active {
		return nil
	}
	return m.copyText(m.selectedText())
}

// handleWheel scrolls the table. With the mouse captured, the terminal no longer
// turns the wheel into arrow keys.
func (m *Model) handleWheel(msg tea.MouseWheelMsg) {
	if len(m.rows) == 0 {
		return
	}
	switch msg.Button {
	case tea.MouseWheelUp:
		m.table.MoveUp(wheelStride)
	case tea.MouseWheelDown:
		m.table.MoveDown(wheelStride)
	default:
		return
	}
	m.sel = selection{} // the rows under it moved
	m.applyRows()
}

// copyText sends s to the clipboard two ways. OSC 52 goes through the terminal, so
// it works over SSH, but not every terminal accepts it (Terminal.app doesn't). The
// native clipboard covers those, and fails where there is none (a remote host, a
// Linux box without xclip or wl-copy), which is the case OSC 52 handles.
func (m *Model) copyText(s string) tea.Cmd {
	if s == "" {
		return nil
	}
	m.notice, m.noticeAt = "copied "+plural(utf8.RuneCountInString(s), "character"), m.now()
	write := m.clipboard
	return tea.Batch(tea.SetClipboard(s), func() tea.Msg {
		_ = write(s)
		return nil
	})
}

// rowText is what y copies: the selected row's value in full. The table shortens
// long cells, so a mouse selection there can't get all of it.
func (m *Model) rowText() string {
	cur := m.table.Cursor()
	if cur < 0 || cur >= len(m.visible) {
		return ""
	}
	idx := m.visible[cur]
	switch m.tab {
	case tabHistory:
		return strings.Join(m.history[idx].DNSNames, "\n")
	case tabLive:
		return strings.Join(m.liveAt(idx).DNSNames, "\n")
	case tabNames:
		return m.nameList[idx]
	case tabLogs:
		if idx < len(m.snap.logs) {
			return m.snap.logs[idx].log.URL
		}
	case tabSources:
		if idx < len(m.snap.events) {
			return m.snap.events[idx].msg
		}
	}
	return ""
}

// handlePaste puts pasted text in the focused input. With none focused it opens
// the domain prompt: a pasted domain is the likely intent, and enter still confirms it.
func (m *Model) handlePaste(msg tea.PasteMsg) tea.Cmd {
	msg.Content = strings.TrimSpace(msg.Content)
	if msg.Content == "" {
		return nil
	}
	var focus tea.Cmd
	if !m.editingDomain && !m.filtering {
		focus = m.openDomainPrompt()
	}
	return tea.Batch(focus, m.updateInput(msg))
}

// updateInput forwards a message to the focused input. Besides pastes, that is
// the input's own messages: the cursor blink and the result of ctrl+v.
func (m *Model) updateInput(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	switch {
	case m.editingDomain:
		before := m.domainInput.Value()
		m.domainInput, cmd = m.domainInput.Update(msg)
		if m.domainInput.Value() != before {
			m.domainErr = ""
		}
	case m.filtering:
		before := m.filter.Value()
		m.filter, cmd = m.filter.Update(msg)
		if m.filter.Value() != before {
			m.refresh()
		}
	}
	return cmd
}
