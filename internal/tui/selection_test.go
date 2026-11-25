package tui

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

// testClipboards holds what each test model wrote to its fake clipboard.
var testClipboards sync.Map // *Model -> *string

// clipboardOf runs a copy Cmd and returns what reached the native clipboard.
func clipboardOf(t *testing.T, m *Model, cmd tea.Cmd) string {
	t.Helper()
	if cmd == nil {
		t.Fatal("nothing was copied")
	}
	v, _ := testClipboards.Load(m)
	got := v.(*string)
	*got = ""
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, c := range batch {
			if c != nil {
				c()
			}
		}
	}
	return *got
}

// cellOf finds text on screen and returns the cell of its first character.
func cellOf(t *testing.T, m *Model, text string) point {
	t.Helper()
	for y, l := range m.frame() {
		l = ansi.Strip(l)
		if i := strings.Index(l, text); i >= 0 {
			return point{ansi.StringWidth(l[:i]), y}
		}
	}
	t.Fatalf("%q is not on screen", text)
	return point{}
}

func click(m *Model, p point) tea.Cmd {
	_, cmd := m.Update(tea.MouseClickMsg{X: p.x, Y: p.y, Button: tea.MouseLeft})
	return cmd
}

func drag(m *Model, from, to point) tea.Cmd {
	click(m, from)
	m.Update(tea.MouseMotionMsg{X: to.x, Y: to.y, Button: tea.MouseLeft})
	_, cmd := m.Update(tea.MouseReleaseMsg{X: to.x, Y: to.y, Button: tea.MouseLeft})
	return cmd
}

func TestDragCopiesOnRelease(t *testing.T) {
	m := newTestModel(t)
	loadHistory(m, cert("1", "CN=R3", now.AddDate(0, 1, 0), "a.example.com", "b.example.com"))

	start := cellOf(t, m, "a.example.com")
	end := point{start.x + len("a.example.com") - 1, start.y}
	if got := clipboardOf(t, m, drag(m, start, end)); got != "a.example.com" {
		t.Errorf("copied %q, want a.example.com", got)
	}
	if !m.sel.active {
		t.Error("the selection should stay highlighted after the copy")
	}
	if !strings.Contains(ansi.Strip(m.render()), "copied 13 characters") {
		t.Error("the status line doesn't confirm the copy")
	}

	// Dragging backwards selects the same text.
	if got := clipboardOf(t, m, drag(m, end, start)); got != "a.example.com" {
		t.Errorf("backwards drag copied %q", got)
	}
}

func TestSelectionLeavesBordersOut(t *testing.T) {
	m := newTestModel(t)
	loadHistory(m,
		cert("1", "CN=R3", now.AddDate(0, 1, 0), "a.example.com"),
		cert("2", "CN=R3", now.AddDate(0, 2, 0), "b.example.com"))

	// From the screen's top-left corner to the right edge of the last table row:
	// header, the box's top border, the table header and its rule, and both rows.
	last := cellOf(t, m, "a.example.com") // history is newest first, so a is the bottom row
	got := clipboardOf(t, m, drag(m, point{0, 0}, point{m.width - 1, last.y}))
	if strings.ContainsAny(got, "│╭╮╰╯") {
		t.Errorf("box borders were copied:\n%s", got)
	}
	for _, l := range strings.Split(got, "\n") {
		if l == "" || l != strings.TrimSpace(l) {
			t.Errorf("line %q should be trimmed and non-empty", l)
		}
	}
	for _, want := range []string{"ctq", "NAMES", "a.example.com", "b.example.com"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q is missing from the copied text:\n%s", want, got)
		}
	}
}

func TestClickAloneCopiesNothing(t *testing.T) {
	m := newTestModel(t)
	loadHistory(m, cert("1", "CN=R3", now.AddDate(0, 1, 0), "a.example.com"))
	p := cellOf(t, m, "a.example.com")
	click(m, p)
	if _, cmd := m.Update(tea.MouseReleaseMsg{X: p.x, Y: p.y, Button: tea.MouseLeft}); cmd != nil {
		t.Error("a click without a drag copied something")
	}
	if m.sel.active {
		t.Error("a click without a drag left a selection")
	}
}

func TestDoubleAndTripleClick(t *testing.T) {
	m := newTestModel(t)
	loadHistory(m, cert("1", "CN=R3", now.AddDate(0, 1, 0), "a.example.com", "b.example.com"))
	m.Update(key("enter")) // details: "names     (2) a.example.com, b.example.com"

	p := cellOf(t, m, "a.example.com, b.example.com")
	p.x += 3 // somewhere inside the first name
	click(m, p)
	if got := clipboardOf(t, m, click(m, p)); got != "a.example.com" {
		t.Errorf("double click copied %q, want the name without the comma", got)
	}
	if got := clipboardOf(t, m, click(m, p)); got != "names     (2) a.example.com, b.example.com" {
		t.Errorf("triple click copied %q, want the line", got)
	}

	// A click somewhere else starts over.
	q := cellOf(t, m, "CN=R3")
	if cmd := click(m, q); cmd != nil || m.clicks != 1 {
		t.Errorf("a click on another cell counted as click %d", m.clicks)
	}

	// Blank cells and borders hold no word.
	m.Update(tea.MouseReleaseMsg{X: q.x, Y: q.y})
	edge := point{1, p.y} // the box's left border
	click(m, edge)
	if cmd := click(m, edge); cmd != nil {
		t.Error("double click on a border copied something")
	}
}

func TestHighlightKeepsText(t *testing.T) {
	m := newTestModel(t)
	loadHistory(m,
		cert("1", "CN=R3", now.AddDate(0, 1, 0), "a.example.com"),
		cert("2", "CN=R3", now.AddDate(0, 0, 3), "b.example.com")) // "expiring" is a styled cell
	plain := ansi.Strip(m.render())

	click(m, point{3, 1})
	m.Update(tea.MouseMotionMsg{X: 40, Y: m.height - 1, Button: tea.MouseLeft})
	if !m.sel.active {
		t.Fatal("the drag selected nothing")
	}
	drawn := m.render()
	if drawn == strings.Join(m.frame(), "\n") {
		t.Error("the selection isn't drawn")
	}
	if ansi.Strip(drawn) != plain {
		t.Error("drawing the selection changed the text on screen")
	}
}

func TestKeysAndSelection(t *testing.T) {
	m := newTestModel(t)
	loadHistory(m, cert("1", "CN=R3", now.AddDate(0, 1, 0), "a.example.com"))
	start := cellOf(t, m, "a.example.com")
	end := point{start.x + 4, start.y}

	// ctrl+c copies the selection instead of quitting.
	drag(m, start, end)
	_, cmd := m.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	if got := clipboardOf(t, m, cmd); got != "a.exa" {
		t.Errorf("ctrl+c copied %q, want a.exa", got)
	}
	if m.sel.active {
		t.Error("ctrl+c should clear the selection")
	}
	// Without one it quits, as before.
	_, cmd = m.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("ctrl+c without a selection should quit")
	}

	// esc only clears the selection: the details pane stays open.
	m.Update(key("enter"))
	drag(m, start, end)
	m.Update(key("esc"))
	if m.sel.active || !m.detail {
		t.Errorf("after esc: selection %v, details %v; want false, true", m.sel.active, m.detail)
	}

	// Any other key clears it and still does its job.
	drag(m, start, end)
	m.Update(key("3"))
	if m.sel.active || m.tab != tabNames {
		t.Errorf("after 3: selection %v, tab %v", m.sel.active, m.tab)
	}
}

func TestCopyRow(t *testing.T) {
	m := newTestModel(t)
	var names []string
	for i := range 40 { // far more than the NAMES column shows
		names = append(names, fmt.Sprintf("host%02d.example.com", i))
	}
	loadHistory(m, cert("1", "CN=R3", now.AddDate(0, 1, 0), names...))

	_, cmd := m.Update(key("y"))
	if got := clipboardOf(t, m, cmd); got != strings.Join(names, "\n") {
		t.Errorf("y copied %d bytes, want every name on its own line", len(got))
	}

	m.Update(key("3"))
	_, cmd = m.Update(key("y"))
	if got := clipboardOf(t, m, cmd); got != selectedName(m) {
		t.Errorf("y on Names copied %q, want %q", got, selectedName(m))
	}

	// Nothing selected, nothing copied.
	m.Update(key("2"))
	if _, cmd := m.Update(key("y")); cmd != nil {
		t.Error("y on an empty tab copied something")
	}
}

func TestWheelScrolls(t *testing.T) {
	m := newTestModel(t)
	var certs = make([]string, 10)
	for i := range certs {
		certs[i] = fmt.Sprintf("host%d.example.com", i)
	}
	loadHistory(m, cert("1", "CN=R3", now.AddDate(0, 1, 0), certs...))
	m.Update(key("3"))

	m.Update(tea.MouseWheelMsg{Button: tea.MouseWheelDown})
	if got := m.table.Cursor(); got != wheelStride {
		t.Errorf("cursor at %d after one notch down, want %d", got, wheelStride)
	}
	m.Update(tea.MouseWheelMsg{Button: tea.MouseWheelUp})
	m.Update(tea.MouseWheelMsg{Button: tea.MouseWheelUp})
	if got := m.table.Cursor(); got != 0 {
		t.Errorf("cursor at %d after scrolling past the top, want 0", got)
	}

	// An empty table has nothing to scroll.
	m.Update(key("2"))
	m.Update(tea.MouseWheelMsg{Button: tea.MouseWheelDown})
}

func TestPaste(t *testing.T) {
	t.Run("into the domain prompt", func(t *testing.T) {
		m := newTestModel(t)
		m.Update(key("d"))
		m.Update(tea.PasteMsg{Content: "  Other.Example\n"})
		if got := m.domainInput.Value(); got != "Other.Example" {
			t.Fatalf("prompt holds %q", got)
		}
		_, cmd := m.Update(key("enter"))
		runSearchCmd(t, m, cmd)
		if m.domain != "other.example" {
			t.Errorf("domain is %q, want other.example", m.domain)
		}
	})

	t.Run("with nothing focused opens the prompt", func(t *testing.T) {
		m := newTestModel(t)
		m.Update(tea.PasteMsg{Content: "other.example"})
		if !m.editingDomain || m.domainInput.Value() != "other.example" {
			t.Errorf("editing %v with %q, want the prompt open on the pasted domain", m.editingDomain, m.domainInput.Value())
		}
		if m.domain != "example.com" {
			t.Error("a paste alone must not switch domains")
		}
	})

	t.Run("into the filter", func(t *testing.T) {
		m := newTestModel(t)
		loadHistory(m,
			cert("1", "CN=R3", now.AddDate(0, 1, 0), "a.example.com"),
			cert("2", "CN=R3", now.AddDate(0, 1, 0), "b.example.com"))
		m.Update(key("/"))
		m.Update(tea.PasteMsg{Content: "b.example"})
		if m.filter.Value() != "b.example" || len(m.rows) != 1 {
			t.Errorf("filter %q shows %d rows, want b.example and 1", m.filter.Value(), len(m.rows))
		}
	})

	t.Run("clears a validation error", func(t *testing.T) {
		m := newTestModel(t)
		m.Update(key("d"))
		typeText(m, "nope")
		m.Update(key("enter"))
		if m.domainErr == "" {
			t.Fatal("expected a validation error")
		}
		m.Update(tea.PasteMsg{Content: ".example"})
		if m.domainErr != "" {
			t.Error("the error should clear when the input changes")
		}
	})

	t.Run("blank paste is ignored", func(t *testing.T) {
		m := newTestModel(t)
		m.Update(tea.PasteMsg{Content: " \n"})
		if m.editingDomain {
			t.Error("a blank paste opened the prompt")
		}
	})
}

func TestMouseCapture(t *testing.T) {
	m := newTestModel(t)
	if got := m.View().MouseMode; got != tea.MouseModeCellMotion {
		t.Errorf("mouse mode %v, want cell motion", got)
	}
	m.opts.NoMouse = true
	if got := m.View().MouseMode; got != tea.MouseModeNone {
		t.Errorf("mouse mode %v with NoMouse, want none", got)
	}
}

func TestResizeClearsSelection(t *testing.T) {
	m := newTestModel(t)
	loadHistory(m, cert("1", "CN=R3", now.AddDate(0, 1, 0), "a.example.com"))
	p := cellOf(t, m, "a.example.com")
	drag(m, p, point{p.x + 5, p.y})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	if m.sel.active {
		t.Error("the selection survived a resize")
	}
}
