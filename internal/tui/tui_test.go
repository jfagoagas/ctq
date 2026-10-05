package tui

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"charm.land/bubbles/v2/table"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jfagoagas/ctq/internal/ct"
)

var now = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func cert(id, issuer string, notAfter time.Time, names ...string) ct.Certificate {
	return ct.Certificate{
		ID: id, Source: "crtsh", Issuer: issuer, DNSNames: names,
		NotBefore: notAfter.AddDate(0, -3, 0), NotAfter: notAfter,
	}
}

func newTestModel(t *testing.T) *Model {
	return newTestModelFor(t, "example.com")
}

func newTestModelFor(t *testing.T, domain string) *Model {
	t.Helper()
	m := New(context.Background(), Options{
		Domain: domain, Subdomains: true,
		Backend: Backend{
			Search: func(_ context.Context, domain, _ string, _ io.Writer) ([]ct.Certificate, error) {
				// Echo the domain back so tests can see which one was searched.
				return []ct.Certificate{cert("echo", "CN=x", now, domain)}, nil
			},
			Watch: func(ctx context.Context, _ string, _ WatchHooks) error { <-ctx.Done(); return ctx.Err() },
		},
	})
	m.now = func() time.Time { return now }
	m.Update(tea.WindowSizeMsg{Width: 140, Height: 30})
	return m
}

func typeText(m *Model, s string) {
	for _, r := range s {
		m.Update(key(string(r)))
	}
}

// runSearchCmd executes the search Cmd produced by a domain switch and feeds the result back.
func runSearchCmd(t *testing.T, m *Model, cmd tea.Cmd) {
	t.Helper()
	if cmd == nil {
		t.Fatal("no command returned")
	}
	msgs := []tea.Msg{cmd()}
	if batch, ok := msgs[0].(tea.BatchMsg); ok {
		msgs = msgs[:0]
		for _, c := range batch {
			if c != nil {
				msgs = append(msgs, c())
			}
		}
	}
	for _, msg := range msgs {
		if done, ok := msg.(searchDoneMsg); ok {
			m.Update(done)
			return
		}
	}
	t.Fatal("no search was started")
}

func key(s string) tea.KeyPressMsg {
	switch s {
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "tab":
		return tea.KeyPressMsg{Code: tea.KeyTab}
	}
	r := []rune(s)
	return tea.KeyPressMsg{Code: r[0], Text: s}
}

func loadHistory(m *Model, certs ...ct.Certificate) {
	m.startSearch()
	m.Update(searchDoneMsg{gen: m.searchGen, certs: certs})
}

func TestHistoryAndNames(t *testing.T) {
	m := newTestModel(t)
	loadHistory(m,
		cert("1", "C=US, O=Let's Encrypt, CN=R12", now.AddDate(0, 1, 0), "api.example.com", "example.com"),
		cert("2", "C=US, O=Let's Encrypt, CN=E5", now.AddDate(0, -1, 0), "api.example.com"),
	)

	if m.searching || len(m.table.Rows()) != 2 {
		t.Fatalf("searching=%v rows=%d", m.searching, len(m.table.Rows()))
	}
	if m.table.Cursor() != 0 {
		t.Errorf("cursor = %d, want 0 after first load", m.table.Cursor())
	}
	view := m.render()
	for _, want := range []string{"example.com", "History 2", "Names 2", "expired", "R12"} {
		if !strings.Contains(view, want) {
			t.Errorf("view missing %q", want)
		}
	}

	m.Update(key("3"))
	if m.tab != tabNames || len(m.table.Rows()) != 2 {
		t.Fatalf("names tab: tab=%v rows=%d", m.tab, len(m.table.Rows()))
	}
	api := m.names["api.example.com"]
	if api.seen != 2 || len(api.issuers) != 2 || !api.lastExpiry.Equal(now.AddDate(0, 1, 0)) {
		t.Errorf("api stats = %+v", api)
	}
}

func TestStaleSearchIgnored(t *testing.T) {
	m := newTestModel(t)
	m.startSearch()
	stale := m.searchGen
	m.startSearch() // user pressed r again
	m.Update(searchDoneMsg{gen: stale, certs: []ct.Certificate{cert("1", "CN=x", now, "a.example.com")}})
	if !m.searching || len(m.history) != 0 {
		t.Fatal("stale search result was applied")
	}
}

func TestSearchErrorKeepsPreviousHistory(t *testing.T) {
	m := newTestModel(t)
	loadHistory(m, cert("1", "CN=x", now, "a.example.com"))
	m.startSearch()
	m.Update(searchDoneMsg{gen: m.searchGen, err: errors.New("crt.sh: HTTP 502")})
	if len(m.history) != 1 || !strings.Contains(m.render(), "search failed") {
		t.Fatal("error should be shown without wiping existing results")
	}
}

func TestLiveMatches(t *testing.T) {
	m := newTestModel(t)
	loadHistory(m, cert("1", "CN=R12", now, "api.example.com"))

	m.Update(matchMsg{gen: m.watchGen, match: ct.Match{Log: "Argon", Index: 9, Precert: true, Certificate: cert("ab", "CN=R13", now.AddDate(0, 3, 0), "new.example.com")}})
	m.Update(matchMsg{gen: m.watchGen, match: ct.Match{Log: "Sycamore", Index: 10, Certificate: cert("cd", "CN=R13", now.AddDate(0, 3, 0), "api.example.com")}})

	if m.unseen != 2 || !strings.Contains(m.render(), "+2") {
		t.Errorf("unseen badge: %d", m.unseen)
	}
	m.Update(key("2"))
	if m.unseen != 0 {
		t.Error("opening the live tab must clear the badge")
	}
	rows := m.table.Rows()
	if len(rows) != 2 || rows[0][3] != "Sycamore" {
		t.Fatalf("live rows should be newest first: %v", rows)
	}
	if !m.names["new.example.com"].live || !m.names["api.example.com"].live {
		t.Error("names seen live must be marked")
	}

	// A re-search rebuilds names from history but must keep live sightings.
	loadHistory(m, cert("1", "CN=R12", now, "api.example.com"))
	if _, ok := m.names["new.example.com"]; !ok {
		t.Error("re-search dropped a live-only name")
	}
}

func TestFilter(t *testing.T) {
	m := newTestModel(t)
	loadHistory(m,
		cert("1", "CN=R12", now, "api.example.com"),
		cert("2", "CN=R12", now, "www.example.com"),
		cert("3", "CN=E5", now, "mail.example.com"),
	)
	m.Update(key("/"))
	for _, r := range "www" {
		m.Update(key(string(r)))
	}
	if n := len(m.table.Rows()); n != 1 {
		t.Fatalf("filter www: %d rows", n)
	}
	m.Update(key("enter")) // keep the filter, leave the input
	if m.filtering || m.filter.Value() != "www" {
		t.Fatal("enter should apply and keep the filter")
	}
	m.Update(key("q"))
	m.Update(key("esc"))
	if len(m.table.Rows()) != 3 {
		t.Error("esc should clear the filter")
	}
}

func TestFilterInputSwallowsShortcuts(t *testing.T) {
	m := newTestModel(t)
	m.Update(key("/"))
	_, cmd := m.Update(key("q"))
	if cmd != nil {
		if _, quit := cmd().(tea.QuitMsg); quit {
			t.Fatal("typing q in the filter quit the app")
		}
	}
	if m.filter.Value() != "q" {
		t.Errorf("filter = %q", m.filter.Value())
	}
}

func TestDetailPane(t *testing.T) {
	m := newTestModel(t)
	loadHistory(m, cert("42", "C=US, O=Let's Encrypt, CN=R12", now.AddDate(0, 0, 10), "api.example.com"))
	before := m.table.Height()
	m.Update(key("enter"))
	view := m.render()
	if !strings.Contains(view, "https://crt.sh/?id=42") || !strings.Contains(view, "10 days left") {
		t.Errorf("detail pane missing fields:\n%s", view)
	}
	if m.table.Height() >= before {
		t.Error("table should shrink to make room for the detail pane")
	}
}

func TestWatchToggle(t *testing.T) {
	m := newTestModel(t)
	_, cmd := m.Update(key("w"))
	if !m.watching || cmd == nil {
		t.Fatal("w should start watching")
	}
	done := make(chan tea.Msg)
	go func() { done <- cmd() }()

	m.Update(key("w"))
	if m.watching {
		t.Fatal("w should stop watching")
	}
	select {
	case msg := <-done:
		m.Update(msg)
		if m.watchErr != nil {
			t.Errorf("cancel must not be reported as an error: %v", m.watchErr)
		}
	case <-time.After(time.Second):
		t.Fatal("watch goroutine did not stop on cancel")
	}
}

func TestSourceCycle(t *testing.T) {
	m := newTestModel(t)
	for _, want := range []string{"crtsh", "certspotter", "auto"} {
		m.Update(key("s"))
		if m.source != want || !m.searching {
			t.Fatalf("source = %q searching=%v, want %q", m.source, m.searching, want)
		}
	}
}

func TestSwitchDomain(t *testing.T) {
	m := newTestModel(t)
	loadHistory(m, cert("1", "CN=R12", now, "api.example.com"))
	m.Update(matchMsg{gen: m.watchGen, match: ct.Match{Log: "Argon", Certificate: cert("ab", "CN=R13", now, "new.example.com")}})
	m.Update(key("/"))
	typeText(m, "api")
	m.Update(key("enter"))

	m.Update(key("d"))
	if !m.editingDomain || !strings.Contains(m.render(), "domain:") {
		t.Fatal("d should open the domain prompt")
	}
	typeText(m, "Other.ORG")
	_, cmd := m.Update(key("enter"))

	if m.domain != "other.org" || m.editingDomain {
		t.Fatalf("domain=%q editing=%v", m.domain, m.editingDomain)
	}
	if len(m.live) != 0 || len(m.history) != 0 || m.filter.Value() != "" || !m.searching {
		t.Fatal("switching must clear the old domain's data and filter, then search")
	}
	runSearchCmd(t, m, cmd)
	if len(m.history) != 1 || m.history[0].DNSNames[0] != "other.org" {
		t.Fatalf("searched the wrong domain: %+v", m.history)
	}
	if _, ok := m.names["api.example.com"]; ok {
		t.Error("names from the old domain survived the switch")
	}
	if !strings.Contains(m.render(), "other.org") {
		t.Error("header should show the new domain")
	}
}

func TestSwitchDomainDropsStaleLiveMatches(t *testing.T) {
	m := newTestModel(t)
	m.Update(key("w"))
	old := m.watchGen

	m.Update(key("d"))
	typeText(m, "other.org")
	m.Update(key("enter"))
	if !m.watching {
		t.Fatal("live feed was on, it should restart for the new domain")
	}

	// A match the old watcher pushed into the channel just before it was cancelled.
	m.Update(matchMsg{gen: old, match: ct.Match{Certificate: cert("x", "CN=x", now, "a.example.com")}})
	if len(m.live) != 0 {
		t.Fatal("a match for the previous domain leaked into the new one")
	}
}

func TestSwitchDomainKeepsLiveOff(t *testing.T) {
	m := newTestModel(t)
	m.Update(key("w")) // on
	m.Update(key("w")) // off
	m.Update(key("d"))
	typeText(m, "other.org")
	m.Update(key("enter"))
	if m.watching {
		t.Fatal("the user turned live off; a domain switch must not turn it back on")
	}
}

func TestDomainPromptValidation(t *testing.T) {
	m := newTestModel(t)
	m.Update(key("d"))
	typeText(m, "%.com")
	m.Update(key("enter"))
	if !m.editingDomain || m.domain != "example.com" || !strings.Contains(m.render(), "invalid domain") {
		t.Fatal("an invalid domain must keep the prompt open with an error")
	}
	m.Update(key("esc"))
	if m.editingDomain || m.domain != "example.com" {
		t.Fatal("esc should cancel and keep the current domain")
	}
}

func TestStartsOnPromptWithoutDomain(t *testing.T) {
	m := newTestModelFor(t, "")
	m.Init()
	if !m.editingDomain || m.searching {
		t.Fatalf("editing=%v searching=%v", m.editingDomain, m.searching)
	}
	m.Update(key("esc"))
	if !m.editingDomain {
		t.Fatal("esc with no domain has nothing to go back to")
	}
	typeText(m, "example.com")
	_, cmd := m.Update(key("enter"))
	runSearchCmd(t, m, cmd)
	if m.domain != "example.com" || len(m.history) != 1 {
		t.Fatalf("domain=%q history=%d", m.domain, len(m.history))
	}
}

func TestSinkStripsPrefixAndTracksLag(t *testing.T) {
	s := newSink()
	io.WriteString(s, "ctq: crt.sh failed; falling back to certspotter\n")
	s.progress(ct.Log{URL: "a"}, 90, 100)
	s.progress(ct.Log{URL: "b"}, 5, 5)
	snap := s.snapshot()
	if snap.lastWarning.text != "crt.sh failed; falling back to certspotter" {
		t.Errorf("warning = %q", snap.lastWarning.text)
	}
	if len(snap.logs) != 2 || snap.totalLag != 10 || snap.counts[logCatchingUp] != 1 || snap.counts[logOK] != 1 {
		t.Errorf("snapshot = %+v", snap)
	}
}

func TestLogHealthTransitions(t *testing.T) {
	s := newSink()
	l := ct.Log{Name: "Luoshu2027", URL: "u", Tiled: true}
	status := func() logStatus { return s.snapshot().logs[0].status() }

	s.progress(l, 100, 100)
	if status() != logOK {
		t.Fatalf("status = %v", status())
	}
	// The screenshot case: one 404 on a tile the checkpoint already covers.
	s.logError(l, errors.New("HTTP 404 from …/tile/data/x856/189"))
	if status() != logRetrying {
		t.Fatalf("one failure should be retrying, got %v", status())
	}
	s.logError(l, errors.New("404"))
	s.logError(l, errors.New("404"))
	if status() != logFailing {
		t.Fatalf("%d failures in a row should be failing, got %v", failingAfter, status())
	}
	// A partial catch-up doesn't prove recovery; a full one does.
	s.progress(l, 150, 200)
	if status() != logFailing {
		t.Fatal("partial progress must not clear the failure count")
	}
	s.progress(l, 200, 200)
	if status() != logOK {
		t.Fatalf("a full catch-up should recover, got %v", status())
	}
}

func TestLogErrorsStayOutOfStatusLine(t *testing.T) {
	m := newTestModel(t)
	m.Update(key("w"))
	l := ct.Log{Name: "TrustAsia Luoshu2027", Operator: "TrustAsia", URL: "https://luoshu2027.trustasia.com/luoshu2027", Tiled: true}
	m.sink.progress(ct.Log{Name: "Argon", Operator: "Google", URL: "a"}, 10, 10)
	m.sink.logError(l, errors.New("HTTP 404 from https://luoshu2027.trustasia.com/luoshu2027/tile/data/x856/189"))
	m.Update(tickMsg(now))

	status := m.statusView()
	if strings.Contains(status, "tile/data") || strings.Contains(status, "404") {
		t.Errorf("a per-log error leaked into the status line: %q", status)
	}
	if !strings.Contains(status, "1 retrying") {
		t.Errorf("status should summarize health: %q", status)
	}

	m.Update(key("4"))
	view := m.render()
	if !strings.Contains(view, "Luoshu2027") || !strings.Contains(view, "retrying") || !strings.Contains(view, "404") {
		t.Errorf("logs tab should show the failing log and its error:\n%s", view)
	}
}

func TestNamesZoneSortAndTags(t *testing.T) {
	m := newTestModel(t)
	loadHistory(m,
		cert("1", "CN=R12", now.AddDate(0, 3, 0), "mcp.ecs.privatecloud.example.com"),
		cert("2", "CN=R12", now.AddDate(0, 3, 0), "mea.ecs.privatecloud.example.com"),
		cert("3", "CN=R12", now.AddDate(0, 3, 0), "med.example.com"),
		cert("4", "CN=R12", now.AddDate(0, 3, 0), "ecs.privatecloud.example.com"),
		cert("5", "CN=E5", now.AddDate(0, 0, 5), "old.example.com"),
	)
	// Set first-seen dates explicitly: everything is two months old except one new name.
	for _, s := range m.names {
		s.firstSeen = now.AddDate(0, -2, 0)
	}
	m.names["mcp.ecs.privatecloud.example.com"].firstSeen = now.Add(-48 * time.Hour)
	m.Update(key("3"))

	var order []string
	for _, r := range m.table.Rows() {
		order = append(order, ansi.Strip(r[0]))
	}
	want := []string{
		"med.example.com", "old.example.com",
		"ecs.privatecloud.example.com", "mcp.ecs.privatecloud.example.com", "mea.ecs.privatecloud.example.com",
	}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("zone order:\n got %v\nwant %v", order, want)
	}

	tags := func(name string) string {
		for _, r := range m.rows {
			if r[0] == name {
				return ansi.Strip(r[1])
			}
		}
		return "?"
	}
	if got := tags("mcp.ecs.privatecloud.example.com"); got != "new" {
		t.Errorf("tags = %q, want new", got)
	}
	if got := tags("old.example.com"); got != "expiring" {
		t.Errorf("tags = %q, want expiring", got)
	}

	m.Update(key("o"))
	if m.sort != sortNewest || ansi.Strip(m.table.Rows()[0][0]) != "mcp.ecs.privatecloud.example.com" {
		t.Errorf("newest sort should put the new name first, got %v", m.table.Rows()[0][0])
	}
	m.Update(key("o"))
	if ansi.Strip(m.table.Rows()[0][0]) != "old.example.com" {
		t.Errorf("expiring sort should put old.example.com first")
	}
}

func TestNameColumnFitsContent(t *testing.T) {
	m := newTestModel(t) // 140 columns wide
	loadHistory(m, cert("1", "CN=R12", now, "api.example.com"))
	m.Update(key("3"))
	cols := m.table.Columns()
	if cols[0].Title != "NAME" || cols[0].Width > 30 {
		t.Errorf("NAME should fit its content, got width %d", cols[0].Width)
	}
	if cols[len(cols)-1].Title != "ISSUERS" || cols[len(cols)-1].Width < 40 {
		t.Errorf("leftover width should go to ISSUERS, got %+v", cols[len(cols)-1])
	}
}

func TestSelectedRowIsUnstyled(t *testing.T) {
	m := newTestModel(t)
	loadHistory(m,
		cert("1", "CN=R12", now.AddDate(0, 0, -1), "a.example.com"), // expired, styled red
		cert("2", "CN=R12", now.AddDate(0, 0, -2), "b.example.com"),
	)
	if row := m.table.Rows()[0]; row[2] != "expired" {
		t.Errorf("selected row must have no ANSI codes, got %q", row[2])
	}
	if row := m.table.Rows()[1]; row[2] == "expired" || ansi.Strip(row[2]) != "expired" {
		t.Errorf("unselected rows keep their color, got %q", row[2])
	}
	m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	if row := m.table.Rows()[1]; row[2] != "expired" {
		t.Errorf("styling must follow the cursor, got %q", row[2])
	}
}

func TestEmptyStates(t *testing.T) {
	m := newTestModel(t)
	m.Update(key("2"))
	if !strings.Contains(m.render(), "live feed is off") {
		t.Error("live tab with the feed off should say so")
	}
	m.Update(key("w"))
	if !strings.Contains(m.render(), "Watching") {
		t.Error("live tab while watching should explain that matches will appear")
	}
	loadHistory(m, cert("1", "CN=R12", now, "api.example.com"))
	m.Update(key("1"))
	m.Update(key("/"))
	typeText(m, "zzz")
	if !strings.Contains(m.render(), `Nothing matches "zzz"`) {
		t.Error("a filter with no matches should say so")
	}
}

// TestLayoutFitsTerminal checks the box geometry in every state: the frame must
// fill the terminal height exactly and never exceed its width, or the alt screen
// scrolls and the boxes tear.
func TestLayoutFitsTerminal(t *testing.T) {
	states := map[string]func(m *Model){
		"plain":   func(m *Model) {},
		"details": func(m *Model) { m.Update(key("enter")) },
		"filter":  func(m *Model) { m.Update(key("/")); typeText(m, "api") },
		"prompt":  func(m *Model) { m.Update(key("d")) },
		"prompt+details+filter": func(m *Model) {
			m.Update(key("enter"))
			m.Update(key("/"))
			typeText(m, "a")
			m.Update(key("enter"))
			m.Update(key("d"))
		},
		"empty live tab": func(m *Model) { m.Update(key("2")) },
		"names":          func(m *Model) { m.Update(key("3")) },
		"logs":           func(m *Model) { m.Update(key("4")) },
	}
	for _, size := range [][2]int{{140, 40}, {100, 30}, {80, 24}} {
		for name, setup := range states {
			m := newTestModel(t)
			m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
			loadHistory(m, cert("1", "C=US, O=Let's Encrypt, CN=R12", now, "api.example.com", "www.example.com"))
			setup(m)

			lines := strings.Split(m.render(), "\n")
			if len(lines) != size[1] {
				t.Errorf("%dx%d %s: %d lines, want %d", size[0], size[1], name, len(lines), size[1])
			}
			for i, l := range lines {
				if w := ansi.StringWidth(l); w > size[0] {
					t.Errorf("%dx%d %s: line %d is %d wide", size[0], size[1], name, i, w)
				}
			}
			plain := ansi.Strip(m.render())
			if strings.Count(plain, "╭") != strings.Count(plain, "╯") {
				t.Errorf("%dx%d %s: unbalanced box corners", size[0], size[1], name)
			}
			// The box truncates overflow, which would hide a table wider than its box.
			tw := 0
			for _, c := range m.table.Columns() {
				tw += c.Width + 2
			}
			if tw > m.innerWidth() {
				t.Errorf("%dx%d %s: table is %d wide, box interior is %d", size[0], size[1], name, tw, m.innerWidth())
			}
		}
	}
}

func TestFitColumns(t *testing.T) {
	specs := []colSpec{
		{title: "A", width: 10}, {title: "B", width: 18, drop: 2}, {title: "C", width: 11, drop: 3},
		{title: "NAME", width: 30, shrink: true}, {title: "FLEX", flex: true},
	}
	titles := func(cols []table.Column) string {
		var s []string
		for _, c := range cols {
			s = append(s, c.Title)
		}
		return strings.Join(s, ",")
	}
	width := func(cols []table.Column) int {
		w := 0
		for _, c := range cols {
			w += c.Width + 2
		}
		return w
	}

	// Wide: everything fits, FLEX takes the rest exactly.
	cols, keep := fitColumns(specs, 120)
	if titles(cols) != "A,B,C,NAME,FLEX" || width(cols) != 120 || len(keep) != 5 {
		t.Errorf("wide: %s width %d", titles(cols), width(cols))
	}
	// Narrower: C (drop 3) goes first, then B.
	cols, keep = fitColumns(specs, 90)
	if titles(cols) != "A,B,NAME,FLEX" || keep[2] != 3 || width(cols) != 90 {
		t.Errorf("90: %s width %d keep %v", titles(cols), width(cols), keep)
	}
	cols, _ = fitColumns(specs, 75)
	if titles(cols) != "A,NAME,FLEX" || width(cols) != 75 {
		t.Errorf("75: %s width %d", titles(cols), width(cols))
	}
	// Nothing left to drop: NAME shrinks so FLEX keeps its minimum.
	cols, _ = fitColumns(specs, 60)
	if titles(cols) != "A,NAME,FLEX" || cols[2].Width != minFlex || width(cols) != 60 {
		t.Errorf("60: %+v width %d", cols, width(cols))
	}
	if specs[3].width != 30 {
		t.Error("fitColumns must not modify the caller's specs")
	}
}

func TestBoxTitleInBorder(t *testing.T) {
	out := ansi.Strip(box("Title", "3/9", "body", 30, 4, true))
	lines := strings.Split(out, "\n")
	if len(lines) != 4 {
		t.Fatalf("%d lines", len(lines))
	}
	if !strings.HasPrefix(lines[0], "╭─Title") || !strings.HasSuffix(lines[0], " 3/9 ─╮") {
		t.Errorf("top border = %q", lines[0])
	}
	if lines[1] != "│ body"+strings.Repeat(" ", 22)+" │" {
		t.Errorf("body line = %q", lines[1])
	}
	for i, l := range lines {
		if ansi.StringWidth(l) != 30 {
			t.Errorf("line %d is %d wide: %q", i, ansi.StringWidth(l), l)
		}
	}
}

func TestHeaderShowsActualSource(t *testing.T) {
	m := newTestModel(t)
	c := cert("1", "CN=R12", now, "api.example.com")
	c.Source = "certspotter" // auto fell back
	loadHistory(m, c)
	if !strings.Contains(ansi.Strip(m.headerView()), "auto → certspotter") {
		t.Errorf("header = %q", ansi.Strip(m.headerView()))
	}
}

func TestTinyTerminalDoesNotPanic(t *testing.T) {
	m := newTestModel(t)
	loadHistory(m, cert("1", "CN=R12", now, "api.example.com"))
	m.Update(key("enter"))
	m.Update(tea.WindowSizeMsg{Width: 20, Height: 5})
	_ = m.render()
}
