// Package tui is an interactive front end for ctq: history, a live CT feed, a
// subdomain inventory and log health for one domain, on one screen.
package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jfagoagas/ctq/internal/ct"
)

// Backend is what the TUI drives. main wires it to the real ct package; tests use fakes.
type Backend struct {
	Search func(ctx context.Context, domain, source string, warn io.Writer) ([]ct.Certificate, error)
	Watch  func(ctx context.Context, domain string, h WatchHooks) error
}

type WatchHooks struct {
	Emit     func(ct.Match)
	Progress func(l ct.Log, next, size uint64)
	Error    func(l ct.Log, err error)
	Warn     io.Writer
}

type Options struct {
	Domain     string // initial domain; empty opens the domain prompt
	Subdomains bool
	Expired    bool          // history includes expired certificates; only part of the cache key
	Source     string        // auto | crtsh-db | crtsh | certspotter
	Watch      bool          // start tailing logs immediately
	CacheTTL   time.Duration // how long a search result is reused; 0 disables the cache
	Backend    Backend
}

var sources = []string{"auto", "crtsh-db", "crtsh", "certspotter"}

type tab int

const (
	tabHistory tab = iota
	tabLive
	tabNames
	tabLogs
	tabSources
	numTabs
)

// sortMode orders the Names tab.
type sortMode int

const (
	sortZone     sortMode = iota // DNS hierarchy: a zone's children stay together
	sortNewest                   // most recent first certificate first
	sortExpiring                 // soonest expiry first
	sortSeen                     // most certificates first
	numSorts
)

func (s sortMode) String() string {
	return [...]string{"zone", "newest", "expiring", "most seen"}[s]
}

const (
	newWindow      = 7 * 24 * time.Hour
	expiringWindow = 14 * 24 * time.Hour
)

type (
	searchDoneMsg struct {
		gen   int
		certs []ct.Certificate
		err   error
		took  time.Duration
	}
	watchDoneMsg struct {
		gen int
		err error
	}
	// matchMsg carries the watch generation that produced it. After a domain switch,
	// matches from the old watcher can still be sitting in the channel buffer.
	matchMsg struct {
		gen   int
		match ct.Match
	}
	tickMsg time.Time
)

type nameStat struct {
	seen       int
	firstSeen  time.Time
	lastExpiry time.Time
	live       bool
	issuers    map[string]struct{}
}

type Model struct {
	ctx  context.Context
	opts Options
	now  func() time.Time

	domain        string
	domainInput   textinput.Model
	editingDomain bool
	domainErr     string

	tab       tab
	sort      sortMode
	table     table.Model
	rows      []table.Row // styled rows; the selected one is shown unstyled
	rowKeys   []string    // stable identity per row, so the selection survives refreshes
	filter    textinput.Model
	filtering bool
	detail    bool
	spinner   spinner.Model
	width     int
	height    int

	mainBoxHeight int   // outer height of the main box, set by layout
	keep          []int // indexes of the row cells whose columns fit the width

	history  []ct.Certificate
	live     []ct.Match // append order; shown newest first
	names    map[string]*nameStat
	nameList []string
	visible  []int // indexes into the current tab's data after filtering
	unseen   int   // live matches that arrived while another tab was open

	source       string
	searching    bool
	searched     bool // at least one search finished
	searchGen    int
	searchCancel context.CancelFunc
	searchErr    error
	searchTook   time.Duration
	searchKey    searchKey // what the in-flight search is for, so its result is cached under it

	cache     *searchCache
	fromCache bool      // the history on screen came from the cache, not a fresh search
	resultAt  time.Time // when the history on screen was fetched

	watching     bool
	watchStarted time.Time
	liveWanted   bool // whether a domain switch should restart the live feed
	watchGen     int
	watchCancel  context.CancelFunc
	watchErr     error

	sink    *sink
	matches chan matchMsg
	snap    snapshot
}

func New(ctx context.Context, o Options) *Model {
	t := table.New(table.WithFocused(true))
	st := table.DefaultStyles()
	st.Header = st.Header.BorderStyle(lipgloss.NormalBorder()).BorderBottom(true).BorderForeground(colorDim).Bold(true)
	st.Selected = st.Selected.Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62")).Bold(false)
	t.SetStyles(st)

	f := textinput.New()
	f.Prompt = "/ "
	f.Placeholder = "filter by name, issuer or log"

	d := textinput.New()
	d.Prompt = "domain: "
	d.Placeholder = "example.com"
	d.CharLimit = 253

	src := o.Source
	if src == "" {
		src = "auto"
	}
	return &Model{
		ctx: ctx, opts: o, now: time.Now,
		domain: o.Domain, domainInput: d,
		table: t, filter: f,
		spinner:    spinner.New(spinner.WithSpinner(spinner.MiniDot), spinner.WithStyle(lipgloss.NewStyle().Foreground(colorAccent))),
		names:      map[string]*nameStat{},
		source:     src,
		liveWanted: o.Watch,
		cache:      newSearchCache(o.CacheTTL),
		sink:       newSink(),
		matches:    make(chan matchMsg, 256),
	}
}

func (m *Model) Init() tea.Cmd {
	cmds := []tea.Cmd{tick(), waitMatch(m.matches), m.spinner.Tick}
	if m.domain == "" {
		return tea.Batch(append(cmds, m.openDomainPrompt())...)
	}
	cmds = append(cmds, m.search())
	if m.liveWanted {
		cmds = append(cmds, m.startWatch())
	}
	return tea.Batch(cmds...)
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// waitMatch is the Bubble Tea pattern for a long-lived channel: one pending read,
// re-armed after every message.
func waitMatch(ch <-chan matchMsg) tea.Cmd {
	return func() tea.Msg { return <-ch }
}

func (m *Model) currentKey() searchKey {
	return searchKey{domain: m.domain, source: m.source, subdomains: m.opts.Subdomains, expired: m.opts.Expired}
}

// search shows the cached answer for the current domain and source when there is a
// fresh one, and otherwise runs the search. r calls startSearch directly to skip the cache.
func (m *Model) search() tea.Cmd {
	k := m.currentKey()
	e, ok := m.cache.get(k, m.now())
	if !ok {
		return m.startSearch()
	}
	// Supersede any search still running for the previous domain or source.
	if m.searchCancel != nil {
		m.searchCancel()
		m.searchCancel = nil
	}
	m.searchGen++
	m.searching, m.searchErr, m.searchTook = false, nil, e.took
	m.sink.trace("search", ct.LevelInfo, fmt.Sprintf("%s via %s: %s from the cache, fetched %s (r to refresh)",
		k.domain, k.source, plural(len(e.certs), "certificate"), ago(m.now().Sub(e.at))))
	m.showHistory(e.certs, true, e.at)
	return nil
}

func (m *Model) showHistory(certs []ct.Certificate, cached bool, at time.Time) {
	m.searched, m.history, m.fromCache, m.resultAt = true, certs, cached, at
	m.rebuildNames()
	m.refresh()
}

// startSearch always queries the backend.
func (m *Model) startSearch() tea.Cmd {
	if m.searchCancel != nil {
		m.searchCancel()
	}
	ctx, cancel := context.WithCancel(m.ctx)
	m.searchCancel = cancel
	m.searchGen++
	m.searchKey = m.currentKey()
	gen, domain, src, search, warn := m.searchGen, m.domain, m.source, m.opts.Backend.Search, m.sink
	m.searching, m.searchErr = true, nil
	trace := m.sink.trace
	ctx = ct.WithTracer(ctx, trace)
	return func() tea.Msg {
		start := time.Now()
		trace("search", ct.LevelInfo, domain+" via "+src)
		certs, err := search(ctx, domain, src, warn)
		took := time.Since(start)
		round := took.Round(100 * time.Millisecond).String()
		switch {
		case errors.Is(err, context.Canceled):
			trace("search", ct.LevelInfo, "cancelled after "+round)
		case err != nil:
			trace("search", ct.LevelError, "failed after "+round+": "+err.Error())
		default:
			trace("search", ct.LevelInfo, plural(len(certs), "certificate")+" in "+round)
		}
		return searchDoneMsg{gen: gen, certs: certs, err: err, took: took}
	}
}

func (m *Model) startWatch() tea.Cmd {
	ctx, cancel := context.WithCancel(m.ctx)
	m.watchCancel = cancel
	m.watchGen++
	m.watching, m.watchErr, m.watchStarted = true, nil, m.now()
	m.sink.resetLogs()
	gen, domain, watch, ch := m.watchGen, m.domain, m.opts.Backend.Watch, m.matches
	hooks := WatchHooks{
		Emit: func(mt ct.Match) {
			select {
			case ch <- matchMsg{gen: gen, match: mt}:
			case <-ctx.Done():
			}
		},
		Progress: m.sink.progress,
		Error:    m.sink.logError,
		Warn:     m.sink,
	}
	return func() tea.Msg { return watchDoneMsg{gen: gen, err: watch(ctx, domain, hooks)} }
}

func (m *Model) stopWatch() {
	if m.watchCancel != nil {
		m.watchCancel()
	}
	m.watching = false
}

func (m *Model) openDomainPrompt() tea.Cmd {
	m.editingDomain, m.domainErr = true, ""
	m.domainInput.SetValue("")
	m.layout()
	return m.domainInput.Focus()
}

// switchDomain throws away everything tied to the old domain and starts over.
// The live feed restarts only if it was on (or, for the first domain, if -no-live wasn't set).
func (m *Model) switchDomain(d string) tea.Cmd {
	m.stopWatch()
	// Bumping the generation drops matches from the old watcher that are still buffered.
	m.watchGen++

	m.domain = d
	m.history, m.live, m.unseen, m.searched, m.fromCache = nil, nil, 0, false, false
	m.searchErr, m.watchErr = nil, nil
	m.filter.SetValue("")
	m.detail = false
	m.rebuildNames()
	m.table.GotoTop()

	cmds := []tea.Cmd{m.search()}
	if m.liveWanted {
		cmds = append(cmds, m.startWatch())
	}
	m.layout()
	return tea.Batch(cmds...)
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
		return m, nil

	case tea.KeyPressMsg: // KeyMsg also matches releases
		return m.handleKey(msg)

	case searchDoneMsg:
		if msg.gen != m.searchGen {
			return m, nil // superseded by a newer search
		}
		m.searching, m.searchErr, m.searchTook = false, msg.err, msg.took
		if msg.err != nil {
			m.refresh()
			return m, nil
		}
		sort.Slice(msg.certs, func(i, j int) bool { return msg.certs[i].NotBefore.After(msg.certs[j].NotBefore) })
		at := m.now()
		m.cache.put(m.searchKey, cacheEntry{certs: msg.certs, at: at, took: msg.took})
		m.showHistory(msg.certs, false, at)
		return m, nil

	case matchMsg:
		if msg.gen != m.watchGen {
			return m, waitMatch(m.matches) // left over from a previous domain
		}
		mt := msg.match
		m.live = append(m.live, mt)
		m.addNames(mt.Certificate, true)
		m.sortNames()
		if m.tab != tabLive {
			m.unseen++
		}
		m.refresh()
		return m, waitMatch(m.matches)

	case watchDoneMsg:
		if msg.gen == m.watchGen {
			m.watching = false
			if msg.err != nil && !errors.Is(msg.err, context.Canceled) {
				m.watchErr = msg.err
			}
		}
		return m, nil

	case tickMsg:
		m.snap = m.sink.snapshot()
		if m.tab == tabLogs || m.tab == tabSources {
			m.refresh()
		}
		return m, tick()

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *Model) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.editingDomain {
		switch msg.String() {
		case "ctrl+c":
			return m.quit()
		case "esc":
			if m.domain == "" {
				return m, nil // nothing to go back to
			}
			m.editingDomain = false
			m.domainInput.Blur()
			m.layout()
			return m, nil
		case "enter":
			d, err := ct.NormalizeDomain(m.domainInput.Value())
			if err != nil {
				m.domainErr = err.Error()
				return m, nil
			}
			m.editingDomain = false
			m.domainInput.Blur()
			if d == m.domain {
				m.layout()
				return m, nil
			}
			return m, m.switchDomain(d)
		}
		var cmd tea.Cmd
		m.domainInput, cmd = m.domainInput.Update(msg)
		m.domainErr = ""
		return m, cmd
	}

	if m.filtering {
		switch msg.String() {
		case "ctrl+c":
			return m.quit()
		case "esc":
			m.filter.SetValue("")
			fallthrough
		case "enter":
			m.filtering = false
			m.filter.Blur()
			m.layout()
			return m, nil
		}
		var cmd tea.Cmd
		m.filter, cmd = m.filter.Update(msg)
		m.refresh()
		return m, cmd
	}

	switch msg.String() {
	case "q", "ctrl+c":
		return m.quit()
	case "tab":
		m.setTab((m.tab + 1) % numTabs)
	case "shift+tab":
		m.setTab((m.tab + numTabs - 1) % numTabs)
	case "1", "2", "3", "4", "5":
		m.setTab(tab(msg.String()[0] - '1'))
	case "/":
		m.filtering = true
		m.layout()
		return m, m.filter.Focus()
	case "esc":
		if m.detail {
			m.detail = false
			m.layout()
		} else if m.filter.Value() != "" {
			m.filter.SetValue("")
			m.refresh()
			m.layout()
		}
	case "enter":
		m.detail = !m.detail
		m.layout()
	case "o":
		if m.tab == tabNames {
			m.sort = (m.sort + 1) % numSorts
			m.sortNames()
			m.refresh()
			m.table.GotoTop()
			m.applyRows()
		}
	case "d":
		return m, m.openDomainPrompt()
	case "r":
		return m, m.startSearch() // always fresh: r is how the user asks past the cache
	case "s":
		for i, s := range sources {
			if s == m.source {
				m.source = sources[(i+1)%len(sources)]
				break
			}
		}
		return m, m.search()
	case "w":
		m.liveWanted = !m.watching
		if m.watching {
			m.stopWatch()
			return m, nil
		}
		return m, m.startWatch()
	default:
		before := m.table.Cursor()
		var cmd tea.Cmd
		m.table, cmd = m.table.Update(msg)
		if m.table.Cursor() != before {
			m.applyRows()
		}
		return m, cmd
	}
	return m, nil
}

func (m *Model) quit() (tea.Model, tea.Cmd) {
	m.stopWatch()
	if m.searchCancel != nil {
		m.searchCancel()
	}
	return m, tea.Quit
}

func (m *Model) setTab(t tab) {
	m.tab = t
	if t == tabLive {
		m.unseen = 0
	}
	if t == tabLogs || t == tabSources {
		m.snap = m.sink.snapshot() // don't wait up to a second for the first tick
	}
	m.layout()
	m.table.GotoTop()
	m.applyRows()
}

// --- data ---

func (m *Model) rebuildNames() {
	m.names = map[string]*nameStat{}
	for _, c := range m.history {
		m.addNames(c, false)
	}
	for _, mt := range m.live {
		m.addNames(mt.Certificate, true)
	}
	m.sortNames()
}

func (m *Model) addNames(c ct.Certificate, live bool) {
	for _, n := range c.DNSNames {
		s := m.names[n]
		if s == nil {
			s = &nameStat{firstSeen: c.NotBefore, issuers: map[string]struct{}{}}
			m.names[n] = s
		}
		s.seen++
		s.live = s.live || live
		if c.NotBefore.Before(s.firstSeen) {
			s.firstSeen = c.NotBefore
		}
		if c.NotAfter.After(s.lastExpiry) {
			s.lastExpiry = c.NotAfter
		}
		s.issuers[ct.IssuerCN(c.Issuer)] = struct{}{}
	}
}

// zoneKey reverses the labels so sorting follows the DNS tree:
// "mcp.ecs.example.com" -> "com.example.ecs.mcp", right after its parent zone.
func zoneKey(name string) string {
	labels := strings.Split(name, ".")
	slices.Reverse(labels)
	// \x00 sorts before any label character, so a parent always precedes its children.
	return strings.Join(labels, "\x00")
}

func (m *Model) sortNames() {
	m.nameList = m.nameList[:0]
	for n := range m.names {
		m.nameList = append(m.nameList, n)
	}
	byZone := func(a, b string) bool { return zoneKey(a) < zoneKey(b) }
	sort.Slice(m.nameList, func(i, j int) bool {
		a, b := m.nameList[i], m.nameList[j]
		sa, sb := m.names[a], m.names[b]
		switch m.sort {
		case sortNewest:
			if !sa.firstSeen.Equal(sb.firstSeen) {
				return sa.firstSeen.After(sb.firstSeen)
			}
		case sortExpiring:
			if !sa.lastExpiry.Equal(sb.lastExpiry) {
				return sa.lastExpiry.Before(sb.lastExpiry)
			}
		case sortSeen:
			if sa.seen != sb.seen {
				return sa.seen > sb.seen
			}
		}
		return byZone(a, b)
	})
}

// nameTags are the short labels in the Names STATUS column, most urgent first.
func (m *Model) nameTags(s *nameStat) []string {
	now := m.now()
	var tags []string
	if s.live {
		tags = append(tags, styleLive.Render("live"))
	}
	// Future-dated certificates exist (NotBefore ahead of issuance); they aren't "new".
	if age := now.Sub(s.firstSeen); age >= 0 && age <= newWindow {
		tags = append(tags, styleNew.Render("new"))
	}
	switch {
	case s.lastExpiry.Before(now):
		tags = append(tags, styleErr.Render("expired"))
	case s.lastExpiry.Sub(now) <= expiringWindow:
		tags = append(tags, styleWarn.Render("expiring"))
	}
	return tags
}

func (m *Model) certStatus(c ct.Certificate) string {
	now := m.now()
	switch {
	case c.Expired(now):
		return styleErr.Render("expired")
	case c.NotAfter.Sub(now) <= expiringWindow:
		return styleWarn.Render("expiring")
	}
	return "valid"
}

func (m *Model) liveAt(i int) ct.Match { return m.live[len(m.live)-1-i] }

func contains(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), needle)
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// refresh recomputes the visible rows for the current tab and filter.
//
// The selection survives it: refresh runs on layout changes (details pane),
// filter keystrokes, live matches and the Logs tab's 1s tick, and rows can move
// (Live is newest first). So the cursor follows the selected item's key, and
// only falls back to its old position when that item is gone.
func (m *Model) refresh() {
	prevCur := m.table.Cursor()
	prevKey := ""
	if prevCur >= 0 && prevCur < len(m.rowKeys) {
		prevKey = m.rowKeys[prevCur]
	}

	needle := strings.ToLower(strings.TrimSpace(m.filter.Value()))
	m.visible = m.visible[:0]
	var rows []table.Row
	var keys []string

	switch m.tab {
	case tabHistory:
		for i, c := range m.history {
			names := strings.Join(c.DNSNames, " ")
			if needle != "" && !contains(names+" "+c.Issuer+" "+c.Source, needle) {
				continue
			}
			m.visible = append(m.visible, i)
			keys = append(keys, "h/"+c.Source+"/"+c.ID)
			rows = append(rows, table.Row{
				c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"), m.certStatus(c),
				ct.IssuerCN(c.Issuer), c.Source, names,
			})
		}
	case tabLive:
		for i := range m.live {
			mt := m.liveAt(i)
			names := strings.Join(mt.DNSNames, " ")
			if needle != "" && !contains(names+" "+mt.Issuer+" "+mt.Log, needle) {
				continue
			}
			m.visible = append(m.visible, i)
			keys = append(keys, fmt.Sprintf("l/%s/%d", mt.Log, mt.Index))
			kind := "cert"
			if mt.Precert {
				kind = "precert"
			}
			rows = append(rows, table.Row{
				mt.NotBefore.Local().Format("01-02 15:04"), kind, ct.IssuerCN(mt.Issuer), mt.Log, names,
			})
		}
	case tabNames:
		for i, n := range m.nameList {
			if needle != "" && !contains(n, needle) {
				continue
			}
			m.visible = append(m.visible, i)
			keys = append(keys, "n/"+n)
			s := m.names[n]
			rows = append(rows, table.Row{
				n, strings.Join(m.nameTags(s), " "), fmt.Sprint(s.seen),
				s.firstSeen.Format("2006-01-02"), s.lastExpiry.Format("2006-01-02"),
				strings.Join(sortedKeys(s.issuers), ", "),
			})
		}
	case tabLogs:
		for i, h := range m.snap.logs {
			if needle != "" && !contains(h.log.Name+" "+h.log.Operator+" "+h.lastErr, needle) {
				continue
			}
			m.visible = append(m.visible, i)
			keys = append(keys, "g/"+h.log.URL)
			kind := "6962"
			if h.log.Tiled {
				kind = "tiled"
			}
			lastErr := ""
			if h.failures > 0 {
				lastErr = h.lastErr
			}
			rows = append(rows, table.Row{
				h.log.Operator, h.log.Name, kind, human(h.next), human(h.lag()), styleLogStatus(h.status()), lastErr,
			})
		}
	case tabSources:
		// Newest first, like Live: the latest step of a running search is on top.
		for i := len(m.snap.events) - 1; i >= 0; i-- {
			e := m.snap.events[i]
			if needle != "" && !contains(e.source+" "+e.msg, needle) {
				continue
			}
			m.visible = append(m.visible, i)
			keys = append(keys, fmt.Sprintf("s/%d", e.seq))
			rows = append(rows, table.Row{e.at.Local().Format("15:04:05"), e.source, styleLevel(e.level, e.msg)})
		}
	}

	m.rows, m.rowKeys = rows, keys
	cols, keep := fitColumns(m.columnSpecs(), m.innerWidth())
	m.keep = keep
	// Rows must never be wider than the columns, or the table panics while rendering.
	// Emptying the table resets its cursor, which is why the selection is restored below.
	m.table.SetRows(nil)
	m.table.SetColumns(cols)
	m.applyRows()

	target := slices.Index(keys, prevKey)
	if target < 0 && prevCur >= 0 && len(rows) > 0 {
		target = min(prevCur, len(rows)-1)
	}
	if target >= 0 && target != m.table.Cursor() {
		m.table.SetCursor(target)
		m.applyRows() // the unstyled row has to follow the cursor
	}
}

// applyRows hands the rows to the table, keeping only the columns that fit and
// stripping the selected row's colors. A colored cell ends in an SGR reset, which
// would also clear the selection background and leave holes in the highlight.
func (m *Model) applyRows() {
	rows := make([]table.Row, len(m.rows))
	for i, r := range m.rows {
		p := make(table.Row, len(m.keep))
		for j, k := range m.keep {
			p[j] = r[k]
		}
		rows[i] = p
	}
	m.table.SetRows(rows) // clamps the cursor to the new length
	if m.table.Cursor() < 0 && len(rows) > 0 {
		m.table.SetCursor(0) // SetRows leaves the cursor at -1 after an empty table
	}
	if cur := m.table.Cursor(); cur >= 0 && cur < len(rows) {
		for j, cell := range rows[cur] {
			rows[cur][j] = ansi.Strip(cell)
		}
		m.table.SetRows(rows)
	}
}

// colSpec describes one column. Exactly one column per table is flex: it takes
// whatever width is left. When that falls under minFlex, columns are dropped
// (highest drop first), then shrink columns give up width.
type colSpec struct {
	title  string
	width  int
	flex   bool
	drop   int  // 0 = always shown; higher = dropped earlier on narrow terminals
	shrink bool // may be narrowed (and truncated) as a last resort
}

const (
	minFlex      = 20 // narrowest useful flex column
	minShrinkCol = 12
)

func (m *Model) columnSpecs() []colSpec {
	switch m.tab {
	case tabHistory:
		return []colSpec{
			{title: "NOT BEFORE", width: 10}, {title: "NOT AFTER", width: 10, drop: 1}, {title: "STATUS", width: 8},
			{title: "ISSUER", width: 18, drop: 2}, {title: "SOURCE", width: 11, drop: 3}, {title: "NAMES", flex: true},
		}
	case tabLive:
		return []colSpec{
			{title: "NOT BEFORE", width: 11}, {title: "TYPE", width: 7, drop: 2}, {title: "ISSUER", width: 18, drop: 1},
			{title: "LOG", width: 30, drop: 3}, {title: "NAMES", flex: true},
		}
	case tabNames:
		// NAME is sized to its content. Stretching it to the full width puts the
		// other columns a screen away from the name they describe.
		longest := len("NAME")
		for _, r := range m.rows {
			longest = max(longest, len(r[0]))
		}
		return []colSpec{
			{title: "NAME", width: longest, shrink: true}, {title: "STATUS", width: 17},
			{title: "SEEN", width: 4, drop: 3}, {title: "FIRST CERT", width: 10, drop: 2},
			{title: "EXPIRES", width: 10}, {title: "ISSUERS", flex: true, drop: 1},
		}
	case tabLogs:
		return []colSpec{
			{title: "OPERATOR", width: 14, drop: 2}, {title: "LOG", width: 30, shrink: true}, {title: "TYPE", width: 5, drop: 3},
			{title: "POSITION", width: 8, drop: 1}, {title: "LAG", width: 6}, {title: "STATUS", width: 11},
			{title: "LAST ERROR", flex: true},
		}
	case tabSources:
		return []colSpec{{title: "TIME", width: 8}, {title: "SOURCE", width: 11, drop: 1}, {title: "EVENT", flex: true}}
	}
	return nil
}

// fitColumns picks the columns that fit in width and sizes them. keep holds the
// indexes of the kept specs, so rows (built with every column) can be projected.
// Each cell has 1 column of padding on each side.
func fitColumns(specs []colSpec, width int) (cols []table.Column, keep []int) {
	specs = slices.Clone(specs)
	for i := range specs {
		keep = append(keep, i)
	}
	hasFlex := func() bool {
		for _, k := range keep {
			if specs[k].flex {
				return true
			}
		}
		return false
	}
	spare := func() int {
		used := 2 * len(keep)
		for _, k := range keep {
			if !specs[k].flex {
				used += specs[k].width
			}
		}
		return width - used
	}
	need := func() int {
		if hasFlex() {
			return minFlex
		}
		return 0
	}

	for spare() < need() {
		victim := -1
		for i, k := range keep {
			if specs[k].drop > 0 && (victim < 0 || specs[k].drop > specs[keep[victim]].drop) {
				victim = i
			}
		}
		if victim < 0 {
			break
		}
		keep = slices.Delete(keep, victim, victim+1)
	}
	// Still too wide: narrow the shrink columns, truncating their content.
	for _, k := range keep {
		if short := need() - spare(); short > 0 && specs[k].shrink {
			specs[k].width = max(specs[k].width-short, minShrinkCol)
		}
	}
	// A dropped flex column leaves spare width; give it to a shrink column.
	if !hasFlex() {
		for _, k := range keep {
			if specs[k].shrink && spare() > 0 {
				specs[k].width += spare()
			}
		}
	}

	for _, k := range keep {
		w := specs[k].width
		if specs[k].flex {
			w = max(spare(), 1)
		}
		cols = append(cols, table.Column{Title: specs[k].title, Width: w})
	}
	return cols, keep
}

func (m *Model) layout() {
	if m.width == 0 {
		return
	}
	// Everything not taken by chrome and the optional boxes goes to the main box.
	main := m.height - chromeRows
	if m.detail {
		main -= detailBoxHeight
	}
	if m.editingDomain {
		main -= promptBoxHeight
	}
	m.mainBoxHeight = max(main, 7)

	body := m.mainBoxHeight - 2 // borders
	if m.filterShown() {
		body-- // the filter line sits at the bottom of the main box
	}
	iw := m.innerWidth()
	m.filter.SetWidth(iw - 4)
	// textinput pads to its full Width. Keep it short so a validation error fits beside it;
	// longer input scrolls horizontally.
	m.domainInput.SetWidth(max(min(iw-50, 40), 10))
	m.table.SetWidth(iw)
	m.table.SetHeight(max(body, 4))
	m.refresh()
}

func (m *Model) filterShown() bool { return m.filtering || m.filter.Value() != "" }
