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
	Source     string // auto | crtsh | certspotter
	Watch      bool   // start tailing logs immediately
	Backend    Backend
}

var sources = []string{"auto", "crtsh", "certspotter"}

type tab int

const (
	tabHistory tab = iota
	tabLive
	tabNames
	tabLogs
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
	detailHeight   = 7 // top border + 6 content lines
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
	filter    textinput.Model
	filtering bool
	detail    bool
	spinner   spinner.Model
	width     int
	height    int

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
		sink:       newSink(),
		matches:    make(chan matchMsg, 256),
	}
}

func (m *Model) Init() tea.Cmd {
	cmds := []tea.Cmd{tick(), waitMatch(m.matches), m.spinner.Tick}
	if m.domain == "" {
		return tea.Batch(append(cmds, m.openDomainPrompt())...)
	}
	cmds = append(cmds, m.startSearch())
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

func (m *Model) startSearch() tea.Cmd {
	if m.searchCancel != nil {
		m.searchCancel()
	}
	ctx, cancel := context.WithCancel(m.ctx)
	m.searchCancel = cancel
	m.searchGen++
	gen, domain, src, search, warn := m.searchGen, m.domain, m.source, m.opts.Backend.Search, m.sink
	m.searching, m.searchErr = true, nil
	return func() tea.Msg {
		start := time.Now()
		certs, err := search(ctx, domain, src, warn)
		return searchDoneMsg{gen: gen, certs: certs, err: err, took: time.Since(start)}
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
	m.history, m.live, m.unseen, m.searched = nil, nil, 0, false
	m.searchErr, m.watchErr = nil, nil
	m.filter.SetValue("")
	m.detail = false
	m.rebuildNames()
	m.table.GotoTop()

	cmds := []tea.Cmd{m.startSearch()}
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
		if msg.err == nil {
			m.searched = true
			sort.Slice(msg.certs, func(i, j int) bool { return msg.certs[i].NotBefore.After(msg.certs[j].NotBefore) })
			m.history = msg.certs
			m.rebuildNames()
		}
		m.refresh()
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
		if m.tab == tabLogs {
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
	case "1", "2", "3", "4":
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
		return m, m.startSearch()
	case "s":
		for i, s := range sources {
			if s == m.source {
				m.source = sources[(i+1)%len(sources)]
				break
			}
		}
		return m, m.startSearch()
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
	if t == tabLogs {
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
	if now.Sub(s.firstSeen) <= newWindow {
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
func (m *Model) refresh() {
	needle := strings.ToLower(strings.TrimSpace(m.filter.Value()))
	m.visible = m.visible[:0]
	var rows []table.Row

	switch m.tab {
	case tabHistory:
		for i, c := range m.history {
			names := strings.Join(c.DNSNames, " ")
			if needle != "" && !contains(names+" "+c.Issuer+" "+c.Source, needle) {
				continue
			}
			m.visible = append(m.visible, i)
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
	}

	m.rows = rows
	// Rows must never be wider than the columns, or the table panics while rendering.
	m.table.SetRows(nil)
	m.table.SetColumns(m.columns())
	m.applyRows()
}

// applyRows hands the rows to the table with the selected row's colors stripped.
// A colored cell ends in an SGR reset, which would also clear the selection
// background and leave holes in the highlight.
func (m *Model) applyRows() {
	m.table.SetRows(m.rows) // clamps the cursor to the new length
	if m.table.Cursor() < 0 && len(m.rows) > 0 {
		m.table.SetCursor(0) // SetRows leaves the cursor at -1 after an empty table
	}
	cur := m.table.Cursor()
	if cur < 0 || cur >= len(m.rows) {
		return
	}
	rows := slices.Clone(m.rows)
	plain := make(table.Row, len(rows[cur]))
	for i, cell := range rows[cur] {
		plain[i] = ansi.Strip(cell)
	}
	rows[cur] = plain
	m.table.SetRows(rows)
}

func (m *Model) columns() []table.Column {
	switch m.tab {
	case tabHistory:
		return withFlex(m.width, "NAMES", []table.Column{
			{Title: "NOT BEFORE", Width: 10}, {Title: "NOT AFTER", Width: 10}, {Title: "STATUS", Width: 8},
			{Title: "ISSUER", Width: 18}, {Title: "SOURCE", Width: 11},
		})
	case tabLive:
		return withFlex(m.width, "NAMES", []table.Column{
			{Title: "NOT BEFORE", Width: 11}, {Title: "TYPE", Width: 7}, {Title: "ISSUER", Width: 18}, {Title: "LOG", Width: 30},
		})
	case tabNames:
		// Size NAME to its content. Stretching it to the full width puts the
		// other columns a screen away from the name they describe.
		longest := 0
		for _, r := range m.rows {
			longest = max(longest, len(r[0]))
		}
		rest := []table.Column{
			{Title: "STATUS", Width: 17}, {Title: "SEEN", Width: 4},
			{Title: "FIRST CERT", Width: 10}, {Title: "EXPIRES", Width: 10},
		}
		const minIssuers = 16
		maxName := flexWidth(m.width, rest) - minIssuers - 2
		name := table.Column{Title: "NAME", Width: max(min(longest, maxName), 20)}
		return withFlex(m.width, "ISSUERS", append([]table.Column{name}, rest...))
	case tabLogs:
		return withFlex(m.width, "LAST ERROR", []table.Column{
			{Title: "OPERATOR", Width: 14}, {Title: "LOG", Width: 30}, {Title: "TYPE", Width: 5},
			{Title: "POSITION", Width: 8}, {Title: "LAG", Width: 6}, {Title: "STATUS", Width: 11},
		})
	}
	return nil
}

func withFlex(total int, title string, fixed []table.Column) []table.Column {
	return append(fixed, table.Column{Title: title, Width: flexWidth(total, fixed)})
}

// flexWidth gives the remaining width to one column. Each cell has 1 column of padding on each side.
func flexWidth(total int, fixed []table.Column) int {
	used := 2 * (len(fixed) + 1)
	for _, c := range fixed {
		used += c.Width
	}
	return max(total-used, 20)
}

func (m *Model) layout() {
	if m.width == 0 {
		return
	}
	h := m.height - 4 // header, tabs, status, help
	if m.detail {
		h -= detailHeight
	}
	if m.filtering || m.filter.Value() != "" {
		h--
	}
	if m.editingDomain {
		h--
	}
	m.filter.SetWidth(m.width - 4)
	// textinput pads to its full Width. Keep it short so a validation error fits beside it;
	// longer input scrolls horizontally.
	m.domainInput.SetWidth(max(min(m.width-50, 40), 10))
	m.table.SetWidth(m.width)
	m.table.SetHeight(max(h, 4))
	m.refresh()
}
