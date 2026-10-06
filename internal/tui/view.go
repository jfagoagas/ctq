package tui

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/jfagoagas/ctq/internal/ct"
)

var (
	colorAccent = lipgloss.Color("69")
	colorDim    = lipgloss.Color("241")
	colorWarn   = lipgloss.Color("214")
	colorErr    = lipgloss.Color("203")
	colorLive   = lipgloss.Color("42")
	colorNew    = lipgloss.Color("117")

	styleTitle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(colorAccent).Padding(0, 1)
	styleDomain    = lipgloss.NewStyle().Bold(true).Padding(0, 1)
	styleDim       = lipgloss.NewStyle().Foreground(colorDim)
	styleTabActive = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62")).Padding(0, 1)
	styleTab       = lipgloss.NewStyle().Foreground(colorDim).Padding(0, 1)
	styleWarn      = lipgloss.NewStyle().Foreground(colorWarn)
	styleErr       = lipgloss.NewStyle().Foreground(colorErr)
	styleLive      = lipgloss.NewStyle().Foreground(colorLive)
	styleNew       = lipgloss.NewStyle().Foreground(colorNew).Bold(true)
	styleLabel     = lipgloss.NewStyle().Foreground(colorDim).Width(10)
	styleEmpty     = lipgloss.NewStyle().Foreground(colorDim).Padding(1, 2)
)

func styleLogStatus(s logStatus) string {
	switch s {
	case logOK:
		return styleLive.Render(s.String())
	case logRetrying:
		return styleWarn.Render(s.String())
	case logFailing:
		return styleErr.Render(s.String())
	}
	return s.String()
}

func styleLevel(l ct.Level, s string) string {
	switch l {
	case ct.LevelWarn:
		return styleWarn.Render(s)
	case ct.LevelError:
		return styleErr.Render(s)
	}
	return s
}

// View declares the alt screen itself. In Bubble Tea v2 that's a property of the
// view, not a program option.
func (m *Model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	return v
}

func (m *Model) render() string {
	if m.width == 0 {
		return "starting…"
	}
	w := m.boxWidth()
	parts := []string{"", m.headerView(), ""}
	// Whichever input has focus gets the accent border; the main box dims meanwhile.
	parts = append(parts, box(m.tabsTitle(), m.tabsRight(), m.mainBody(), w, m.mainBoxHeight, !m.editingDomain))
	if m.detail {
		parts = append(parts, box(boxTitle("Details", colorDim), "", m.detailBody(), w, detailBoxHeight, false))
	}
	if m.editingDomain {
		line := m.domainInput.View()
		if m.domainErr != "" {
			line += styleErr.Render("  " + m.domainErr)
		}
		parts = append(parts, box(boxTitle("Search a domain", colorAccent), "", line, w, promptBoxHeight, true))
	}
	parts = append(parts, m.statusView(), m.helpView())

	// Indent every line by the margin: boxes, header and status alike.
	margin := strings.Repeat(" ", marginX)
	out := strings.Split(lipgloss.JoinVertical(lipgloss.Left, parts...), "\n")
	for i, l := range out {
		if l != "" {
			out[i] = margin + l
		}
	}
	return strings.Join(out, "\n")
}

// mainBody is the table (or an empty-state message) plus the filter line when active.
func (m *Model) mainBody() string {
	body := m.table.View()
	if len(m.rows) == 0 {
		// An empty table can't tell "still loading" from "nothing found" from "filtered out".
		body = lipgloss.NewStyle().Height(m.table.Height() + 2).Render(styleEmpty.Render(m.emptyMessage()))
	}
	if m.filterShown() {
		body += "\n" + m.filter.View()
	}
	return body
}

func (m *Model) emptyMessage() string {
	if f := m.filter.Value(); f != "" {
		return fmt.Sprintf("Nothing matches %q. Press esc to clear the filter.", f)
	}
	switch m.tab {
	case tabHistory, tabNames:
		switch {
		case m.domain == "":
			return "Type a domain to start."
		case m.searching:
			return m.spinner.View() + " Searching " + m.source + " for " + m.domain + "…"
		case m.searchErr != nil:
			return "The search failed. Press r to retry, or s to try another source."
		case m.searched:
			return "No certificates found for " + m.domain + "."
		}
	case tabLive:
		switch {
		case m.watchErr != nil:
			return "The live feed stopped. Press w to restart it."
		case !m.watching:
			return "The live feed is off. Press w to watch the CT logs for new certificates."
		default:
			return fmt.Sprintf("Watching %d CT logs since %s.\nNew certificates for %s will show up here within seconds of being logged.",
				len(m.snap.logs), m.watchStarted.Format("15:04:05"), m.domain)
		}
	case tabLogs:
		if !m.watching {
			return "The live feed is off. Press w to start it and see each log's health here."
		}
		return m.spinner.View() + " Connecting to the CT logs…"
	case tabSources:
		return "No search activity yet. Every search logs its connections, requests, retries and fallbacks here."
	}
	return ""
}

func (m *Model) headerView() string {
	scope := "+ subdomains"
	if !m.opts.Subdomains {
		scope = "exact"
	}
	domain := m.domain
	if domain == "" {
		domain = styleDim.Render("no domain yet")
	}
	left := styleTitle.Render("ctq") + styleDomain.Render(domain) + styleDim.Render(scope)
	right := styleDim.Render("source: ") + m.source
	// With auto, show which backend actually answered: crt.sh or the fallback.
	if m.source == "auto" && len(m.history) > 0 && !m.searching {
		right += styleDim.Render(" → ") + m.history[0].Source
	}
	return spread(m.boxWidth(), left, right)
}

// tabsTitle is the tab bar, drawn inside the main box's top border.
func (m *Model) tabsTitle() string {
	live := fmt.Sprintf("2 Live %d", len(m.live))
	if m.unseen > 0 {
		live += styleLive.Render(fmt.Sprintf(" +%d", m.unseen))
	}
	logs := fmt.Sprintf("4 Logs %d", len(m.snap.logs))
	if n := m.snap.counts[logFailing]; n > 0 {
		logs += styleErr.Render(fmt.Sprintf(" !%d", n))
	} else if n := m.snap.counts[logRetrying]; n > 0 {
		logs += styleWarn.Render(fmt.Sprintf(" !%d", n))
	}
	sources := "5 Sources"
	if m.searchErr != nil {
		sources += styleErr.Render(" !")
	}
	labels := []string{fmt.Sprintf("1 History %d", len(m.history)), live, fmt.Sprintf("3 Names %d", len(m.names)), logs, sources}
	out := make([]string, len(labels))
	for i, l := range labels {
		if tab(i) == m.tab {
			out[i] = styleTabActive.Render(l)
		} else {
			out[i] = styleTab.Render(l)
		}
	}
	return strings.Join(out, " ")
}

// tabsRight is the main box's top-right corner: sort order and row position.
func (m *Model) tabsRight() string {
	var right []string
	if m.tab == tabNames {
		right = append(right, styleDim.Render("sort: ")+m.sort.String())
	}
	if n := len(m.rows); n > 0 {
		right = append(right, styleDim.Render(fmt.Sprintf("%d/%d", m.table.Cursor()+1, n)))
	}
	return strings.Join(right, styleDim.Render(" · "))
}

// lineWidth is the width of the lines below the boxes. They're inset like box
// content so their text lines up with the table's first column.
func (m *Model) lineWidth() int { return m.boxWidth() - 2*boxPad }

func inset(s string) string { return strings.Repeat(" ", boxPad) + s }

func (m *Model) statusView() string {
	var left string
	switch {
	case m.domain == "":
		left = styleDim.Render("type a domain and press enter")
	case m.searching:
		left = m.spinner.View() + " searching " + m.source + "…"
	case m.searchErr != nil:
		// The error is often longer than the line; the Sources tab has all of it.
		left = styleErr.Render("search failed") + styleDim.Render(" (full log in 5 Sources): ") + styleErr.Render(m.searchErr.Error())
	default:
		left = fmt.Sprintf("history: %d certs in %s", len(m.history), m.searchTook.Round(100*time.Millisecond))
	}
	// Per-log errors no longer land here (they're in the Logs tab), so what's left
	// is rare and worth reading: search fallbacks, state file problems.
	if w := m.snap.lastWarning; w.text != "" && m.now().Sub(w.at) < 30*time.Second {
		left += styleWarn.Render("  ⚠ " + w.text)
	}

	right := m.liveStatus()
	w := m.lineWidth()
	return inset(spread(w, truncate(left, w-lipgloss.Width(right)-2), right))
}

func (m *Model) liveStatus() string {
	switch {
	case m.watchErr != nil:
		return styleErr.Render("live failed: " + m.watchErr.Error())
	case !m.watching:
		return styleDim.Render("live: off")
	case len(m.snap.logs) == 0:
		return m.spinner.View() + " live: connecting…"
	}
	parts := []string{styleLive.Render("● live") + fmt.Sprintf(" %d logs", len(m.snap.logs))}
	c := m.snap.counts
	if c[logCatchingUp] == 0 && c[logRetrying] == 0 && c[logFailing] == 0 {
		parts = append(parts, styleDim.Render("all caught up"))
	}
	if n := c[logCatchingUp]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d catching up (%s)", n, human(m.snap.totalLag)))
	}
	if n := c[logRetrying]; n > 0 {
		parts = append(parts, styleWarn.Render(fmt.Sprintf("%d retrying", n)))
	}
	if n := c[logFailing]; n > 0 {
		parts = append(parts, styleErr.Render(fmt.Sprintf("%d failing", n)))
	}
	return strings.Join(parts, styleDim.Render(" · "))
}

func (m *Model) helpView() string {
	keys := "d domain · tab/1-5 switch · / filter · enter details · r search · s source · w live · q quit"
	switch {
	case m.editingDomain:
		keys = "enter search · esc cancel · ctrl+c quit"
	case m.tab == tabNames:
		keys = "o sort · " + keys
	}
	return inset(styleDim.Render(truncate(keys, m.lineWidth())))
}

// detailBody is the details box content. The box pads and truncates it.
func (m *Model) detailBody() string {
	lines := m.detailLines()
	return strings.Join(lines[:min(len(lines), detailLines)], "\n")
}

func (m *Model) detailLines() []string {
	cur := m.table.Cursor()
	if cur < 0 || cur >= len(m.visible) {
		return []string{styleDim.Render("nothing selected")}
	}
	idx := m.visible[cur]
	field := func(label, value string) string { return styleLabel.Render(label) + value }

	switch m.tab {
	case tabHistory:
		c := m.history[idx]
		source := c.Source + "  id " + c.ID
		if c.Source == "crtsh" || c.Source == "crtsh-db" {
			source += "  https://crt.sh/?id=" + c.ID
		}
		return []string{
			field("names", fmt.Sprintf("(%d) %s", len(c.DNSNames), strings.Join(c.DNSNames, ", "))),
			field("issuer", c.Issuer),
			field("validity", m.validity(c)),
			field("source", source),
		}
	case tabLive:
		mt := m.liveAt(idx)
		kind := "final certificate"
		if mt.Precert {
			kind = "precertificate (final cert usually follows within seconds)"
		}
		return []string{
			field("names", fmt.Sprintf("(%d) %s", len(mt.DNSNames), strings.Join(mt.DNSNames, ", "))),
			field("issuer", mt.Issuer),
			field("validity", m.validity(mt.Certificate)),
			field("log", fmt.Sprintf("%s  index %d", mt.Log, mt.Index)),
			field("type", kind),
			field("serial", mt.ID),
		}
	case tabNames:
		n := m.nameList[idx]
		s := m.names[n]
		live := "no"
		if s.live {
			live = styleLive.Render("yes, seen in a live CT log this session")
		}
		first := s.firstSeen.Format("2006-01-02") + "  " + ago(m.now().Sub(s.firstSeen))
		return []string{
			field("name", n),
			field("seen", plural(s.seen, "certificate")),
			field("first", first),
			field("expires", s.lastExpiry.Format("2006-01-02")+"  (latest expiry across all certs)"),
			field("issuers", strings.Join(sortedKeys(s.issuers), ", ")),
			field("live", live),
		}
	case tabLogs:
		if idx >= len(m.snap.logs) {
			return nil
		}
		h := m.snap.logs[idx]
		kind := "RFC 6962"
		if h.log.Tiled {
			kind = "static-ct-api (tiled)"
		}
		status := styleLogStatus(h.status())
		if h.failures > 0 {
			status += fmt.Sprintf("  %d failed polls in a row, retried every poll", h.failures)
		}
		lastErr := styleDim.Render("none this session")
		if !h.lastErrAt.IsZero() {
			lastErr = ago(m.now().Sub(h.lastErrAt)) + ": " + h.lastErr
		}
		return []string{
			field("log", h.log.Name+"  ("+h.log.Operator+", "+kind+")"),
			field("url", h.log.URL),
			field("position", fmt.Sprintf("%d of %d  (lag %d)", h.next, h.size, h.lag())),
			field("status", status),
			field("last err", lastErr),
		}
	case tabSources:
		if idx >= len(m.snap.events) {
			return nil
		}
		e := m.snap.events[idx]
		level := [...]string{"info", "warning", "error"}[e.level]
		lines := []string{field("event", e.at.Local().Format("2006-01-02 15:04:05.000")+"  "+e.source+"  "+styleLevel(e.level, level))}
		// The point of this tab: errors the status line truncates, wrapped in full.
		width := max(m.innerWidth()-lipgloss.Width(styleLabel.Render("")), 20)
		for i, l := range strings.Split(ansi.Wrap(e.msg, width, " "), "\n") {
			label := ""
			if i == 0 {
				label = "message"
			}
			lines = append(lines, field(label, styleLevel(e.level, l)))
		}
		return lines
	}
	return nil
}

func (m *Model) validity(c ct.Certificate) string {
	now := m.now()
	span := c.NotBefore.Format("2006-01-02") + " → " + c.NotAfter.Format("2006-01-02")
	days := int(c.NotAfter.Sub(now).Hours() / 24)
	if c.Expired(now) {
		return span + styleErr.Render(fmt.Sprintf("  expired %d days ago", -days))
	}
	return span + styleLive.Render(fmt.Sprintf("  valid, %d days left", days))
}

func ago(d time.Duration) string {
	if d < 0 {
		return "in the future (" + strings.TrimSuffix(ago(-d), " ago") + " from now)"
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// spread puts left and right on one line, right-aligned.
func spread(width int, left, right string) string {
	gap := width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		return left
	}
	return left + strings.Repeat(" ", gap) + right
}

// truncate cuts to width cells without splitting ANSI escape sequences, so styled
// text can be shortened safely.
func truncate(s string, width int) string {
	return ansi.Truncate(s, max(width, 1), "…")
}

func human(n uint64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1_000:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	}
	return fmt.Sprint(n)
}
