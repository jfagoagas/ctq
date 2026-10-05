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
	styleDetail    = lipgloss.NewStyle().BorderStyle(lipgloss.NormalBorder()).BorderTop(true).BorderForeground(colorDim).Padding(0, 1)
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
	parts := []string{m.headerView(), m.tabsView(), m.bodyView()}
	if m.detail {
		parts = append(parts, m.detailView())
	}
	if m.filtering || m.filter.Value() != "" {
		parts = append(parts, m.filter.View())
	}
	if m.editingDomain {
		line := m.domainInput.View()
		if m.domainErr != "" {
			line += styleErr.Render("  " + m.domainErr)
		}
		parts = append(parts, truncate(line, m.width))
	}
	parts = append(parts, m.statusView(), m.helpView())
	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

// bodyView is the table, or an explanation when it has no rows. An empty table
// can't tell "still loading" from "nothing found" from "filtered out".
func (m *Model) bodyView() string {
	if len(m.rows) > 0 {
		return m.table.View()
	}
	height := m.table.Height() + 2 // viewport + header row and its border
	return lipgloss.NewStyle().Height(height).MaxHeight(height).Width(m.width).
		Render(styleEmpty.Render(m.emptyMessage()))
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
	return spread(m.width, left, right)
}

func (m *Model) tabsView() string {
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
	labels := []string{fmt.Sprintf("1 History %d", len(m.history)), live, fmt.Sprintf("3 Names %d", len(m.names)), logs}
	out := make([]string, len(labels))
	for i, l := range labels {
		if tab(i) == m.tab {
			out[i] = styleTabActive.Render(l)
		} else {
			out[i] = styleTab.Render(l)
		}
	}

	var right []string
	if m.tab == tabNames {
		right = append(right, styleDim.Render("sort: ")+m.sort.String())
	}
	if n := len(m.rows); n > 0 {
		right = append(right, styleDim.Render(fmt.Sprintf("%d/%d", m.table.Cursor()+1, n)))
	}
	return spread(m.width, lipgloss.JoinHorizontal(lipgloss.Top, out...), strings.Join(right, styleDim.Render(" · ")))
}

func (m *Model) statusView() string {
	var left string
	switch {
	case m.domain == "":
		left = styleDim.Render("type a domain and press enter")
	case m.searching:
		left = m.spinner.View() + " searching " + m.source + "…"
	case m.searchErr != nil:
		left = styleErr.Render("search failed: " + m.searchErr.Error())
	default:
		left = fmt.Sprintf("history: %d certs in %s", len(m.history), m.searchTook.Round(100*time.Millisecond))
	}
	// Per-log errors no longer land here (they're in the Logs tab), so what's left
	// is rare and worth reading: search fallbacks, state file problems.
	if w := m.snap.lastWarning; w.text != "" && m.now().Sub(w.at) < 30*time.Second {
		left += styleWarn.Render("  ⚠ " + w.text)
	}

	right := m.liveStatus()
	return spread(m.width, truncate(left, m.width-lipgloss.Width(right)-2), right)
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
	keys := "d domain · tab/1-4 switch · / filter · enter details · r search · s source · w live · q quit"
	switch {
	case m.editingDomain:
		keys = "enter search · esc cancel · ctrl+c quit"
	case m.tab == tabNames:
		keys = "o sort · " + keys
	}
	return styleDim.Render(truncate(keys, m.width))
}

func (m *Model) detailView() string {
	lines := m.detailLines()
	for len(lines) < detailHeight-1 {
		lines = append(lines, "")
	}
	for i, l := range lines[:detailHeight-1] {
		lines[i] = truncate(l, m.width-2)
	}
	return styleDetail.Width(m.width).Render(strings.Join(lines[:detailHeight-1], "\n"))
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
		if c.Source == "crtsh" {
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
			field("seen", fmt.Sprintf("%d certificates", s.seen)),
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
