package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ir-netlify/netlify-scanner-go/internal/netlify"
	"github.com/ir-netlify/netlify-scanner-go/internal/pipeline"
)

var (
	cAccent = lipgloss.Color("#00FFD7")
	cWarn   = lipgloss.Color("#FFD700")
	cOk     = lipgloss.Color("#7CFC00")
	cDim    = lipgloss.Color("#7F8C8D")
	cErr    = lipgloss.Color("#FF5555")
	cInfo   = lipgloss.Color("#88C0D0")
	cNuc    = lipgloss.Color("#FF8800")
	cBdr    = lipgloss.Color("#3B4252")
	cBdrAct = lipgloss.Color("#00FFD7")
	cBg     = lipgloss.Color("#1F2430")

	sTitle    = lipgloss.NewStyle().Bold(true).Foreground(cAccent).Background(cBg).Padding(0, 1)
	sStage    = lipgloss.NewStyle().Foreground(cWarn).Bold(true)
	sHost     = lipgloss.NewStyle().Foreground(cOk)
	sIP       = lipgloss.NewStyle().Foreground(cInfo)
	sDim      = lipgloss.NewStyle().Foreground(cDim)
	sErr      = lipgloss.NewStyle().Foreground(cErr).Bold(true)
	sNuc      = lipgloss.NewStyle().Foreground(cNuc)
	sTabOn    = lipgloss.NewStyle().Bold(true).Foreground(cBg).Background(cAccent).Padding(0, 2)
	sTabOff   = lipgloss.NewStyle().Foreground(cDim).Padding(0, 2)
	sBdr      = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cBdr).Padding(0, 1)
	sBdrAct   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cBdrAct).Padding(0, 1)
	sStatLbl  = lipgloss.NewStyle().Foreground(cDim)
	sStatVal  = lipgloss.NewStyle().Foreground(cAccent).Bold(true)
	sBadge    = lipgloss.NewStyle().Background(cBg).Foreground(cAccent).Padding(0, 1).Bold(true)
	sBadgeBad = lipgloss.NewStyle().Background(cBg).Foreground(cErr).Padding(0, 1).Bold(true)
)

type Tab int

const (
	TabHosts Tab = iota
	TabIPs
	TabVerified
	TabEvents
	TabStats
	tabCount
)

func (t Tab) String() string {
	switch t {
	case TabHosts:
		return "Hosts"
	case TabIPs:
		return "IPs"
	case TabVerified:
		return "Verified"
	case TabEvents:
		return "Events"
	case TabStats:
		return "Stats"
	}
	return "?"
}

type Model struct {
	target string
	stage  string

	spin   spinner.Model
	prog   progress.Model
	filter textinput.Model

	tab        Tab
	filtering  bool
	helpOpen   bool

	hostsVP, ipsVP, verifiedVP, eventsVP viewport.Model

	hosts    []*netlify.Verdict
	ips      map[string]string
	ipList   []string
	verified []verifiedRow
	events   []eventRow

	counts   map[pipeline.EventKind]int
	stages   map[string]int
	dropped  int64
	startedAt time.Time

	width, height int
	done          bool
	err           error

	cancel context.CancelFunc
	ch     <-chan pipeline.Event

	naabuRate *atomic.Int64
}

type eventRow struct {
	t    time.Time
	kind pipeline.EventKind
	line string
}

type verifiedRow struct {
	Target string
	Kind   string // "ip" or "sni"
	Status string
	Detail string
}

type VerifiedMsg struct {
	Target, Kind, Status, Detail string
}

const stageOrder = "subfinder|dnsx|httpx|naabu|nuclei|done"

// WithNaabuRate attaches a shared atomic that the TUI can adjust via +/-/r
// keys. The pipeline reads this value just before launching naabu.
func (m Model) WithNaabuRate(rate *atomic.Int64) Model {
	m.naabuRate = rate
	return m
}

func New(target string, ch <-chan pipeline.Event, cancel context.CancelFunc) Model {
	sp := spinner.New(spinner.WithStyle(lipgloss.NewStyle().Foreground(cAccent)))
	sp.Spinner = spinner.MiniDot
	pr := progress.New(progress.WithDefaultGradient(), progress.WithoutPercentage())
	pr.Width = 20 // initial; relayout() resizes based on terminal width
	ti := textinput.New()
	ti.Placeholder = "filter…"
	ti.Prompt = "/ "
	ti.CharLimit = 64

	return Model{
		target:    target,
		stage:     "starting",
		spin:      sp,
		prog:      pr,
		filter:    ti,
		hostsVP:    viewport.New(0, 0),
		ipsVP:      viewport.New(0, 0),
		verifiedVP: viewport.New(0, 0),
		eventsVP:   viewport.New(0, 0),
		ips:       map[string]string{},
		counts:    map[pipeline.EventKind]int{},
		stages:    map[string]int{},
		startedAt: time.Now(),
		ch:        ch,
		cancel:    cancel,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.spin.Tick, m.next(), tickEvery())
}

type evMsg pipeline.Event
type closedMsg struct{}
type tickMsg time.Time

func tickEvery() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m Model) next() tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-m.ch
		if !ok {
			return closedMsg{}
		}
		return evMsg(ev)
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.relayout()
		return m, nil

	case tea.KeyMsg:
		if m.filtering {
			switch msg.String() {
			case "esc":
				m.filtering = false
				m.filter.Blur()
				m.filter.SetValue("")
				m.refreshActive()
			case "enter":
				m.filtering = false
				m.filter.Blur()
				m.refreshActive()
			default:
				var cmd tea.Cmd
				m.filter, cmd = m.filter.Update(msg)
				m.refreshActive()
				return m, cmd
			}
			return m, nil
		}
		switch msg.String() {
		case "q", "ctrl+c":
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		case "?":
			m.helpOpen = !m.helpOpen
		case "/":
			m.filtering = true
			m.filter.Focus()
			return m, textinput.Blink
		case "tab", "right", "l":
			m.tab = (m.tab + 1) % tabCount
		case "shift+tab", "left", "h":
			m.tab = (m.tab - 1 + tabCount) % tabCount
		case "1":
			m.tab = TabHosts
		case "2":
			m.tab = TabIPs
		case "3":
			m.tab = TabVerified
		case "4":
			m.tab = TabEvents
		case "5":
			m.tab = TabStats
		case "g":
			m.activeVP().GotoTop()
		case "G":
			m.activeVP().GotoBottom()
		case "j", "down":
			vp := m.activeVP()
			vp.LineDown(1)
		case "k", "up":
			vp := m.activeVP()
			vp.LineUp(1)
		case "pgdown":
			m.activeVP().HalfViewDown()
		case "pgup":
			m.activeVP().HalfViewUp()
		case "+", "=":
			m.bumpNaabuRate(+100)
		case "-", "_":
			m.bumpNaabuRate(-100)
		case "]":
			m.bumpNaabuRate(+1000)
		case "[":
			m.bumpNaabuRate(-1000)
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case tickMsg:
		return m, tickEvery()

	case evMsg:
		m.handle(pipeline.Event(msg))
		return m, m.next()

	case VerifiedMsg:
		m.verified = append(m.verified, verifiedRow{Target: msg.Target, Kind: msg.Kind, Status: msg.Status, Detail: msg.Detail})
		m.refreshVerified()
		return m, nil

	case closedMsg:
		m.done = true
		m.stage = "done"
	}
	return m, nil
}

func (m *Model) bumpNaabuRate(delta int64) {
	if m.naabuRate == nil {
		return
	}
	v := m.naabuRate.Add(delta)
	if v < 0 {
		m.naabuRate.Store(0)
		v = 0
	}
	m.pushEvent(pipeline.EvLog, sDim.Render(fmt.Sprintf("naabu rate → %d pps", v)))
}

func (m *Model) activeVP() *viewport.Model {
	switch m.tab {
	case TabHosts:
		return &m.hostsVP
	case TabIPs:
		return &m.ipsVP
	case TabVerified:
		return &m.verifiedVP
	case TabEvents:
		return &m.eventsVP
	}
	return &m.eventsVP
}

func (m *Model) handle(ev pipeline.Event) {
	m.counts[ev.Kind]++
	if ev.Stage != "" {
		m.stages[ev.Stage]++
	}

	switch ev.Kind {
	case pipeline.EvStage:
		m.stage = ev.Stage
		m.pushEvent(ev.Kind, sStage.Render("» "+ev.Stage)+" "+ev.Message)
	case pipeline.EvVerdict:
		if ev.Verdict != nil {
			m.hosts = append(m.hosts, ev.Verdict)
			for _, a := range ev.Verdict.Addrs {
				if _, ok := m.ips[a]; !ok {
					m.ips[a] = ev.Verdict.Host
					m.ipList = append(m.ipList, a)
				}
			}
			m.refreshHosts()
			m.refreshIPs()
		}
	case pipeline.EvFound:
		m.pushEvent(ev.Kind, sDim.Render("[sub] ")+ev.Message)
	case pipeline.EvHTTPX:
		m.pushEvent(ev.Kind, sDim.Render("[httpx] ")+truncate(ev.Message, 240))
	case pipeline.EvNaabu:
		m.pushEvent(ev.Kind, sDim.Render("[naabu] ")+ev.Message)
	case pipeline.EvNuclei:
		m.pushEvent(ev.Kind, sNuc.Render("[nuclei] ")+truncate(ev.Message, 240))
	case pipeline.EvError:
		m.pushEvent(ev.Kind, sErr.Render("[!] ")+ev.Message)
	case pipeline.EvLog:
		m.pushEvent(ev.Kind, sDim.Render("· ")+ev.Message)
	}
}

func (m *Model) pushEvent(kind pipeline.EventKind, line string) {
	m.events = append(m.events, eventRow{t: time.Now(), kind: kind, line: line})
	if len(m.events) > 2000 {
		m.events = m.events[len(m.events)-2000:]
	}
	m.refreshEvents()
}

func (m *Model) refreshActive() {
	switch m.tab {
	case TabHosts:
		m.refreshHosts()
	case TabIPs:
		m.refreshIPs()
	case TabVerified:
		m.refreshVerified()
	case TabEvents:
		m.refreshEvents()
	}
}

func (m *Model) refreshVerified() {
	q := strings.ToLower(m.filter.Value())
	var b strings.Builder
	confirmed, notNetlify, unreach := 0, 0, 0
	for _, v := range m.verified {
		switch v.Status {
		case "confirmed":
			confirmed++
		case "not-netlify":
			notNetlify++
		case "unreachable":
			unreach++
		}
		if q != "" && !strings.Contains(strings.ToLower(v.Target), q) {
			continue
		}
		var statusStyle lipgloss.Style
		switch v.Status {
		case "confirmed":
			statusStyle = sHost
		case "not-netlify":
			statusStyle = sErr
		default:
			statusStyle = sDim
		}
		fmt.Fprintf(&b, "%s  %s  %s  %s\n",
			sDim.Render(pad(v.Kind, 4)),
			sIP.Render(pad(v.Target, 38)),
			statusStyle.Render(pad(v.Status, 12)),
			sDim.Render(v.Detail),
		)
	}
	if len(m.verified) == 0 {
		b.WriteString(sDim.Render("(no verifications yet — run with --verify or `verify` subcommand)"))
	} else {
		summary := fmt.Sprintf("%s confirmed=%d  %s not-netlify=%d  %s unreachable=%d\n",
			sHost.Render("✓"), confirmed,
			sErr.Render("✗"), notNetlify,
			sDim.Render("·"), unreach,
		)
		b.WriteString("\n" + summary)
	}
	m.verifiedVP.SetContent(b.String())
}

func (m *Model) refreshHosts() {
	q := strings.ToLower(m.filter.Value())
	var b strings.Builder
	count := 0
	for _, v := range m.hosts {
		if q != "" && !strings.Contains(strings.ToLower(v.Host), q) {
			continue
		}
		count++
		fmt.Fprintf(&b, "%s  %s  %s",
			sHost.Render(pad(v.Host, 38)),
			sStage.Render(fmt.Sprintf("%3d", v.Score)),
			sDim.Render(reasonOf(v)),
		)
		if len(v.Addrs) > 0 {
			b.WriteString("  ")
			b.WriteString(sIP.Render(strings.Join(v.Addrs, ",")))
		}
		b.WriteByte('\n')
	}
	if count == 0 {
		b.WriteString(sDim.Render("(no hosts yet)"))
	}
	m.hostsVP.SetContent(b.String())
}

func (m *Model) refreshIPs() {
	q := strings.ToLower(m.filter.Value())
	sorted := make([]string, len(m.ipList))
	copy(sorted, m.ipList)
	sort.Strings(sorted)
	var b strings.Builder
	count := 0
	for _, ip := range sorted {
		if q != "" && !strings.Contains(ip, q) {
			continue
		}
		count++
		fmt.Fprintf(&b, "%s  %s\n",
			sIP.Render(pad(ip, 18)),
			sDim.Render("via "+m.ips[ip]),
		)
	}
	if count == 0 {
		b.WriteString(sDim.Render("(no IPs yet)"))
	}
	m.ipsVP.SetContent(b.String())
}

func (m *Model) refreshEvents() {
	q := strings.ToLower(m.filter.Value())
	var lines []string
	for _, e := range m.events {
		if q != "" && !strings.Contains(strings.ToLower(e.line), q) {
			continue
		}
		lines = append(lines, sDim.Render(e.t.Format("15:04:05"))+"  "+e.line)
	}
	if len(lines) == 0 {
		lines = []string{sDim.Render("(no events)")}
	}
	m.eventsVP.SetContent(strings.Join(lines, "\n"))
	m.eventsVP.GotoBottom()
}

func reasonOf(v *netlify.Verdict) string {
	switch {
	case v.Signals.HeaderMatch != "":
		return "hdr=" + v.Signals.HeaderMatch
	case v.Signals.CNAMEMatch != "":
		return "CNAME→" + v.Signals.CNAMEMatch
	case v.Signals.APEXFallback:
		return "A=" + netlify.FallbackApexA
	case v.Signals.ASNMatch:
		return "ASN=AS54113"
	case v.Signals.TLSSANMatch != "":
		return "san=" + v.Signals.TLSSANMatch
	}
	return "matched"
}

func (m *Model) relayout() {
	if m.width == 0 {
		return
	}
	innerH := m.height - 8
	if innerH < 5 {
		innerH = 5
	}
	w := m.width - 4
	m.hostsVP.Width, m.hostsVP.Height = w, innerH
	m.ipsVP.Width, m.ipsVP.Height = w, innerH
	m.verifiedVP.Width, m.verifiedVP.Height = w, innerH
	m.eventsVP.Width, m.eventsVP.Height = w, innerH
	m.filter.Width = 40

	pw := m.width / 4
	if pw < 10 {
		pw = 10
	} else if pw > 40 {
		pw = 40
	}
	m.prog.Width = pw
}

func (m Model) View() string {
	if m.helpOpen {
		return m.renderHelp()
	}

	header := m.renderHeader()
	tabs := m.renderTabs()
	body := m.renderActiveTab()
	footer := m.renderFooter()

	return lipgloss.JoinVertical(lipgloss.Left, header, tabs, body, footer)
}

func (m Model) renderHeader() string {
	left := sTitle.Render(" netlify-scanner-go ")
	target := sDim.Render("target ") + sHost.Render(m.target)

	stageBadge := sBadge.Render(m.stage)
	if m.done {
		stageBadge = sBadge.Render("✓ done")
	}
	stageLine := m.spin.View() + " " + stageBadge
	if m.naabuRate != nil {
		stageLine += "  " + sDim.Render("naabu="+fmt.Sprintf("%dpps", m.naabuRate.Load()))
	}

	pf := stageProgressFraction(m.stage)
	bar := m.prog.ViewAs(pf)

	return lipgloss.JoinHorizontal(lipgloss.Center, left, "  ", target, "   ", stageLine, "  ", bar)
}

func (m Model) renderTabs() string {
	var parts []string
	for i := Tab(0); i < tabCount; i++ {
		label := i.String()
		switch i {
		case TabHosts:
			label = fmt.Sprintf("%s (%d)", label, len(m.hosts))
		case TabIPs:
			label = fmt.Sprintf("%s (%d)", label, len(m.ipList))
		case TabVerified:
			label = fmt.Sprintf("%s (%d)", label, len(m.verified))
		case TabEvents:
			label = fmt.Sprintf("%s (%d)", label, len(m.events))
		}
		if i == m.tab {
			parts = append(parts, sTabOn.Render(label))
		} else {
			parts = append(parts, sTabOff.Render(label))
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

func (m Model) renderActiveTab() string {
	var inner string
	switch m.tab {
	case TabHosts:
		inner = m.hostsVP.View()
	case TabIPs:
		inner = m.ipsVP.View()
	case TabVerified:
		inner = m.verifiedVP.View()
	case TabEvents:
		inner = m.eventsVP.View()
	case TabStats:
		inner = m.renderStats()
	}
	return sBdrAct.Render(inner)
}

func (m Model) renderStats() string {
	uptime := time.Since(m.startedAt).Round(time.Second)
	rate := float64(0)
	if uptime > 0 {
		rate = float64(totalEvents(m.counts)) / uptime.Seconds()
	}
	rows := []struct{ k, v string }{
		{"target", m.target},
		{"stage", m.stage},
		{"uptime", uptime.String()},
		{"events", fmt.Sprintf("%d  (%.1f/s)", totalEvents(m.counts), rate)},
		{"hosts", fmt.Sprint(len(m.hosts))},
		{"unique IPs", fmt.Sprint(len(m.ipList))},
		{"verdicts", fmt.Sprint(m.counts[pipeline.EvVerdict])},
		{"httpx", fmt.Sprint(m.counts[pipeline.EvHTTPX])},
		{"naabu", fmt.Sprint(m.counts[pipeline.EvNaabu])},
		{"nuclei", fmt.Sprint(m.counts[pipeline.EvNuclei])},
		{"errors", fmt.Sprint(m.counts[pipeline.EvError])},
	}
	var b strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&b, "%s  %s\n", sStatLbl.Render(pad(r.k, 12)), sStatVal.Render(r.v))
	}
	b.WriteString("\n" + sStatLbl.Render("stages:") + "\n")
	for _, s := range strings.Split(stageOrder, "|") {
		fmt.Fprintf(&b, "  %s  %s\n", sStatLbl.Render(pad(s, 10)), sStatVal.Render(fmt.Sprint(m.stages[s])))
	}
	return b.String()
}

func (m Model) renderFooter() string {
	if m.filtering {
		return sBdr.Render(m.filter.View())
	}
	hint := "[1-5] tabs  [/] filter  [j/k] scroll  [+/-] naabu rate  [?] help  [q] quit"
	return sDim.Render(hint)
}

func (m Model) renderHelp() string {
	help := `
  netlify-scanner-go — keys

    1, 2, 3, 4         switch tabs (Hosts / IPs / Events / Stats)
    tab / shift+tab    cycle tabs
    /                  filter current tab (esc to clear)
    j / k or ↑/↓       scroll one line
    pgup / pgdown      half-page
    g / G              top / bottom
    ?                  toggle this help
    q / ctrl+c         quit (cancels in-flight scan)
    + / -              naabu rate ±100 pps
    ] / [              naabu rate ±1000 pps

  scoring (≥30 → IsNetlify):
    x-nf-request-id        +60
    CNAME → netlify edge   +50
    A == 75.2.60.5         +50
    IP in AS54113          +30
    Server: Netlify        +25
    TLS SAN match          +20
`
	return sBdrAct.Render(help)
}

func stageProgressFraction(stage string) float64 {
	idx := -1
	parts := strings.Split(stageOrder, "|")
	for i, p := range parts {
		if p == stage {
			idx = i
			break
		}
	}
	if idx < 0 {
		return 0
	}
	return float64(idx+1) / float64(len(parts))
}

func totalEvents(c map[pipeline.EventKind]int) int {
	n := 0
	for _, v := range c {
		n += v
	}
	return n
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

var _ = sBadgeBad
