package web

import (
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/z6il/perimeter/internal/alert"
	"github.com/z6il/perimeter/internal/check"
	"github.com/z6il/perimeter/internal/monitor"
	"github.com/z6il/perimeter/internal/store"
	"github.com/z6il/perimeter/internal/verify"
)

var funcs = template.FuncMap{
	"ago":       ago,
	"date":      func(t time.Time) string { return t.Local().Format("2 Jan 2006") },
	"datetime":  func(t time.Time) string { return t.Local().Format("2 Jan 15:04") },
	"clock":     func(t time.Time) string { return clockOrDay(t) },
	"sev":       func(s store.Severity) string { return s.String() },
	"sevLabel":  func(s store.Severity) string { return strings.ToUpper(s.String()[:1]) + s.String()[1:] },
	"portLabel": check.PortLabel,
	"days":      daysUntil,
	"plural": func(n int, one, many string) string {
		if n == 1 {
			return one
		}
		return many
	},
	"ports":      store.FormatPorts,
	"hostPort":   func(h string, p int) string { return fmt.Sprintf("%s:%d", h, p) },
	"txtName":    verify.TXTName,
	"filePath":   func() string { return verify.FilePath },
	"isPrivate":  verify.Private,
	"portOfKey":  portOfKey,
	"interval":   func(name string) string { return humanDuration(monitor.Intervals[name]) },
	"checkLabel": checkLabel,
	"portList":   func() []int { return check.CommonPorts },
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	case d < 48*time.Hour:
		return "yesterday"
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

func clockOrDay(t time.Time) string {
	l := t.Local()
	now := time.Now()
	if l.YearDay() == now.YearDay() && l.Year() == now.Year() {
		return l.Format("15:04")
	}
	return l.Format("2 Jan")
}

func daysUntil(t time.Time) int { return int(time.Until(t).Hours() / 24) }

func humanDuration(d time.Duration) string {
	if d >= time.Hour && d%time.Hour == 0 {
		h := int(d.Hours())
		if h == 1 {
			return "every hour"
		}
		return fmt.Sprintf("every %d hours", h)
	}
	return "every " + d.String()
}

func checkLabel(name string) string {
	return map[string]string{
		monitor.CheckDNS: "DNS records", monitor.CheckCT: "Certificate logs", monitor.CheckExpiry: "Domain expiry",
		monitor.CheckTLS: "TLS certificates", monitor.CheckPorts: "Port scan",
	}[name]
}

func portOfKey(key string) int {
	i := strings.LastIndex(key, ":")
	var p int
	fmt.Sscanf(key[i+1:], "%d", &p)
	return p
}

// ---------- overview ----------

type kpi struct {
	Label, Value, Unit, Sub string
	Hot                     bool
}

type runwayItem struct {
	Name, Kind string
	AssetID    int64
	Days, Pct  int
	Class      string
}

type portChip struct {
	Port    int
	Label   string
	Allowed bool
}

type exposureRow struct {
	Asset store.Asset
	Ports []portChip
	Note  string
	Bad   int
}

type lead struct {
	Strong, Rest string
	Hot          bool
}

type nextCheck struct {
	Label  string
	Assets int
	In     string
	due    time.Time
}

type overviewData struct {
	Next       []nextCheck
	Alerts     alert.Config
	Lead       lead
	KPIs       []kpi
	Findings   []store.Finding
	MoreFind   int
	Expiring   []runwayItem
	Exposure   []exposureRow
	Events     []store.Event
	LastCheck  time.Time
	AssetCount int
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	assets, _ := s.Store.Assets(ctx)
	findings, _ := s.Store.Findings(ctx, 0)
	ports, _ := s.Store.AllPorts(ctx)
	certs, _ := s.Store.AllCerts(ctx)
	subTotal, subNew, _ := s.Store.SubdomainCounts(ctx, time.Now().Add(-7*24*time.Hour))
	events, _ := s.Store.Events(ctx, 0, 200)

	d := overviewData{AssetCount: len(assets), LastCheck: s.Store.LatestRun(ctx)}

	verified, openTotal, unexpected := 0, 0, 0
	hosts := map[string]bool{}
	for _, a := range assets {
		if a.Verified() {
			verified++
		}
		row := exposureRow{Asset: a}
		for _, p := range ports[a.ID] {
			openTotal++
			hosts[p.Host] = true
			chip := portChip{Port: p.Port, Label: check.PortLabel(p.Port), Allowed: a.Allowed(p.Port)}
			if !chip.Allowed {
				unexpected++
				row.Bad++
			}
			row.Ports = append(row.Ports, chip)
		}
		sort.SliceStable(row.Ports, func(i, j int) bool {
			if row.Ports[i].Allowed != row.Ports[j].Allowed {
				return !row.Ports[i].Allowed
			}
			return row.Ports[i].Port < row.Ports[j].Port
		})
		switch {
		case !a.Verified():
			row.Note = "Port scans start once you verify ownership"
		case len(row.Ports) == 0:
			row.Note = "No open ports found"
		}
		d.Exposure = append(d.Exposure, row)
	}
	sort.SliceStable(d.Exposure, func(i, j int) bool { return d.Exposure[i].Bad > d.Exposure[j].Bad })

	// The runway: certificates and domain registrations on one 90-day scale, soonest first.
	for _, c := range certs {
		if c.NotAfter == nil {
			continue
		}
		d.Expiring = append(d.Expiring, runway(fmt.Sprintf("%s:%d", c.Host, c.Port), "TLS certificate", c.AssetID, *c.NotAfter))
	}
	for _, a := range assets {
		if a.ExpiresAt != nil {
			d.Expiring = append(d.Expiring, runway(a.Value, "Domain registration", a.ID, *a.ExpiresAt))
		}
	}
	sort.SliceStable(d.Expiring, func(i, j int) bool { return d.Expiring[i].Days < d.Expiring[j].Days })
	soonest := -1
	if len(d.Expiring) > 0 {
		soonest = d.Expiring[0].Days
	}
	if len(d.Expiring) > 5 {
		d.Expiring = d.Expiring[:5]
	}

	attention, recent := 0, 0
	for _, e := range events {
		if time.Since(e.CreatedAt) < 24*time.Hour {
			recent++
			if e.Severity >= store.Medium {
				attention++
			}
		}
	}

	certSub := "none checked yet"
	if soonestCert := soonestCertDays(certs); soonestCert >= 0 {
		certSub = fmt.Sprintf("soonest expires in %d days", soonestCert)
	}
	d.KPIs = []kpi{
		{Label: "Assets watched", Value: fmt.Sprint(len(assets)), Sub: fmt.Sprintf("%d verified for port scans", verified)},
		{Label: "Open ports", Value: fmt.Sprint(openTotal), Unit: fmt.Sprintf("on %d %s", len(hosts), pluralWord(len(hosts), "host", "hosts")),
			Sub: fmt.Sprintf("%d unexpected", unexpected), Hot: unexpected > 0},
		{Label: "Certificates", Value: fmt.Sprint(len(certs)), Sub: certSub},
		{Label: "Subdomains known", Value: fmt.Sprint(subTotal), Sub: fmt.Sprintf("%d new in the last 7 days", subNew)},
		{Label: "Events in 24 h", Value: fmt.Sprint(recent), Sub: fmt.Sprintf("%d medium or worse", attention), Hot: attention > 0},
	}

	d.Findings = findings
	if len(d.Findings) > 6 {
		d.MoreFind = len(d.Findings) - 6
		d.Findings = d.Findings[:6]
	}
	if len(events) > 8 {
		events = events[:8]
	}
	d.Events = events
	d.Lead = leadLine(len(assets), findings, soonest, d.Expiring)
	d.Alerts = alert.Load(ctx, s.Store)
	d.Next = s.nextChecks(r, assets)
	s.render(w, r, "overview", "Overview", "overview", d)
}

// nextChecks says when each kind of check runs next, and on how many assets.
func (s *Server) nextChecks(r *http.Request, assets []store.Asset) []nextCheck {
	var out []nextCheck
	for _, name := range []string{monitor.CheckPorts, monitor.CheckTLS, monitor.CheckDNS, monitor.CheckCT, monitor.CheckExpiry} {
		var soonest time.Time
		n := 0
		for _, a := range assets {
			if !monitor.Applies(a, name) {
				continue
			}
			n++
			last, _, _ := s.Store.LastRun(r.Context(), a.ID, name)
			due := last.Add(monitor.Intervals[name])
			if soonest.IsZero() || due.Before(soonest) {
				soonest = due
			}
		}
		if n == 0 {
			continue
		}
		out = append(out, nextCheck{Label: checkLabel(name), Assets: n, In: until(soonest), due: soonest})
	}
	// The three soonest are what someone glancing at the overview wants to know.
	sort.SliceStable(out, func(i, j int) bool { return out[i].due.Before(out[j].due) })
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}

func until(t time.Time) string {
	d := time.Until(t)
	switch {
	case d <= time.Minute:
		return "due now"
	case d < time.Hour:
		return fmt.Sprintf("in %d min", int(d.Minutes()))
	}
	return fmt.Sprintf("in %d h %02d min", int(d.Hours()), int(d.Minutes())%60)
}

func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func soonestCertDays(certs []store.AssetCert) int {
	best := -1
	for _, c := range certs {
		if c.NotAfter == nil {
			continue
		}
		if d := daysUntil(*c.NotAfter); best < 0 || d < best {
			best = d
		}
	}
	return best
}

func runway(name, kind string, assetID int64, t time.Time) runwayItem {
	days := daysUntil(t)
	pct := days * 100 / 90
	pct = max(2, min(100, pct))
	class := ""
	switch {
	case days <= 7:
		class = "hot"
	case days <= 30:
		class = "warm"
	}
	return runwayItem{Name: name, Kind: kind, AssetID: assetID, Days: days, Pct: pct, Class: class}
}

// leadLine is the sentence under the title: the one finding that matters most right now.
func leadLine(assets int, findings []store.Finding, soonest int, expiring []runwayItem) lead {
	switch {
	case assets == 0:
		return lead{Strong: "Nothing is watched yet.", Rest: "Add a domain or IP address to start."}
	case len(findings) > 0 && findings[0].Severity >= store.High:
		f := findings[0]
		n := 0
		for _, x := range findings {
			if x.Severity >= store.High {
				n++
			}
		}
		return lead{Hot: true, Strong: fmt.Sprintf("%d %s need attention.", n, pluralWord(n, "issue", "issues")),
			Rest: fmt.Sprintf("Worst: %s on %s, since %s.", strings.ToLower(f.Title[:1])+f.Title[1:], f.Asset, clockOrDay(f.FirstSeen))}
	case soonest >= 0 && soonest <= 30:
		return lead{Strong: "Nothing unexpected is exposed.", Rest: fmt.Sprintf("Next to expire: %s in %d days.", expiring[0].Name, soonest)}
	case len(findings) > 0:
		return lead{Strong: fmt.Sprintf("Nothing urgent. %d smaller %s open.", len(findings), pluralWord(len(findings), "issue is", "issues are")), Rest: ""}
	}
	return lead{Strong: "Nothing unexpected is exposed.", Rest: fmt.Sprintf("All %d %s match their allowlists.", assets, pluralWord(assets, "asset", "assets"))}
}

// ---------- assets ----------

type assetRow struct {
	Asset    store.Asset
	Open     int
	Findings int
	Worst    store.Severity
	LastRun  time.Time
}

func (s *Server) assetsPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	assets, _ := s.Store.Assets(ctx)
	findings, _ := s.Store.Findings(ctx, 0)
	ports, _ := s.Store.AllPorts(ctx)
	var rows []assetRow
	for _, a := range assets {
		row := assetRow{Asset: a, Open: len(ports[a.ID]), Worst: -1}
		for _, f := range findings {
			if f.AssetID == a.ID {
				row.Findings++
				row.Worst = max(row.Worst, f.Severity)
			}
		}
		runs, _ := s.Store.Runs(ctx, a.ID)
		for _, run := range runs {
			if run.At.After(row.LastRun) {
				row.LastRun = run.At
			}
		}
		rows = append(rows, row)
	}
	s.render(w, r, "assets", "Assets", "assets", rows)
}

func (s *Server) newPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "new", "Add an asset", "assets", nil)
}

// ---------- asset detail ----------

type checkRow struct {
	Name, Label string
	Run         store.Run
	Applies     bool
	Why         string
}

type portRow struct {
	store.Port
	Label   string
	Allowed bool
}

type assetData struct {
	Asset      store.Asset
	Parent     *store.Asset
	Busy       bool
	Ports      []portRow
	Certs      []store.Cert
	DNS        []string
	Subdomains []string
	Watched    map[string]int64
	Findings   []store.Finding
	Events     []store.Event
	Checks     []checkRow
	Self       string
}

func (s *Server) assetPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	a, err := s.Store.Asset(ctx, idOf(r))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	d := assetData{Asset: a, Busy: s.Monitor.Busy(a.ID), Watched: map[string]int64{}, Self: fmt.Sprintf("/assets/%d", a.ID)}
	if a.ParentID != nil {
		if p, err := s.Store.Asset(ctx, *a.ParentID); err == nil {
			d.Parent = &p
		}
	}
	ports, _ := s.Store.Ports(ctx, a.ID)
	for _, p := range ports {
		d.Ports = append(d.Ports, portRow{Port: p, Label: check.PortLabel(p.Port), Allowed: a.Allowed(p.Port)})
	}
	d.Certs, _ = s.Store.Certs(ctx, a.ID)
	d.DNS, _ = s.Store.DNS(ctx, a.ID)
	d.Subdomains, _ = s.Store.Subdomains(ctx, a.ID)
	d.Findings, _ = s.Store.Findings(ctx, a.ID)
	d.Events, _ = s.Store.Events(ctx, a.ID, 12)
	all, _ := s.Store.Assets(ctx)
	for _, x := range all {
		d.Watched[x.Value] = x.ID
	}
	runs, _ := s.Store.Runs(ctx, a.ID)
	for _, name := range monitor.Order {
		row := checkRow{Name: name, Label: checkLabel(name), Run: runs[name], Applies: monitor.Applies(a, name)}
		if !row.Applies {
			switch {
			case name == monitor.CheckPorts:
				row.Why = "after verification"
			case a.Kind == store.IP:
				row.Why = "domains only"
			default:
				row.Why = "on the parent domain"
			}
		}
		d.Checks = append(d.Checks, row)
	}
	s.render(w, r, "asset", a.Value, "assets", d)
}

// ---------- events and settings ----------

func (s *Server) eventsPage(w http.ResponseWriter, r *http.Request) {
	events, _ := s.Store.Events(r.Context(), 0, 200)
	s.render(w, r, "events", "Events", "events", events)
}

type settingsData struct {
	Alerts   alert.Config
	HasToken bool
	Levels   []string
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	c := alert.Load(r.Context(), s.Store)
	s.render(w, r, "settings", "Settings", "settings", settingsData{Alerts: c, HasToken: c.TelegramToken != "",
		Levels: []string{"info", "low", "medium", "high", "critical"}})
}
