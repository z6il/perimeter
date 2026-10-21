// Package monitor runs checks on a schedule and turns what changed into findings, events and alerts.
package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/z6il/perimeter/internal/alert"
	"github.com/z6il/perimeter/internal/check"
	"github.com/z6il/perimeter/internal/store"
)

// Check names, also used as keys in the runs table.
const (
	CheckDNS    = "dns"
	CheckCT     = "ct"
	CheckExpiry = "expiry"
	CheckTLS    = "tls"
	CheckPorts  = "ports"
)

// Intervals between runs of each check.
var Intervals = map[string]time.Duration{
	CheckDNS:    time.Hour,
	CheckCT:     12 * time.Hour,
	CheckExpiry: 24 * time.Hour,
	CheckTLS:    12 * time.Hour,
	CheckPorts:  6 * time.Hour,
}

// RetryAfter is how soon a failed check runs again.
var RetryAfter = 30 * time.Minute

// Order in which checks run for an asset. Ports go before TLS so TLS sees new endpoints.
var Order = []string{CheckDNS, CheckExpiry, CheckCT, CheckPorts, CheckTLS}

// Monitor ties the checks to the store and alerts.
type Monitor struct {
	Store    *store.Store
	Scanner  check.Scanner
	Ports    []int
	TLS      check.TLSChecker
	HTTP     check.HTTP
	Resolver check.Resolver
	Alerts   *alert.Sender
	Log      *slog.Logger

	mu   sync.Mutex
	busy map[int64]bool
}

// New returns a Monitor wired to the real network.
func New(s *store.Store, log *slog.Logger) *Monitor {
	return &Monitor{
		Store: s, Scanner: check.DefaultScanner, Ports: check.CommonPorts,
		TLS: check.TLSChecker{}, HTTP: check.DefaultHTTP, Resolver: net.DefaultResolver,
		Alerts: alert.NewSender(), Log: log,
	}
}

// Applies reports whether a check runs for an asset at all.
func Applies(a store.Asset, name string) bool {
	switch name {
	case CheckDNS:
		return a.Kind == store.Domain
	case CheckCT, CheckExpiry:
		return a.Kind == store.Domain && a.ParentID == nil
	case CheckTLS:
		return a.Kind == store.Domain || a.Verified()
	case CheckPorts:
		return a.Verified()
	}
	return false
}

// Loop runs due checks every minute until ctx ends.
func (m *Monitor) Loop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		m.RunDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunDue runs every check whose interval has passed.
func (m *Monitor) RunDue(ctx context.Context) {
	assets, err := m.Store.Assets(ctx)
	if err != nil {
		m.Log.Error("list assets", "err", err)
		return
	}
	for _, a := range assets {
		if ctx.Err() != nil {
			return
		}
		m.Run(ctx, a.ID, false)
	}
}

// Run runs the checks for one asset: only the due ones, or all of them when force is set.
// It returns false when the asset is already being checked.
func (m *Monitor) Run(ctx context.Context, assetID int64, force bool) bool {
	m.mu.Lock()
	if m.busy == nil {
		m.busy = map[int64]bool{}
	}
	if m.busy[assetID] {
		m.mu.Unlock()
		return false
	}
	m.busy[assetID] = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.busy, assetID)
		m.mu.Unlock()
	}()

	for _, name := range Order {
		a, err := m.Store.Asset(ctx, assetID)
		if err != nil {
			return true
		}
		if !Applies(a, name) {
			continue
		}
		last, lastErr, _ := m.Store.LastRun(ctx, a.ID, name)
		wait := Intervals[name]
		if lastErr != "" && wait > RetryAfter {
			// Public services like crt.sh fail often; try again soon rather than in 12 hours.
			wait = RetryAfter
		}
		if !force && time.Since(last) < wait {
			continue
		}
		err = m.runCheck(ctx, a, name, last.IsZero())
		if err != nil {
			m.Log.Warn("check failed", "asset", a.Value, "check", name, "err", err)
		}
		m.Store.RecordRun(ctx, a.ID, name, err)
	}
	return true
}

// Busy reports whether an asset is being checked right now.
func (m *Monitor) Busy(assetID int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.busy[assetID]
}

func (m *Monitor) runCheck(ctx context.Context, a store.Asset, name string, first bool) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	switch name {
	case CheckDNS:
		return m.dns(ctx, a, first)
	case CheckCT:
		return m.ct(ctx, a, first)
	case CheckExpiry:
		return m.expiry(ctx, a)
	case CheckPorts:
		return m.ports(ctx, a, first)
	case CheckTLS:
		return m.tls(ctx, a)
	}
	return nil
}

// emit stores an event and sends it as an alert.
func (m *Monitor) emit(ctx context.Context, a store.Asset, sev store.Severity, title, detail string) {
	e, err := m.Store.AddEvent(ctx, store.Event{AssetID: a.ID, Asset: a.Value, Severity: sev, Title: title, Detail: detail})
	if err != nil {
		m.Log.Error("add event", "err", err)
		return
	}
	e.Asset = a.Value
	if err := m.Alerts.Send(ctx, alert.Load(ctx, m.Store), e); err != nil {
		m.Log.Warn("alert failed", "err", err)
	}
}

// sync updates findings under prefix and reports new and resolved ones.
func (m *Monitor) sync(ctx context.Context, a store.Asset, prefix string, current []store.Finding) error {
	added, resolved, err := m.Store.SyncFindings(ctx, a.ID, prefix, current)
	if err != nil {
		return err
	}
	for _, f := range added {
		m.emit(ctx, a, f.Severity, f.Title, f.Detail)
	}
	for _, f := range resolved {
		m.emit(ctx, a, store.Info, "Resolved: "+f.Title, f.Detail)
	}
	return nil
}

func (m *Monitor) dns(ctx context.Context, a store.Asset, first bool) error {
	now, err := check.DNSSnapshot(ctx, m.Resolver, a.Value)
	if err != nil {
		return err
	}
	prev, err := m.Store.DNS(ctx, a.ID)
	if err != nil {
		return err
	}
	if err := m.Store.ReplaceDNS(ctx, a.ID, now); err != nil {
		return err
	}
	if first {
		m.emit(ctx, a, store.Info, fmt.Sprintf("Recorded %d DNS records", len(now)), "")
		return nil
	}
	added, removed := check.Diff(prev, now)
	if len(added)+len(removed) == 0 {
		return nil
	}
	sev := store.Low
	var lines []string
	for _, r := range added {
		lines = append(lines, "+ "+r)
		sev = max(sev, dnsSeverity(r))
	}
	for _, r := range removed {
		lines = append(lines, "- "+r)
		sev = max(sev, dnsSeverity(r))
	}
	m.emit(ctx, a, sev, "DNS records changed", strings.Join(lines, "\n"))
	return nil
}

func dnsSeverity(record string) store.Severity {
	switch strings.SplitN(record, " ", 2)[0] {
	case "NS":
		return store.High
	case "A", "AAAA", "CNAME":
		return store.Medium
	}
	return store.Low
}

func (m *Monitor) ct(ctx context.Context, a store.Asset, first bool) error {
	names, err := m.HTTP.Subdomains(ctx, a.Value)
	if err != nil {
		return err
	}
	added, err := m.Store.AddSubdomains(ctx, a.ID, names)
	if err != nil {
		return err
	}
	switch {
	case first:
		m.emit(ctx, a, store.Info, fmt.Sprintf("Found %d subdomains in certificate logs", len(added)), "")
	case len(added) > 5:
		m.emit(ctx, a, store.Medium, fmt.Sprintf("%d new subdomains in certificate logs", len(added)), strings.Join(added, "\n"))
	default:
		for _, n := range added {
			m.emit(ctx, a, store.Medium, "New subdomain: "+n, "A certificate was issued for this name. If you don't recognise it, find out who created it.")
		}
	}
	return nil
}

func (m *Monitor) expiry(ctx context.Context, a store.Asset) error {
	t, registrar, err := m.HTTP.Expiry(ctx, a.Value)
	if err != nil {
		return err
	}
	if err := m.Store.SetExpiry(ctx, a.ID, &t); err != nil {
		return err
	}
	var current []store.Finding
	days := int(time.Until(t).Hours() / 24)
	if sev, ok := expirySeverity(days, 14, 30, 60); ok {
		detail := "Expires " + t.Format("2 Jan 2006")
		if registrar != "" {
			detail += " at " + registrar
		}
		current = append(current, store.Finding{Key: "expiry:domain", Severity: sev, Title: domainExpiryTitle(days), Detail: detail})
	}
	return m.sync(ctx, a, "expiry:", current)
}

func domainExpiryTitle(days int) string {
	if days < 0 {
		return "Domain registration has expired"
	}
	return fmt.Sprintf("Domain registration expires in %d days", days)
}

// expirySeverity grades days left against critical/high/medium thresholds.
func expirySeverity(days, crit, high, med int) (store.Severity, bool) {
	switch {
	case days <= crit:
		return store.Critical, true
	case days <= high:
		return store.High, true
	case days <= med:
		return store.Medium, true
	}
	return 0, false
}

// hosts returns the addresses to scan: the IP itself, or a domain's A/AAAA records (up to 4).
func (m *Monitor) hosts(ctx context.Context, a store.Asset) ([]string, error) {
	if a.Kind == store.IP {
		return []string{a.Value}, nil
	}
	addrs, err := m.Resolver.LookupHost(ctx, a.Value)
	if err != nil {
		return nil, err
	}
	sort.Strings(addrs)
	if len(addrs) > 4 {
		addrs = addrs[:4]
	}
	return addrs, nil
}

func (m *Monitor) ports(ctx context.Context, a store.Asset, first bool) error {
	if !a.Verified() {
		return nil
	}
	hosts, err := m.hosts(ctx, a)
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		return fmt.Errorf("%s has no A or AAAA records to scan", a.Value)
	}
	all, err := m.Store.Ports(ctx, a.ID)
	if err != nil {
		return err
	}
	var findings []store.Finding
	var opened, closed, changed []string
	total := 0
	for _, host := range hosts {
		prev := map[int]store.Port{}
		for _, p := range all {
			if p.Host == host {
				prev[p.Port] = p
			}
		}
		open := m.Scanner.Scan(ctx, host, m.Ports)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		total += len(open)
		var rows []store.Port
		now := map[int]bool{}
		for _, o := range open {
			now[o.Port] = true
			rows = append(rows, store.Port{Port: o.Port, Banner: o.Banner})
			label := check.PortLabel(o.Port)
			if old, ok := prev[o.Port]; !ok {
				opened = append(opened, fmt.Sprintf("%s:%d %s", host, o.Port, label))
			} else if old.Banner != "" && o.Banner != "" && old.Banner != o.Banner {
				changed = append(changed, fmt.Sprintf("%s:%d %q → %q", host, o.Port, old.Banner, o.Banner))
			}
			if !a.Allowed(o.Port) {
				detail := fmt.Sprintf("%s:%d is reachable from the internet", host, o.Port)
				if o.Banner != "" {
					detail += " (" + o.Banner + ")"
				}
				detail += ". If this is intended, add the port to the allowlist."
				findings = append(findings, store.Finding{
					Key:      fmt.Sprintf("port:%s:%d", host, o.Port),
					Severity: check.PortSeverity(o.Port),
					Title:    fmt.Sprintf("Unexpected open port %d%s", o.Port, paren(label)),
					Detail:   detail,
				})
			}
		}
		for p := range prev {
			if !now[p] {
				closed = append(closed, fmt.Sprintf("%s:%d %s", host, p, check.PortLabel(p)))
				if a.Allowed(p) {
					findings = append(findings, store.Finding{
						Key: fmt.Sprintf("down:%s:%d", host, p), Severity: store.Medium,
						Title:  fmt.Sprintf("Allowed port %d stopped responding", p),
						Detail: fmt.Sprintf("%s:%d was open before and is on the allowlist. The service may be down.", host, p),
					})
				}
			}
		}
		if err := m.Store.ReplacePorts(ctx, a.ID, host, rows); err != nil {
			return err
		}
	}
	// "down:" findings only exist until the port comes back, so they share the sync with "port:".
	if err := m.syncPorts(ctx, a, findings); err != nil {
		return err
	}
	if first {
		where := ""
		if len(hosts) > 1 {
			where = fmt.Sprintf(" across %d addresses", len(hosts))
		}
		m.emit(ctx, a, store.Info, fmt.Sprintf("First port scan found %d open %s%s", total, pluralWord(total, "port", "ports"), where), strings.Join(hosts, ", "))
		return nil
	}
	if len(opened) > 0 {
		m.emit(ctx, a, store.Low, "Ports opened", strings.Join(opened, "\n"))
	}
	if len(closed) > 0 {
		m.emit(ctx, a, store.Low, "Ports closed", strings.Join(closed, "\n"))
	}
	if len(changed) > 0 {
		m.emit(ctx, a, store.Low, "Service banner changed", strings.Join(changed, "\n"))
	}
	return nil
}

// Reevaluate recomputes port findings from the stored scan after the allowlist changes, without scanning.
func (m *Monitor) Reevaluate(ctx context.Context, a store.Asset) error {
	var findings []store.Finding
	existing, err := m.Store.Findings(ctx, a.ID)
	if err != nil {
		return err
	}
	for _, f := range existing {
		if strings.HasPrefix(f.Key, "port:") && !a.Allowed(portOf(f.Key)) {
			findings = append(findings, f)
		}
	}
	return m.sync(ctx, a, "port:", findings)
}

func (m *Monitor) syncPorts(ctx context.Context, a store.Asset, findings []store.Finding) error {
	var open, down []store.Finding
	for _, f := range findings {
		if strings.HasPrefix(f.Key, "down:") {
			down = append(down, f)
		} else {
			open = append(open, f)
		}
	}
	if err := m.sync(ctx, a, "port:", open); err != nil {
		return err
	}
	// A down port stays a finding until it answers again, so keep earlier ones that weren't re-detected
	// only if the port is still missing: recompute from the stored ports.
	stored, err := m.Store.Ports(ctx, a.ID)
	if err != nil {
		return err
	}
	isOpen := map[string]bool{}
	for _, p := range stored {
		isOpen[fmt.Sprintf("down:%s:%d", p.Host, p.Port)] = true
	}
	existing, err := m.Store.Findings(ctx, a.ID)
	if err != nil {
		return err
	}
	keep := down
	for _, f := range existing {
		if strings.HasPrefix(f.Key, "down:") && !isOpen[f.Key] && !containsKey(down, f.Key) && a.Allowed(portOf(f.Key)) {
			keep = append(keep, f)
		}
	}
	return m.sync(ctx, a, "down:", keep)
}

func containsKey(fs []store.Finding, k string) bool {
	for _, f := range fs {
		if f.Key == k {
			return true
		}
	}
	return false
}

func portOf(key string) int {
	i := strings.LastIndex(key, ":")
	var p int
	fmt.Sscanf(key[i+1:], "%d", &p)
	return p
}

func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func paren(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}

// tlsPorts are checked for certificates when they are open.
var tlsPorts = map[int]bool{443: true, 465: true, 636: true, 993: true, 995: true, 4443: true, 5986: true, 6443: true, 8443: true, 9443: true}

func (m *Monitor) tls(ctx context.Context, a store.Asset) error {
	type endpoint struct {
		host, sni string
		port      int
	}
	var eps []endpoint
	seen := map[string]bool{}
	add := func(host, sni string, port int) {
		k := fmt.Sprintf("%s:%d", host, port)
		if !seen[k] {
			seen[k] = true
			eps = append(eps, endpoint{host, sni, port})
		}
	}
	if a.Kind == store.Domain {
		// An HTTPS visit to the domain is passive enough to run before verification.
		add(a.Value, a.Value, 443)
	}
	if a.Verified() {
		open, err := m.Store.Ports(ctx, a.ID)
		if err != nil {
			return err
		}
		for _, p := range open {
			if !tlsPorts[p.Port] {
				continue
			}
			if a.Kind == store.Domain {
				add(a.Value, a.Value, p.Port)
			} else {
				add(p.Host, "", p.Port)
			}
		}
	}

	var findings []store.Finding
	for _, ep := range eps {
		res, err := m.TLS.CheckTLS(ctx, ep.host, ep.port, ep.sni)
		if err != nil {
			if ep.port == 443 && a.Kind == store.Domain {
				continue // no HTTPS on this domain
			}
			findings = append(findings, store.Finding{
				Key: fmt.Sprintf("tls:%s:%d:handshake", ep.host, ep.port), Severity: store.Medium,
				Title: fmt.Sprintf("TLS handshake failed on port %d", ep.port), Detail: err.Error(),
			})
			continue
		}
		na := res.NotAfter
		m.Store.PutCert(ctx, a.ID, store.Cert{
			Host: ep.host, Port: ep.port, Subject: res.Subject, Issuer: res.Issuer,
			NotAfter: &na, Version: res.Version, Problem: strings.Join(res.Problems, "; "),
		})
		where := fmt.Sprintf("%s:%d", ep.host, ep.port)
		days := int(time.Until(res.NotAfter).Hours() / 24)
		if sev, ok := expirySeverity(days, 0, 7, 21); ok {
			title := fmt.Sprintf("Certificate expires in %d days", days)
			if days < 0 {
				title = "Certificate has expired"
			}
			findings = append(findings, store.Finding{
				Key: "tls:" + where + ":expiry", Severity: sev, Title: title,
				Detail: fmt.Sprintf("%s, issued by %s, valid until %s", where, res.Issuer, res.NotAfter.Format("2 Jan 2006")),
			})
		}
		for _, p := range res.Problems {
			kind, sev := "untrusted", store.High
			switch {
			case strings.HasPrefix(p, "certificate does not cover"):
				kind = "name"
			case strings.HasPrefix(p, "still accepts"):
				kind, sev = "oldproto", store.Medium
			}
			findings = append(findings, store.Finding{
				Key: "tls:" + where + ":" + kind, Severity: sev,
				Title: strings.ToUpper(p[:1]) + p[1:], Detail: where,
			})
		}
	}
	return m.sync(ctx, a, "tls:", findings)
}
