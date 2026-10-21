package check

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Passive checks only read public records; they never touch the target's servers.

// Resolver is the subset of net.Resolver the DNS check uses.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// DNSSnapshot returns the domain's records as sorted "TYPE value" lines.
func DNSSnapshot(ctx context.Context, r Resolver, domain string) ([]string, error) {
	var out []string
	hosts, err := r.LookupHost(ctx, domain)
	if err != nil {
		var dnsErr *net.DNSError
		if !(errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
			return nil, err
		}
	}
	for _, h := range hosts {
		if strings.Contains(h, ":") {
			out = append(out, "AAAA "+h)
		} else {
			out = append(out, "A "+h)
		}
	}
	if c, err := r.LookupCNAME(ctx, domain); err == nil {
		c = strings.TrimSuffix(c, ".")
		if c != "" && !strings.EqualFold(c, domain) {
			out = append(out, "CNAME "+c)
		}
	}
	if mx, err := r.LookupMX(ctx, domain); err == nil {
		for _, m := range mx {
			out = append(out, "MX "+strings.TrimSuffix(m.Host, "."))
		}
	}
	if ns, err := r.LookupNS(ctx, domain); err == nil {
		for _, n := range ns {
			out = append(out, "NS "+strings.ToLower(strings.TrimSuffix(n.Host, ".")))
		}
	}
	if txt, err := r.LookupTXT(ctx, domain); err == nil {
		for _, t := range txt {
			if strings.HasPrefix(t, "perimeter-verify=") {
				continue
			}
			if len(t) > 120 {
				t = t[:120] + "…"
			}
			out = append(out, "TXT "+t)
		}
	}
	sort.Strings(out)
	return dedupe(out), nil
}

func dedupe(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// Diff returns what is in b but not a (added) and in a but not b (removed). Both must be sorted.
func Diff(a, b []string) (added, removed []string) {
	in := func(list []string, v string) bool {
		i := sort.SearchStrings(list, v)
		return i < len(list) && list[i] == v
	}
	for _, v := range b {
		if !in(a, v) {
			added = append(added, v)
		}
	}
	for _, v := range a {
		if !in(b, v) {
			removed = append(removed, v)
		}
	}
	return added, removed
}

// HTTP is used by the CT and RDAP lookups. Tests point the base URLs at a local server.
type HTTP struct {
	Client         *http.Client
	CTURL          string // e.g. https://crt.sh
	CertSpotterURL string // fallback CT source, e.g. https://api.certspotter.com
	RDAPURL        string // e.g. https://rdap.org
}

// DefaultHTTP talks to the public services.
var DefaultHTTP = HTTP{
	Client:         &http.Client{Timeout: 60 * time.Second},
	CTURL:          "https://crt.sh",
	CertSpotterURL: "https://api.certspotter.com",
	RDAPURL:        "https://rdap.org",
}

func (h HTTP) get(ctx context.Context, u string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Perimeter (+https://github.com/z6il/perimeter)")
	req.Header.Set("Accept", "application/json, application/rdap+json")
	resp, err := h.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %s", req.URL.Host, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(into)
}

// Subdomains lists names under domain seen in certificate transparency logs. It asks crt.sh first
// and Cert Spotter when crt.sh fails, which it often does under load.
func (h HTTP) Subdomains(ctx context.Context, domain string) ([]string, error) {
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	err := h.get(ctx, h.CTURL+"/?output=json&q="+url.QueryEscape("%."+domain), &entries)
	if err == nil {
		var names []string
		for _, e := range entries {
			names = append(names, strings.Split(e.NameValue, "\n")...)
		}
		return under(domain, names), nil
	}
	if h.CertSpotterURL == "" {
		return nil, err
	}
	var issuances []struct {
		DNSNames []string `json:"dns_names"`
	}
	u := h.CertSpotterURL + "/v1/issuances?include_subdomains=true&expand=dns_names&domain=" + url.QueryEscape(domain)
	if err2 := h.get(ctx, u, &issuances); err2 != nil {
		return nil, fmt.Errorf("crt.sh: %v; Cert Spotter: %v", err, err2)
	}
	var names []string
	for _, i := range issuances {
		names = append(names, i.DNSNames...)
	}
	return under(domain, names), nil
}

// under keeps the distinct names that are strict subdomains of domain, wildcards folded into their base.
func under(domain string, names []string) []string {
	suffix := "." + strings.ToLower(domain)
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(n), "*.")))
		if n == "" || seen[n] || !strings.HasSuffix(n, suffix) || strings.ContainsAny(n, " @*") {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Expiry returns when the registration of domain's registrable name ends.
func (h HTTP) Expiry(ctx context.Context, domain string) (time.Time, string, error) {
	reg, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return time.Time{}, "", err
	}
	var doc struct {
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
		Entities []struct {
			Roles      []string `json:"roles"`
			VCardArray []any    `json:"vcardArray"`
		} `json:"entities"`
	}
	if err := h.get(ctx, h.RDAPURL+"/domain/"+reg, &doc); err != nil {
		return time.Time{}, "", err
	}
	registrar := ""
	for _, e := range doc.Entities {
		for _, r := range e.Roles {
			if r == "registrar" {
				registrar = vcardName(e.VCardArray)
			}
		}
	}
	for _, e := range doc.Events {
		if e.Action == "expiration" {
			t, err := time.Parse(time.RFC3339, e.Date)
			return t, registrar, err
		}
	}
	return time.Time{}, registrar, fmt.Errorf("registry for %s does not publish an expiry date", reg)
}

// vcardName pulls "fn" out of a jCard array: ["vcard", [["fn", {}, "text", "Name"], ...]].
func vcardName(v []any) string {
	if len(v) < 2 {
		return ""
	}
	props, _ := v[1].([]any)
	for _, p := range props {
		arr, _ := p.([]any)
		if len(arr) >= 4 && arr[0] == "fn" {
			s, _ := arr[3].(string)
			return s
		}
	}
	return ""
}
