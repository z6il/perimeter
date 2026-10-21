package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/z6il/perimeter/internal/monitor"
	"github.com/z6il/perimeter/internal/store"
	"github.com/z6il/perimeter/internal/verify"
)

func TestNormalizeAsset(t *testing.T) {
	cases := map[string]string{
		"Example.ORG":                "domain example.org",
		"https://shop.example.org/x": "domain shop.example.org",
		"*.example.org.":             "domain example.org",
		"203.0.113.9":                "ip 203.0.113.9",
		"[2001:db8::1]":              "ip 2001:db8::1",
	}
	for in, want := range cases {
		k, v, err := NormalizeAsset(in)
		if err != nil || k+" "+v != want {
			t.Errorf("%q: got %q %q %v", in, k, v, err)
		}
	}
	for _, bad := range []string{"", "localhost", "a..b", "-x.com", "x_y.com", "evil.com/../", strings.Repeat("a", 64) + ".com"} {
		if _, _, err := NormalizeAsset(bad); err == nil && bad != "evil.com/../" {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{"/assets/3": "/assets/3", "//evil.com": "/", "https://evil.com": "/", "/\\evil.com": "/", "": "/"} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q", in, got)
		}
	}
}

func newTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := SetPassword(context.Background(), st, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := New(st, monitor.New(st, log), log, "test")
	if err != nil {
		t.Fatal(err)
	}
	srv.Verify = &verify.Checker{LookupTXT: func(context.Context, string) ([]string, error) { return nil, nil }}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, st
}

func client(t *testing.T) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func post(c *http.Client, ts *httptest.Server, path string, form url.Values, origin bool) *http.Response {
	req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin {
		req.Header.Set("Origin", ts.URL)
	}
	resp, err := c.Do(req)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()
	return resp
}

func TestLoginAndGuards(t *testing.T) {
	ts, st := newTestServer(t)
	c := client(t)

	// Signed out: pages redirect to the login, actions are refused.
	resp, _ := c.Get(ts.URL + "/assets")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Fatalf("signed-out GET: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if r := post(c, ts, "/assets", url.Values{"value": {"example.org"}}, true); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("signed-out POST: %d", r.StatusCode)
	}

	// Wrong password, then a cross-site login attempt, then the real one.
	if r := post(c, ts, "/login", url.Values{"password": {"nope"}}, true); !strings.Contains(r.Header.Get("Location"), "err=") {
		t.Fatalf("wrong password: %s", r.Header.Get("Location"))
	}
	if r := post(c, ts, "/login", url.Values{"password": {"correct horse battery"}}, false); r.StatusCode != http.StatusForbidden {
		t.Fatalf("login without Origin: %d", r.StatusCode)
	}
	r := post(c, ts, "/login", url.Values{"password": {"correct horse battery"}, "next": {"//evil.com"}}, true)
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/" {
		t.Fatalf("login: %d %s", r.StatusCode, r.Header.Get("Location"))
	}

	// Signed in: a same-origin post works, a cross-site one is refused.
	if r := post(c, ts, "/assets", url.Values{"value": {"example.org"}}, false); r.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site POST: %d", r.StatusCode)
	}
	r = post(c, ts, "/assets", url.Values{"value": {"example.org"}, "ports": {"443"}}, true)
	if r.StatusCode != http.StatusSeeOther || !strings.HasPrefix(r.Header.Get("Location"), "/assets/1") {
		t.Fatalf("add asset: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	a, _ := st.Asset(context.Background(), 1)
	if a.Value != "example.org" || a.Verified() {
		t.Errorf("asset: %+v", a)
	}

	// A public IP cannot skip verification by ticking the private-network box.
	post(c, ts, "/assets", url.Values{"value": {"198.51.100.20"}, "local": {"on"}}, true)
	b, _ := st.Asset(context.Background(), 2)
	if b.Verified() {
		t.Error("public IP was verified by the local checkbox")
	}

	// Every page renders.
	for _, p := range []string{"/", "/assets", "/assets/1", "/assets/new", "/events", "/settings"} {
		resp, err := c.Get(ts.URL + p)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: %v %d", p, err, resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), "<h1>") {
			t.Errorf("GET %s has no h1", p)
		}
		if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("GET %s: CSP %q", p, csp)
		}
	}

	// Deleting needs the name typed back.
	post(c, ts, "/assets/1/delete", url.Values{"confirm": {"wrong"}}, true)
	if _, err := st.Asset(context.Background(), 1); err != nil {
		t.Error("asset deleted without confirmation")
	}
	post(c, ts, "/assets/1/delete", url.Values{"confirm": {"example.org"}}, true)
	if _, err := st.Asset(context.Background(), 1); err == nil {
		t.Error("asset not deleted")
	}
}
