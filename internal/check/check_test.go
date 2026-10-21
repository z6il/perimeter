package check

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func listen(t *testing.T, greeting string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte(greeting))
			time.AfterFunc(time.Second, func() { c.Close() })
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestScan(t *testing.T) {
	ssh := listen(t, "SSH-2.0-OpenSSH_9.6\r\n")
	mysql := listen(t, "\x4a\x00\x00\x00\x0a8.0.39\x00rest")
	closed := func() int { // a port that was free a moment ago
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		p := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		return p
	}()
	s := Scanner{Timeout: time.Second, Concurrency: 4}
	open := s.Scan(context.Background(), "127.0.0.1", []int{closed, mysql, ssh})
	if len(open) != 2 {
		t.Fatalf("open: %+v", open)
	}
	got := map[int]string{}
	for _, o := range open {
		got[o.Port] = o.Banner
	}
	if got[ssh] != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("ssh banner %q", got[ssh])
	}
	if got[mysql] != "MySQL 8.0.39" {
		t.Errorf("mysql banner %q", got[mysql])
	}
}

func TestTLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// With the system roots the test certificate is untrusted.
	res, err := TLSChecker{}.CheckTLS(context.Background(), host, port, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) != 1 || !strings.Contains(res.Problems[0], "not trusted") {
		t.Errorf("problems: %v", res.Problems)
	}
	if res.Version != "TLS 1.3" || res.NotAfter.IsZero() {
		t.Errorf("result: %+v", res)
	}

	// Trusting its certificate clears that, and the TLS 1.2 minimum means no old-protocol finding.
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	res, _ = TLSChecker{Roots: roots}.CheckTLS(context.Background(), host, port, "")
	if len(res.Problems) != 0 {
		t.Errorf("trusted server still has problems: %v", res.Problems)
	}
	// A name the certificate doesn't cover is reported.
	res, _ = TLSChecker{Roots: roots}.CheckTLS(context.Background(), host, port, "shop.example.org")
	if !strings.Contains(strings.Join(res.Problems, ";"), "does not cover") {
		t.Errorf("name mismatch not reported: %v", res.Problems)
	}
}

func TestSubdomainsFallback(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "busy", http.StatusBadGateway) })
	mux.HandleFunc("/v1/issuances", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"dns_names":["*.example.org","example.org","api.example.org"]},{"dns_names":["API.example.org","mail.example.org","evil.com"]}]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	h := HTTP{Client: srv.Client(), CTURL: srv.URL, CertSpotterURL: srv.URL}
	names, err := h.Subdomains(context.Background(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(names, ",") != "api.example.org,mail.example.org" {
		t.Errorf("names: %v", names)
	}
}

func TestSubdomainsCrtSh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"name_value":"vpn.example.org\n*.dev.example.org"},{"name_value":"example.org"}]`))
	}))
	defer srv.Close()
	names, err := HTTP{Client: srv.Client(), CTURL: srv.URL}.Subdomains(context.Background(), "example.org")
	if err != nil || strings.Join(names, ",") != "dev.example.org,vpn.example.org" {
		t.Errorf("names: %v, %v", names, err)
	}
}

func TestExpiry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/domain/example.org" {
			t.Errorf("asked for %s, want the registrable domain", r.URL.Path)
		}
		w.Write([]byte(`{"events":[{"eventAction":"registration","eventDate":"2020-01-02T00:00:00Z"},{"eventAction":"expiration","eventDate":"2027-03-04T05:06:07Z"}],
			"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Registrar"]]]}]}`))
	}))
	defer srv.Close()
	exp, registrar, err := HTTP{Client: srv.Client(), RDAPURL: srv.URL}.Expiry(context.Background(), "shop.example.org")
	if err != nil {
		t.Fatal(err)
	}
	if exp.Year() != 2027 || registrar != "Example Registrar" {
		t.Errorf("got %v %q", exp, registrar)
	}
}

type fakeResolver struct{}

func (fakeResolver) LookupHost(context.Context, string) ([]string, error) {
	return []string{"203.0.113.5", "2001:db8::5"}, nil
}
func (fakeResolver) LookupCNAME(_ context.Context, h string) (string, error) { return h + ".", nil }
func (fakeResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	return []*net.MX{{Host: "mx.example.org.", Pref: 10}}, nil
}
func (fakeResolver) LookupNS(context.Context, string) ([]*net.NS, error) {
	return []*net.NS{{Host: "NS1.Example.net."}}, nil
}
func (fakeResolver) LookupTXT(context.Context, string) ([]string, error) {
	return []string{"v=spf1 -all", "perimeter-verify=abc"}, nil
}

func TestDNSSnapshotAndDiff(t *testing.T) {
	got, err := DNSSnapshot(context.Background(), fakeResolver{}, "example.org")
	if err != nil {
		t.Fatal(err)
	}
	want := "A 203.0.113.5|AAAA 2001:db8::5|MX mx.example.org|NS ns1.example.net|TXT v=spf1 -all"
	if strings.Join(got, "|") != want {
		t.Errorf("snapshot:\n got %s\nwant %s", strings.Join(got, "|"), want)
	}
	added, removed := Diff([]string{"A 1.1.1.1", "MX a"}, []string{"A 2.2.2.2", "MX a"})
	if strings.Join(added, ",") != "A 2.2.2.2" || strings.Join(removed, ",") != "A 1.1.1.1" {
		t.Errorf("diff: %v %v", added, removed)
	}
}

func TestPortSeverity(t *testing.T) {
	if PortSeverity(6379) <= PortSeverity(3306) || PortSeverity(3306) <= PortSeverity(8081) {
		t.Error("Redis should outrank MySQL, which should outrank an unknown web port")
	}
}
