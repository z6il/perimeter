// Package verify proves that the person adding an asset controls it before any active scan runs.
package verify

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Methods recorded when an asset is verified.
const (
	MethodDNS    = "dns"
	MethodFile   = "file"
	MethodLocal  = "local"
	MethodParent = "parent"
)

// FilePath is where the verification file must be served on an IP.
const FilePath = "/.well-known/perimeter-verify.txt"

// NewToken returns a random verification token.
func NewToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "perimeter-verify=" + hex.EncodeToString(b)
}

// TXTName is the record name checked for a domain, in addition to the domain itself.
func TXTName(domain string) string { return "_perimeter." + domain }

// Checker verifies ownership. Its fields can be replaced in tests.
type Checker struct {
	LookupTXT func(ctx context.Context, name string) ([]string, error)
	Client    *http.Client
}

// New returns a Checker using the system resolver and a short-timeout HTTP client.
func New() *Checker {
	return &Checker{
		LookupTXT: net.DefaultResolver.LookupTXT,
		Client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				// The file proves control of the host; the certificate on a bare IP is rarely valid.
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// Domain checks for the token in a TXT record on _perimeter.<domain> or on the domain itself.
func (c *Checker) Domain(ctx context.Context, domain, token string) error {
	for _, name := range []string{TXTName(domain), domain} {
		recs, err := c.LookupTXT(ctx, name)
		if err != nil {
			continue
		}
		for _, r := range recs {
			if strings.TrimSpace(r) == token {
				return nil
			}
		}
	}
	return fmt.Errorf("no TXT record %q found on %s or %s yet (DNS changes can take a few minutes)", token, TXTName(domain), domain)
}

// IP checks that http(s)://<ip>/.well-known/perimeter-verify.txt contains the token.
func (c *Checker) IP(ctx context.Context, ip, token string) error {
	host := ip
	if strings.Contains(ip, ":") {
		host = "[" + ip + "]"
	}
	var lastErr error
	for _, scheme := range []string{"http", "https"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+host+FilePath, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "Perimeter ownership check (+https://github.com/z6il/perimeter)")
		resp, err := c.Client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && strings.Contains(string(body), token) {
			return nil
		}
		lastErr = fmt.Errorf("%s returned %d without the token", scheme, resp.StatusCode)
	}
	return fmt.Errorf("could not find the token at %s on %s: %v", FilePath, ip, lastErr)
}

// Private reports whether ip is loopback, link-local or in a private range. Such addresses are
// on the operator's own network, so they can be confirmed without a token.
func Private(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && (p.IsLoopback() || p.IsPrivate() || p.IsLinkLocalUnicast())
}
