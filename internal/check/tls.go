package check

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// TLSResult describes the certificate and protocol on one endpoint.
type TLSResult struct {
	Subject  string
	Issuer   string
	NotAfter time.Time
	Version  string
	// Problems are human-readable issues: an untrusted chain, a wrong name, old protocols.
	Problems []string
}

// TLSChecker connects to endpoints and inspects their certificates.
type TLSChecker struct {
	Timeout time.Duration
	// Roots overrides the system roots (used in tests).
	Roots *x509.CertPool
}

// CheckTLS connects to host:port. serverName is used for SNI and name checks; leave it empty for bare IPs.
func (c TLSChecker) CheckTLS(ctx context.Context, host string, port int, serverName string) (TLSResult, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 8 * time.Second
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config:    &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return TLSResult{}, err
	}
	state := conn.(*tls.Conn).ConnectionState()
	conn.Close()
	if len(state.PeerCertificates) == 0 {
		return TLSResult{}, fmt.Errorf("no certificate presented")
	}
	leaf := state.PeerCertificates[0]
	res := TLSResult{
		Subject:  leaf.Subject.CommonName,
		Issuer:   firstNonEmpty(leaf.Issuer.CommonName, strings.Join(leaf.Issuer.Organization, ", ")),
		NotAfter: leaf.NotAfter,
		Version:  tls.VersionName(state.Version),
	}
	if res.Subject == "" && len(leaf.DNSNames) > 0 {
		res.Subject = leaf.DNSNames[0]
	}

	inter := x509.NewCertPool()
	for _, ic := range state.PeerCertificates[1:] {
		inter.AddCert(ic)
	}
	opts := x509.VerifyOptions{Roots: c.Roots, Intermediates: inter, CurrentTime: time.Now()}
	if _, err := leaf.Verify(opts); err != nil {
		res.Problems = append(res.Problems, "certificate is not trusted ("+trustReason(err)+")")
	}
	if serverName != "" {
		if err := leaf.VerifyHostname(serverName); err != nil {
			res.Problems = append(res.Problems, "certificate does not cover "+serverName)
		}
	}

	// Old protocol versions: try a handshake capped at TLS 1.1.
	old := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{ServerName: serverName, InsecureSkipVerify: true,
			MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11},
	}
	if oc, err := old.DialContext(ctx, "tcp", addr); err == nil {
		v := tls.VersionName(oc.(*tls.Conn).ConnectionState().Version)
		oc.Close()
		res.Problems = append(res.Problems, "still accepts "+v)
	}
	return res, nil
}

// trustReason turns an x509 verification error into a few plain words.
func trustReason(err error) string {
	var ua x509.UnknownAuthorityError
	var ci x509.CertificateInvalidError
	switch {
	case errors.As(err, &ua):
		return "self-signed or from a private CA"
	case errors.As(err, &ci) && ci.Reason == x509.Expired:
		return "expired or not yet valid"
	}
	s := err.Error()
	if i := strings.Index(s, ": "); i > 0 && strings.HasPrefix(s, "x509") {
		s = s[i+2:]
	}
	return s
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
