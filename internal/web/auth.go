package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/z6il/perimeter/internal/store"
)

const (
	keyPasswordHash = "auth.password_hash"
	cookieName      = "perimeter_session"
	sessionTTL      = 30 * 24 * time.Hour
)

// EnsurePassword sets the admin password from env when given; otherwise it creates one on first start
// and returns it so it can be printed once.
func EnsurePassword(ctx context.Context, s *store.Store, fromEnv string) (generated string, err error) {
	if fromEnv != "" {
		return "", SetPassword(ctx, s, fromEnv)
	}
	if s.Setting(ctx, keyPasswordHash, "") != "" {
		return "", nil
	}
	generated = randomString(18)
	return generated, SetPassword(ctx, s, generated)
}

// SetPassword stores a bcrypt hash of pw.
func SetPassword(ctx context.Context, s *store.Store, pw string) error {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.SetSetting(ctx, keyPasswordHash, string(h))
}

func randomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}

// sessions are kept in memory; a restart signs everyone out.
type sessions struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func (ss *sessions) create() string {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.m == nil {
		ss.m = map[string]time.Time{}
	}
	tok := randomString(32)
	ss.m[tok] = time.Now().Add(sessionTTL)
	return tok
}

func (ss *sessions) valid(tok string) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	exp, ok := ss.m[tok]
	if ok && time.Now().After(exp) {
		delete(ss.m, tok)
		return false
	}
	return ok
}

func (ss *sessions) drop(tok string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	delete(ss.m, tok)
}

// failures slows down password guessing per client address.
type failures struct {
	mu sync.Mutex
	m  map[string][]time.Time
}

func (f *failures) recent(addr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	cut := time.Now().Add(-15 * time.Minute)
	var keep []time.Time
	for _, t := range f.m[addr] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if f.m == nil {
		f.m = map[string][]time.Time{}
	}
	f.m[addr] = keep
	return len(keep)
}

func (f *failures) add(addr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.m == nil {
		f.m = map[string][]time.Time{}
	}
	f.m[addr] = append(f.m[addr], time.Now())
}

func clientAddr(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}

func secureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// sameOrigin rejects cross-site form posts. Browsers send Origin on POST; Referer is the fallback.
func sameOrigin(r *http.Request) bool {
	src := r.Header.Get("Origin")
	if src == "" || src == "null" {
		src = r.Header.Get("Referer")
	}
	if src == "" {
		return false
	}
	u, err := url.Parse(src)
	if err != nil {
		return false
	}
	host := r.Host
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
		host = fwd
	}
	return strings.EqualFold(u.Host, host)
}
