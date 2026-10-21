// Package web serves the dashboard.
package web

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/z6il/perimeter/internal/alert"
	"github.com/z6il/perimeter/internal/monitor"
	"github.com/z6il/perimeter/internal/store"
	"github.com/z6il/perimeter/internal/verify"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// Server is the dashboard.
type Server struct {
	Store   *store.Store
	Monitor *monitor.Monitor
	Verify  *verify.Checker
	Log     *slog.Logger
	Version string

	pages    map[string]*template.Template
	sessions sessions
	failed   failures
}

// New parses templates and returns a ready Server.
func New(s *store.Store, m *monitor.Monitor, log *slog.Logger, version string) (*Server, error) {
	srv := &Server{Store: s, Monitor: m, Verify: verify.New(), Log: log, Version: version, pages: map[string]*template.Template{}}
	for _, name := range []string{"overview", "assets", "asset", "new", "events", "settings"} {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", name, err)
		}
		srv.pages[name] = t
	}
	t, err := template.New("login.html").Funcs(funcs).ParseFS(templateFS, "templates/login.html")
	if err != nil {
		return nil, err
	}
	srv.pages["login"] = t
	return srv, nil
}

// Handler returns the HTTP handler with every route.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheForever(http.FileServerFS(static))))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.auth(s.logout))

	mux.HandleFunc("GET /{$}", s.auth(s.overview))
	mux.HandleFunc("GET /assets", s.auth(s.assetsPage))
	mux.HandleFunc("GET /assets/new", s.auth(s.newPage))
	mux.HandleFunc("POST /assets", s.auth(s.createAsset))
	mux.HandleFunc("GET /assets/{id}", s.auth(s.assetPage))
	mux.HandleFunc("POST /assets/{id}/verify", s.auth(s.verifyAsset))
	mux.HandleFunc("POST /assets/{id}/scan", s.auth(s.scanAsset))
	mux.HandleFunc("POST /assets/{id}/allow", s.auth(s.allowPort))
	mux.HandleFunc("POST /assets/{id}/ports", s.auth(s.setPorts))
	mux.HandleFunc("POST /assets/{id}/watch", s.auth(s.watchSubdomain))
	mux.HandleFunc("POST /assets/{id}/delete", s.auth(s.deleteAsset))
	mux.HandleFunc("POST /scan", s.auth(s.scanAll))
	mux.HandleFunc("GET /events", s.auth(s.eventsPage))
	mux.HandleFunc("GET /settings", s.auth(s.settingsPage))
	mux.HandleFunc("POST /settings/alerts", s.auth(s.saveAlerts))
	mux.HandleFunc("POST /settings/test", s.auth(s.testAlert))
	mux.HandleFunc("POST /settings/password", s.auth(s.changePassword))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; style-src-attr 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func cacheForever(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		next.ServeHTTP(w, r)
	})
}

// auth requires a session, and a same-origin request for anything that changes state.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil || !s.sessions.valid(c.Value) {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
				return
			}
			http.Error(w, "sign in first", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && !sameOrigin(r) {
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// page is the data every template gets.
type page struct {
	Title   string
	Nav     string
	Flash   string
	Error   string
	Version string
	Data    any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name, title, nav string, data any) {
	p := page{Title: title, Nav: nav, Version: s.Version, Data: data,
		Flash: r.URL.Query().Get("ok"), Error: r.URL.Query().Get("err")}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.pages[name].Execute(w, p); err != nil {
		s.Log.Error("render", "page", name, "err", err)
	}
}

// back redirects to path with a one-line message.
func back(w http.ResponseWriter, r *http.Request, path, okMsg string, err error) {
	q := url.Values{}
	if err != nil {
		q.Set("err", err.Error())
	} else if okMsg != "" {
		q.Set("ok", okMsg)
	}
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "login", "Sign in", "", map[string]string{"Next": safeNext(r.URL.Query().Get("next"))})
}

func safeNext(n string) string {
	if !strings.HasPrefix(n, "/") || strings.HasPrefix(n, "//") || strings.HasPrefix(n, "/\\") {
		return "/"
	}
	return n
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return
	}
	addr := clientAddr(r)
	next := safeNext(r.FormValue("next"))
	if s.failed.recent(addr) >= 10 {
		back(w, r, "/login?next="+url.QueryEscape(next), "", errors.New("too many attempts, try again in 15 minutes"))
		return
	}
	hash := s.Store.Setting(r.Context(), keyPasswordHash, "")
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(r.FormValue("password"))) != nil {
		s.failed.add(addr)
		time.Sleep(700 * time.Millisecond)
		http.Redirect(w, r, "/login?err="+url.QueryEscape("Wrong password")+"&next="+url.QueryEscape(next), http.StatusSeeOther)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.sessions.create(), Path: "/", HttpOnly: true,
		Secure: secureRequest(r), SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.sessions.drop(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func idOf(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id
}

// runInBackground starts checks for an asset without tying them to the request.
func (s *Server) runInBackground(id int64) {
	go s.Monitor.Run(context.Background(), id, true)
}

// NormalizeAsset turns user input into an asset kind and value, rejecting anything that isn't a
// plain domain or IP address.
func NormalizeAsset(in string) (kind, value string, err error) {
	v := strings.ToLower(strings.TrimSpace(in))
	if u, err := url.Parse(v); err == nil && u.Host != "" {
		v = u.Hostname()
	}
	v = strings.TrimSuffix(strings.TrimPrefix(v, "*."), ".")
	if ip := net.ParseIP(strings.Trim(v, "[]")); ip != nil {
		return store.IP, ip.String(), nil
	}
	if len(v) == 0 || len(v) > 253 || !strings.Contains(v, ".") {
		return "", "", fmt.Errorf("%q is not a domain or IP address", in)
	}
	for _, label := range strings.Split(v, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", "", fmt.Errorf("%q is not a valid domain", in)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", "", fmt.Errorf("%q is not a valid domain", in)
			}
		}
	}
	return store.Domain, v, nil
}

func (s *Server) createAsset(w http.ResponseWriter, r *http.Request) {
	kind, value, err := NormalizeAsset(r.FormValue("value"))
	if err != nil {
		back(w, r, "/assets/new", "", err)
		return
	}
	a := store.Asset{Kind: kind, Value: value, Token: verify.NewToken(), AllowedPorts: store.ParsePorts(r.FormValue("ports"))}
	if kind == store.IP && verify.Private(value) && r.FormValue("local") == "on" {
		now := time.Now().UTC()
		a.VerifiedAt, a.VerifyMethod = &now, verify.MethodLocal
	}
	id, err := s.Store.AddAsset(r.Context(), a)
	if err != nil {
		back(w, r, "/assets/new", "", err)
		return
	}
	s.Store.AddEvent(r.Context(), store.Event{AssetID: id, Severity: store.Info, Title: "Started watching " + value})
	s.runInBackground(id)
	back(w, r, fmt.Sprintf("/assets/%d", id), "Added. Passive checks are running now.", nil)
}

func (s *Server) verifyAsset(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	a, err := s.Store.Asset(ctx, idOf(r))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	path := fmt.Sprintf("/assets/%d", a.ID)
	var method string
	switch {
	case a.Kind == store.Domain:
		err, method = s.Verify.Domain(ctx, a.Value, a.Token), verify.MethodDNS
	case r.FormValue("local") == "on" && verify.Private(a.Value):
		err, method = nil, verify.MethodLocal
	default:
		err, method = s.Verify.IP(ctx, a.Value, a.Token), verify.MethodFile
	}
	if err != nil {
		back(w, r, path, "", err)
		return
	}
	s.Store.MarkVerified(ctx, a.ID, method)
	s.Store.AddEvent(ctx, store.Event{AssetID: a.ID, Severity: store.Info, Title: "Ownership verified (" + method + ")", Detail: "Port scans are now enabled."})
	s.runInBackground(a.ID)
	back(w, r, path, "Verified. The first port scan has started.", nil)
}

func (s *Server) scanAsset(w http.ResponseWriter, r *http.Request) {
	id := idOf(r)
	if _, err := s.Store.Asset(r.Context(), id); err != nil {
		http.NotFound(w, r)
		return
	}
	s.runInBackground(id)
	back(w, r, fmt.Sprintf("/assets/%d", id), "Checks started. Refresh in a minute.", nil)
}

func (s *Server) scanAll(w http.ResponseWriter, r *http.Request) {
	assets, _ := s.Store.Assets(r.Context())
	go func() {
		for _, a := range assets {
			s.Monitor.Run(context.Background(), a.ID, true)
		}
	}()
	back(w, r, "/", fmt.Sprintf("Checking %d assets now.", len(assets)), nil)
}

func (s *Server) allowPort(w http.ResponseWriter, r *http.Request) {
	a, err := s.Store.Asset(r.Context(), idOf(r))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	port, _ := strconv.Atoi(r.FormValue("port"))
	if port <= 0 || port > 65535 {
		back(w, r, safeNext(r.FormValue("back")), "", errors.New("invalid port"))
		return
	}
	ports := append(a.AllowedPorts, port)
	if err := s.Store.SetAllowedPorts(r.Context(), a.ID, store.ParsePorts(store.FormatPorts(ports))); err != nil {
		back(w, r, safeNext(r.FormValue("back")), "", err)
		return
	}
	a.AllowedPorts = store.ParsePorts(store.FormatPorts(ports))
	err = s.Monitor.Reevaluate(r.Context(), a)
	back(w, r, safeNext(r.FormValue("back")), fmt.Sprintf("Port %d is now allowed on %s.", port, a.Value), err)
}

func (s *Server) setPorts(w http.ResponseWriter, r *http.Request) {
	a, err := s.Store.Asset(r.Context(), idOf(r))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	a.AllowedPorts = store.ParsePorts(r.FormValue("ports"))
	if err := s.Store.SetAllowedPorts(r.Context(), a.ID, a.AllowedPorts); err != nil {
		back(w, r, fmt.Sprintf("/assets/%d", a.ID), "", err)
		return
	}
	err = s.Monitor.Reevaluate(r.Context(), a)
	back(w, r, fmt.Sprintf("/assets/%d", a.ID), "Allowlist saved.", err)
}

func (s *Server) watchSubdomain(w http.ResponseWriter, r *http.Request) {
	parent, err := s.Store.Asset(r.Context(), idOf(r))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	name := strings.ToLower(strings.TrimSpace(r.FormValue("name")))
	if !strings.HasSuffix(name, "."+parent.Value) {
		back(w, r, fmt.Sprintf("/assets/%d", parent.ID), "", fmt.Errorf("%s is not under %s", name, parent.Value))
		return
	}
	a := store.Asset{Kind: store.Domain, Value: name, Token: verify.NewToken(), ParentID: &parent.ID, AllowedPorts: parent.AllowedPorts}
	hosted := ""
	if cname, err := net.DefaultResolver.LookupCNAME(r.Context(), name); err == nil {
		cname = strings.TrimSuffix(strings.ToLower(cname), ".")
		if cname != name && cname != parent.Value && !strings.HasSuffix(cname, "."+parent.Value) {
			hosted = cname
		}
	}
	if parent.Verified() && hosted == "" {
		// Control of the parent domain's DNS proves control of names that resolve to its own servers.
		now := time.Now().UTC()
		a.VerifiedAt, a.VerifyMethod = &now, verify.MethodParent
	}
	id, err := s.Store.AddAsset(r.Context(), a)
	if err != nil {
		back(w, r, fmt.Sprintf("/assets/%d", parent.ID), "", err)
		return
	}
	s.Store.AddEvent(r.Context(), store.Event{AssetID: id, Severity: store.Info, Title: "Started watching " + name})
	s.runInBackground(id)
	msg := "Now watching " + name + "."
	if hosted != "" {
		msg += " It points to " + hosted + ", a server you may not run, so port scans stay off until you verify it yourself."
	}
	back(w, r, fmt.Sprintf("/assets/%d", id), msg, nil)
}

func (s *Server) deleteAsset(w http.ResponseWriter, r *http.Request) {
	a, err := s.Store.Asset(r.Context(), idOf(r))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if r.FormValue("confirm") != a.Value {
		back(w, r, fmt.Sprintf("/assets/%d", a.ID), "", fmt.Errorf("type %s to confirm", a.Value))
		return
	}
	if err := s.Store.DeleteAsset(r.Context(), a.ID); err != nil {
		back(w, r, fmt.Sprintf("/assets/%d", a.ID), "", err)
		return
	}
	back(w, r, "/assets", "Stopped watching "+a.Value+". Its history was removed.", nil)
}

func (s *Server) saveAlerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	for key, field := range map[string]string{
		alert.KeyTelegramChat: "telegram_chat", alert.KeySlackURL: "slack_url",
		alert.KeyWebhookURL: "webhook_url", alert.KeyMinSeverity: "min_severity", alert.KeyPublicURL: "public_url",
	} {
		s.Store.SetSetting(ctx, key, strings.TrimSpace(r.FormValue(field)))
	}
	// The token field is left blank in the form; only overwrite it when a new one is typed.
	if t := strings.TrimSpace(r.FormValue("telegram_token")); t != "" {
		s.Store.SetSetting(ctx, alert.KeyTelegramToken, t)
	}
	if r.FormValue("telegram_clear") == "on" {
		s.Store.SetSetting(ctx, alert.KeyTelegramToken, "")
	}
	back(w, r, "/settings", "Alert settings saved.", nil)
}

func (s *Server) testAlert(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	err := s.Monitor.Alerts.Test(ctx, alert.Load(ctx, s.Store))
	back(w, r, "/settings", "Test alert sent.", err)
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hash := s.Store.Setting(ctx, keyPasswordHash, "")
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(r.FormValue("current"))) != nil {
		back(w, r, "/settings", "", errors.New("the current password is wrong"))
		return
	}
	if len(r.FormValue("new")) < 12 {
		back(w, r, "/settings", "", errors.New("use at least 12 characters"))
		return
	}
	back(w, r, "/settings", "Password changed.", SetPassword(ctx, s.Store, r.FormValue("new")))
}
