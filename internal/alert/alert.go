// Package alert sends events to Telegram, Slack and generic webhooks.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/z6il/perimeter/internal/store"
)

// Config holds where alerts go. Empty fields are skipped.
type Config struct {
	TelegramToken string
	TelegramChat  string
	SlackURL      string
	WebhookURL    string
	MinSeverity   store.Severity
	// PublicURL is the dashboard address used for links in messages.
	PublicURL string
}

// Enabled reports whether any destination is set.
func (c Config) Enabled() bool {
	return (c.TelegramToken != "" && c.TelegramChat != "") || c.SlackURL != "" || c.WebhookURL != ""
}

// Setting keys used to store the config.
const (
	KeyTelegramToken = "alert.telegram_token"
	KeyTelegramChat  = "alert.telegram_chat"
	KeySlackURL      = "alert.slack_url"
	KeyWebhookURL    = "alert.webhook_url"
	KeyMinSeverity   = "alert.min_severity"
	KeyPublicURL     = "public_url"
)

// Load reads the config from settings.
func Load(ctx context.Context, s *store.Store) Config {
	return Config{
		TelegramToken: s.Setting(ctx, KeyTelegramToken, ""),
		TelegramChat:  s.Setting(ctx, KeyTelegramChat, ""),
		SlackURL:      s.Setting(ctx, KeySlackURL, ""),
		WebhookURL:    s.Setting(ctx, KeyWebhookURL, ""),
		MinSeverity:   store.ParseSeverity(s.Setting(ctx, KeyMinSeverity, "medium")),
		PublicURL:     strings.TrimSuffix(s.Setting(ctx, KeyPublicURL, ""), "/"),
	}
}

// Sender delivers alerts. TelegramAPI can be pointed at a test server.
type Sender struct {
	Client      *http.Client
	TelegramAPI string
}

// NewSender returns a Sender with sensible timeouts.
func NewSender() *Sender {
	return &Sender{Client: &http.Client{Timeout: 15 * time.Second}, TelegramAPI: "https://api.telegram.org"}
}

var icons = map[store.Severity]string{
	store.Critical: "🟥", store.High: "🔴", store.Medium: "🟠", store.Low: "🔵", store.Info: "⚪",
}

// Send delivers e to every configured destination if it is severe enough. It returns every delivery error.
func (s *Sender) Send(ctx context.Context, c Config, e store.Event) error {
	if e.Severity < c.MinSeverity || !c.Enabled() {
		return nil
	}
	return s.deliver(ctx, c, e)
}

// Test sends a test message regardless of severity.
func (s *Sender) Test(ctx context.Context, c Config) error {
	if !c.Enabled() {
		return errors.New("no alert destination is configured")
	}
	return s.deliver(ctx, c, store.Event{Severity: store.Info, Title: "Test alert from Perimeter", Detail: "If you can read this, alerts work.", CreatedAt: time.Now()})
}

func (s *Sender) deliver(ctx context.Context, c Config, e store.Event) error {
	var errs []error
	link := ""
	if c.PublicURL != "" && e.AssetID != 0 {
		link = fmt.Sprintf("%s/assets/%d", c.PublicURL, e.AssetID)
	}
	if c.TelegramToken != "" && c.TelegramChat != "" {
		var b strings.Builder
		fmt.Fprintf(&b, "%s <b>%s</b>", icons[e.Severity], html.EscapeString(e.Title))
		if e.Asset != "" {
			fmt.Fprintf(&b, "\n<code>%s</code>", html.EscapeString(e.Asset))
		}
		if e.Detail != "" {
			fmt.Fprintf(&b, "\n%s", html.EscapeString(e.Detail))
		}
		if link != "" {
			fmt.Fprintf(&b, "\n<a href=\"%s\">Open in Perimeter</a>", html.EscapeString(link))
		}
		body := map[string]any{"chat_id": c.TelegramChat, "text": b.String(), "parse_mode": "HTML", "disable_web_page_preview": true}
		errs = append(errs, s.post(ctx, s.TelegramAPI+"/bot"+c.TelegramToken+"/sendMessage", body, "telegram"))
	}
	if c.SlackURL != "" {
		text := fmt.Sprintf("%s *%s*", icons[e.Severity], e.Title)
		if e.Asset != "" {
			text += " `" + e.Asset + "`"
		}
		if e.Detail != "" {
			text += "\n" + e.Detail
		}
		if link != "" {
			text += "\n<" + link + "|Open in Perimeter>"
		}
		errs = append(errs, s.post(ctx, c.SlackURL, map[string]any{"text": text}, "slack"))
	}
	if c.WebhookURL != "" {
		body := map[string]any{
			"severity": e.Severity.String(), "title": e.Title, "detail": e.Detail,
			"asset": e.Asset, "asset_id": e.AssetID, "time": e.CreatedAt.Format(time.RFC3339), "url": link,
		}
		errs = append(errs, s.post(ctx, c.WebhookURL, body, "webhook"))
	}
	return errors.Join(errs...)
}

func (s *Sender) post(ctx context.Context, url string, body any, name string) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Client.Do(req)
	if err != nil {
		// Don't leak the Telegram token, which is part of the URL, into logs.
		return fmt.Errorf("%s: request failed", name)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("%s: %s %s", name, resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}
