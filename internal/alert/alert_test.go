package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/z6il/perimeter/internal/store"
)

func TestSend(t *testing.T) {
	var mu sync.Mutex
	got := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got[r.URL.Path] = string(b)
		mu.Unlock()
	}))
	defer srv.Close()

	s := &Sender{Client: srv.Client(), TelegramAPI: srv.URL}
	c := Config{TelegramToken: "123:abc", TelegramChat: "-100", SlackURL: srv.URL + "/slack", WebhookURL: srv.URL + "/hook",
		MinSeverity: store.Medium, PublicURL: "https://perimeter.local"}
	e := store.Event{AssetID: 3, Asset: "api.example.org", Severity: store.High, Title: "Unexpected open port 3306 (MySQL)", Detail: "a <b>tag</b>"}

	if err := s.Send(context.Background(), c, e); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got["/bot123:abc/sendMessage"], "Unexpected open port 3306") ||
		!strings.Contains(got["/bot123:abc/sendMessage"], "\\u0026lt;b\\u0026gt;tag") {
		t.Errorf("telegram body (detail must be HTML-escaped): %s", got["/bot123:abc/sendMessage"])
	}
	if !strings.Contains(got["/slack"], "perimeter.local/assets/3") {
		t.Errorf("slack body: %s", got["/slack"])
	}
	var hook map[string]any
	json.Unmarshal([]byte(got["/hook"]), &hook)
	if hook["severity"] != "high" || hook["asset"] != "api.example.org" {
		t.Errorf("webhook body: %v", hook)
	}

	// Below the minimum: nothing is sent.
	got = map[string]string{}
	s.Send(context.Background(), c, store.Event{Severity: store.Low, Title: "Ports opened"})
	if len(got) != 0 {
		t.Errorf("low event was sent: %v", got)
	}
}

func TestErrorsDoNotLeakToken(t *testing.T) {
	s := &Sender{Client: http.DefaultClient, TelegramAPI: "http://127.0.0.1:1"}
	err := s.Test(context.Background(), Config{TelegramToken: "SECRET-TOKEN", TelegramChat: "1"})
	if err == nil || strings.Contains(err.Error(), "SECRET-TOKEN") {
		t.Errorf("error %v", err)
	}
}
