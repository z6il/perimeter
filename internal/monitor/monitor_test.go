package monitor

import (
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/z6il/perimeter/internal/alert"
	"github.com/z6il/perimeter/internal/check"
	"github.com/z6il/perimeter/internal/store"
)

func listener(t *testing.T) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { ln.Close() }
}

func TestPortsLifecycle(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	web, closeWeb := listener(t)
	db, closeDB := listener(t)
	defer closeDB()

	m := &Monitor{Store: st, Scanner: check.Scanner{Timeout: time.Second, Concurrency: 4}, Ports: []int{web, db},
		Alerts: alert.NewSender(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	now := time.Now()
	id, _ := st.AddAsset(ctx, store.Asset{Kind: store.IP, Value: "127.0.0.1", Token: "t", VerifiedAt: &now, VerifyMethod: "local", AllowedPorts: []int{web}})

	// First scan: the database port is unexpected.
	m.Run(ctx, id, true)
	fs, _ := st.Findings(ctx, id)
	if len(fs) != 1 || fs[0].Key == "" || portOf(fs[0].Key) != db {
		t.Fatalf("after first scan: %+v", fs)
	}

	// Allowing it resolves the finding without a scan.
	a, _ := st.Asset(ctx, id)
	a.AllowedPorts = append(a.AllowedPorts, db)
	st.SetAllowedPorts(ctx, id, a.AllowedPorts)
	if err := m.Reevaluate(ctx, a); err != nil {
		t.Fatal(err)
	}
	if fs, _ := st.Findings(ctx, id); len(fs) != 0 {
		t.Fatalf("after allow: %+v", fs)
	}

	// An allowed port that stops answering becomes a finding until it comes back.
	closeWeb()
	m.Run(ctx, id, true)
	fs, _ = st.Findings(ctx, id)
	if len(fs) != 1 || portOf(fs[0].Key) != web || fs[0].Severity != store.Medium {
		t.Fatalf("after service went down: %+v", fs)
	}
	m.Run(ctx, id, true)
	if fs, _ := st.Findings(ctx, id); len(fs) != 1 {
		t.Fatalf("down finding should persist while the port stays closed: %+v", fs)
	}

	events, _ := st.Events(ctx, id, 50)
	titles := map[string]bool{}
	for _, e := range events {
		titles[e.Title] = true
	}
	for _, want := range []string{"First port scan found 2 open ports", "Ports closed"} {
		if !titles[want] {
			t.Errorf("missing event %q in %v", want, titles)
		}
	}
}

func TestUnverifiedAssetIsNeverScanned(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "p.db"))
	defer st.Close()
	ctx := context.Background()
	port, closeIt := listener(t)
	defer closeIt()
	m := &Monitor{Store: st, Scanner: check.Scanner{Timeout: time.Second}, Ports: []int{port},
		Alerts: alert.NewSender(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	id, _ := st.AddAsset(ctx, store.Asset{Kind: store.IP, Value: "127.0.0.1", Token: "t"})
	m.Run(ctx, id, true)
	if ports, _ := st.Ports(ctx, id); len(ports) != 0 {
		t.Fatalf("scanned an unverified asset: %+v", ports)
	}
	if last, _, _ := st.LastRun(ctx, id, CheckPorts); !last.IsZero() {
		t.Error("port check ran on an unverified asset")
	}
}

func TestExpirySeverity(t *testing.T) {
	cases := []struct {
		days int
		want store.Severity
		ok   bool
	}{{-1, store.Critical, true}, {10, store.Critical, true}, {20, store.High, true}, {45, store.Medium, true}, {90, 0, false}}
	for _, c := range cases {
		got, ok := expirySeverity(c.days, 14, 30, 60)
		if got != c.want || ok != c.ok {
			t.Errorf("%d days: got %v %v", c.days, got, ok)
		}
	}
}
