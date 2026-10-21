package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestParsePorts(t *testing.T) {
	got := FormatPorts(ParsePorts("443, 22;80 80 x 70000 -1"))
	if got != "22, 80, 443" {
		t.Errorf("got %q", got)
	}
}

func TestAssetsAndReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	id, err := s.AddAsset(ctx, Asset{Kind: Domain, Value: "shop.example.org", Token: "t", AllowedPorts: []int{443}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddAsset(ctx, Asset{Kind: Domain, Value: "shop.example.org", Token: "t"}); err == nil {
		t.Error("duplicate asset accepted")
	}
	s.MarkVerified(ctx, id, "dns")
	s.Close()

	// Migrations must be idempotent across restarts.
	s, err = Open(filepath.Join(dir, "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, err := s.Asset(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Verified() || a.VerifyMethod != "dns" || !a.Allowed(443) || a.Allowed(22) {
		t.Errorf("asset not round-tripped: %+v", a)
	}
}

func TestSyncFindings(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	id, _ := s.AddAsset(ctx, Asset{Kind: IP, Value: "198.51.100.7", Token: "t"})

	f := func(key string, sev Severity) Finding { return Finding{Key: key, Severity: sev, Title: key} }
	added, resolved, err := s.SyncFindings(ctx, id, "port:", []Finding{f("port:a:22", High), f("port:a:23", Critical)})
	if err != nil || len(added) != 2 || len(resolved) != 0 {
		t.Fatalf("first sync: %d added, %d resolved, %v", len(added), len(resolved), err)
	}
	// Same findings again: nothing new.
	added, resolved, _ = s.SyncFindings(ctx, id, "port:", []Finding{f("port:a:22", High), f("port:a:23", Critical)})
	if len(added)+len(resolved) != 0 {
		t.Fatalf("repeat sync reported %d added, %d resolved", len(added), len(resolved))
	}
	// One goes away; another prefix is untouched.
	s.SyncFindings(ctx, id, "tls:", []Finding{f("tls:a:443:expiry", Medium)})
	added, resolved, _ = s.SyncFindings(ctx, id, "port:", []Finding{f("port:a:22", High)})
	if len(added) != 0 || len(resolved) != 1 || resolved[0].Key != "port:a:23" {
		t.Fatalf("resolve: %+v %+v", added, resolved)
	}
	// Getting worse counts as new.
	added, _, _ = s.SyncFindings(ctx, id, "tls:", []Finding{f("tls:a:443:expiry", High)})
	if len(added) != 1 {
		t.Errorf("worsening not reported")
	}
	all, _ := s.Findings(ctx, id)
	if len(all) != 2 || all[0].Severity != High {
		t.Errorf("findings: %+v", all)
	}
}

func TestReplacePortsKeepsFirstSeen(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	id, _ := s.AddAsset(ctx, Asset{Kind: IP, Value: "198.51.100.8", Token: "t"})
	s.ReplacePorts(ctx, id, "198.51.100.8", []Port{{Port: 22}, {Port: 80}})
	before, _ := s.Ports(ctx, id)
	time.Sleep(20 * time.Millisecond)
	s.ReplacePorts(ctx, id, "198.51.100.8", []Port{{Port: 22, Banner: "SSH-2.0"}})
	after, _ := s.Ports(ctx, id)
	if len(after) != 1 || after[0].Port != 22 || after[0].Banner != "SSH-2.0" {
		t.Fatalf("after: %+v", after)
	}
	if !after[0].FirstSeen.Equal(before[0].FirstSeen) {
		t.Errorf("first_seen changed: %v → %v", before[0].FirstSeen, after[0].FirstSeen)
	}
	if s.LatestRun(ctx).IsZero() == false {
		t.Error("no runs yet, LatestRun should be zero")
	}
	s.RecordRun(ctx, id, "ports", nil)
	if s.LatestRun(ctx).IsZero() {
		t.Error("LatestRun did not read back the run")
	}
}
