// Package check runs the individual checks: ports, TLS, DNS, certificate transparency and domain expiry.
package check

import (
	"bufio"
	"context"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CommonPorts are the TCP ports scanned by default: the services most often exposed by mistake.
var CommonPorts = []int{
	21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 514, 587, 631, 636,
	873, 993, 995, 1080, 1194, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2181, 2222, 2375, 2376,
	2379, 3000, 3001, 3128, 3306, 3389, 4000, 4369, 4443, 4848, 5000, 5001, 5005, 5060, 5432, 5601, 5672,
	5900, 5984, 5985, 5986, 6000, 6379, 6443, 6667, 7001, 7474, 7687, 8000, 8008, 8080, 8081, 8086, 8088,
	8089, 8161, 8200, 8443, 8500, 8834, 8880, 8888, 9000, 9001, 9042, 9090, 9092, 9100, 9200, 9300, 9418,
	9443, 9999, 10000, 10250, 11211, 15672, 25565, 27017, 28017, 32400, 50000,
}

// Open is one open TCP port.
type Open struct {
	Port   int
	Banner string
}

// Scanner does TCP connect scans. Connect scans need no special privileges.
type Scanner struct {
	Timeout     time.Duration
	Concurrency int
	// Delay between connection attempts, to stay polite to the target.
	Delay time.Duration
}

// DefaultScanner is gentle enough to run against production hosts.
var DefaultScanner = Scanner{Timeout: 2 * time.Second, Concurrency: 32, Delay: 5 * time.Millisecond}

// Scan connects to each port on host and returns the open ones, sorted.
func (s Scanner) Scan(ctx context.Context, host string, ports []int) []Open {
	var (
		mu   sync.Mutex
		out  []Open
		wg   sync.WaitGroup
		sema = make(chan struct{}, max(1, s.Concurrency))
	)
	for _, p := range ports {
		if ctx.Err() != nil {
			break
		}
		sema <- struct{}{}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			defer func() { <-sema }()
			if o, ok := s.probe(ctx, host, port); ok {
				mu.Lock()
				out = append(out, o)
				mu.Unlock()
			}
		}(p)
		if s.Delay > 0 {
			time.Sleep(s.Delay)
		}
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

func (s Scanner) probe(ctx context.Context, host string, port int) (Open, bool) {
	d := net.Dialer{Timeout: s.Timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return Open{}, false
	}
	defer conn.Close()
	return Open{Port: port, Banner: banner(conn, host, port)}, true
}

var httpish = map[int]bool{80: true, 81: true, 3000: true, 3001: true, 5000: true, 8000: true, 8008: true, 8080: true, 8081: true, 8088: true, 8888: true, 9000: true}

// banner reads what a service says first, or asks HTTP services for their Server header.
func banner(conn net.Conn, host string, port int) string {
	conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	r := bufio.NewReader(conn)
	if !httpish[port] {
		buf := make([]byte, 160)
		n, _ := r.Read(buf)
		if v, ok := mysqlVersion(buf[:n]); ok {
			return "MySQL " + v
		}
		if n > 0 {
			return clean(string(buf[:n]))
		}
		if port != 443 && port != 8443 {
			return ""
		}
		return "tls"
	}
	conn.Write([]byte("HEAD / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: Perimeter\r\n\r\n"))
	status, server := "", ""
	for i := 0; i < 30; i++ {
		line, err := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if i == 0 {
			status = line
		}
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			server = strings.TrimSpace(line[7:])
		}
		if err != nil || line == "" {
			break
		}
	}
	if server != "" {
		return clean("http · " + server)
	}
	if status != "" {
		return clean(status)
	}
	return ""
}

// mysqlVersion reads the server version from a MySQL/MariaDB protocol-10 greeting:
// a 3-byte length, a sequence byte, 0x0a, then the version as a NUL-terminated string.
func mysqlVersion(b []byte) (string, bool) {
	if len(b) < 7 || b[4] != 0x0a {
		return "", false
	}
	end := -1
	for i := 5; i < len(b) && i < 70; i++ {
		if b[i] == 0 {
			end = i
			break
		}
	}
	if end <= 5 {
		return "", false
	}
	v := clean(string(b[5:end]))
	return v, v != "" && v[0] >= '0' && v[0] <= '9'
}

// clean keeps the first printable line of a banner.
func clean(s string) string {
	s = strings.SplitN(strings.ReplaceAll(s, "\r", "\n"), "\n", 2)[0]
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if len(out) > 100 {
		out = out[:100]
	}
	return out
}
