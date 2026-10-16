package check

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeRunner struct {
	run     func(context.Context, Command) CommandResult
	missing map[string]bool
}

func (f fakeRunner) Run(c context.Context, cmd Command) CommandResult { return f.run(c, cmd) }
func (f fakeRunner) LookPath(s string) (string, error) {
	if f.missing[s] {
		return "", exec.ErrNotFound
	}
	return s, nil
}

const pingOK = "64 bytes from 192.0.2.1: icmp_seq=0 ttl=64 time=0.321 ms\n1 packets transmitted, 1 packets received, 0.0% packet loss\n"
const dnsOK = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1\n\n;; ANSWER SECTION:\nexample.test. 60 IN A 192.0.2.1\n\n;; Query time: 1 msec\n"

func TestParsePing(t *testing.T) {
	p := parseProbe(1, CommandResult{Output: pingOK})
	if p.Status != "PASS" || p.RTTMS == nil || *p.RTTMS != 0.321 || p.Sent == nil || !*p.Sent {
		t.Fatal(p)
	}
	p = parseProbe(2, CommandResult{Output: "1 packets transmitted, 0 received", Err: context.DeadlineExceeded})
	if p.Status != "FAIL" || p.Sent == nil || !*p.Sent || p.RTTMS != nil {
		t.Fatal(p)
	}
	p = parseProbe(1, CommandResult{Output: "time<1 ms"})
	if !p.RTTUpperBound {
		t.Fatal(p)
	}
	p = parseProbe(1, CommandResult{})
	if p.Status != "ERROR" {
		t.Fatal(p)
	}
}
func TestPingPartialAndUnsent(t *testing.T) {
	c := Defaults()
	c.Ping.Count = 3
	c.Ping.IntervalSeconds = 0
	e := NewEngine(c)
	n := 0
	e.Runner = fakeRunner{run: func(context.Context, Command) CommandResult {
		n++
		if n == 1 {
			return CommandResult{Output: pingOK}
		}
		return CommandResult{Output: "1 packets transmitted, 0 received", Err: context.DeadlineExceeded}
	}}
	r := e.ping(context.Background(), job{target: "192.0.2.1", version: 4})
	d := r.Details.(PingDetails)
	if r.Status != "WARN" || d.Sent != 3 || d.Received != 1 || d.LossPercent == nil || *d.LossPercent < 66 {
		t.Fatal(r, d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = e.ping(ctx, job{target: "192.0.2.1", version: 4})
	d = r.Details.(PingDetails)
	if r.Status != "SKIP" || d.Sent != 0 || d.LossPercent != nil || len(d.Probes) != 3 {
		t.Fatal(r, d)
	}
}
func TestMTURequiredAndOptional(t *testing.T) {
	c := Defaults()
	c.MTU.Count = 1
	c.MTU.RequiredSizes = []int{1500}
	e := NewEngine(c)
	e.Runner = fakeRunner{run: func(context.Context, Command) CommandResult {
		return CommandResult{Output: "1 packets transmitted, 0 received", Err: context.DeadlineExceeded}
	}}
	for _, size := range []int{1280, 1500} {
		r := e.ping(context.Background(), job{target: "2001:db8::1", version: 6, size: size})
		want := "WARN"
		if size == 1500 {
			want = "FAIL"
		}
		if r.Status != want || r.Details.(PingDetails).PayloadSize != size-48 {
			t.Fatal(r)
		}
	}
}
func TestDNSParser(t *testing.T) {
	d := parseDNS(dnsOK, "example.test", "A")
	if d.RCode != "NOERROR" || len(d.Records) != 1 {
		t.Fatal(d)
	}
	d = parseDNS(strings.ReplaceAll(dnsOK, "qr rd ra;", "qr tc rd ra;"), "example.test", "A")
	if !d.Truncated {
		t.Fatal(d)
	}
	d = parseDNS(strings.ReplaceAll(dnsOK, "example.test. 60", "unrelated.test. 60"), "example.test", "A")
	if len(d.Records) != 0 {
		t.Fatal("unrelated answer accepted")
	}
	d = parseDNS(strings.Replace(dnsOK, "example.test. 60 IN A", "example.test. 60 IN CNAME alias.test.\nalias.test. 60 IN A", 1), "example.test", "A")
	if len(d.Records) != 1 {
		t.Fatal("CNAME chain rejected", d)
	}
}
func TestDNSProtocolFailureDoesNotFallback(t *testing.T) {
	c := Defaults()
	c.DNS.Name = "example.test"
	e := NewEngine(c)
	calls := 0
	e.Runner = fakeRunner{run: func(_ context.Context, cmd Command) CommandResult {
		calls++
		args := strings.Join(cmd.Args, " ")
		if !strings.Contains(args, "+ignore") || !strings.Contains(args, "+tries=1") {
			t.Fatal(cmd)
		}
		if strings.Contains(args, "+notcp") {
			return CommandResult{Output: "communications error: timed out", Err: &exec.ExitError{}}
		}
		return CommandResult{Output: dnsOK}
	}}
	udp := e.dns(context.Background(), job{id: "dns_udp", target: "192.0.2.53", version: 4, kind: "A"})
	tcp := e.dns(context.Background(), job{id: "dns_tcp", target: "192.0.2.53", version: 4, kind: "A"})
	if udp.Status != "FAIL" || tcp.Status != "PASS" || calls != 3 {
		t.Fatal(udp, tcp, calls)
	}
	for _, response := range []string{strings.Replace(dnsOK, "NOERROR", "NXDOMAIN", 1), strings.Replace(dnsOK, "NOERROR", "SERVFAIL", 1), strings.Replace(dnsOK, " IN A ", " IN AAAA ", 1), strings.Replace(dnsOK, "qr rd ra;", "qr tc rd ra;", 1)} {
		calls = 0
		e.Runner = fakeRunner{run: func(context.Context, Command) CommandResult { calls++; return CommandResult{Output: response} }}
		r := e.dns(context.Background(), job{id: "dns_udp", target: "192.0.2.53", version: 4, kind: "A"})
		if r.Status != "FAIL" || calls != 1 {
			t.Fatal(r, calls)
		}
	}
}
func TestTraceParserAndContinuation(t *testing.T) {
	p, ok := parseHop(" 2  2001:db8::1  2.5 ms !N\n", 2, 1)
	if !ok || p.IP != "2001:db8::1" || p.Annotation != "!N" || p.Status != "WARN" {
		t.Fatal(p, ok)
	}
	c := Defaults()
	c.Traceroute.MaxHops = 2
	c.Traceroute.Probes = 1
	c.Traceroute.ASLookup = false
	e := NewEngine(c)
	calls := 0
	e.Runner = fakeRunner{run: func(context.Context, Command) CommandResult {
		calls++
		if calls == 1 {
			return CommandResult{Output: "1 *\n"}
		}
		return CommandResult{Output: "2 192.0.2.1 1.1 ms\n"}
	}}
	r := e.traceroute(context.Background(), job{id: "traceroute", target: "192.0.2.1", version: 4})
	d := r.Details.(TraceDetails)
	if r.Status != "PASS" || len(d.Hops) != 2 || d.Hops[0].Probes[0].Reason != "無応答 (*)" {
		t.Fatal(r)
	}
}

type fakeResolver struct{}

func (fakeResolver) LookupIP(_ context.Context, network, _ string) ([]net.IP, error) {
	if network == "ip6" {
		return nil, errors.New("fixture IPv6 DNS failure")
	}
	return []net.IP{net.ParseIP("192.0.2.1")}, nil
}
func TestEnginePartialFailureAndDeadline(t *testing.T) {
	c := Defaults()
	c.Checks = []string{"system_dns", "dns_udp", "dns_tcp"}
	c.DNS.Name = "example.test"
	c.TotalSeconds = 1
	e := NewEngine(c)
	e.Resolver = fakeResolver{}
	var mu sync.Mutex
	active, maxActive := 0, 0
	e.Runner = fakeRunner{run: func(ctx context.Context, _ Command) CommandResult {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		<-ctx.Done()
		mu.Lock()
		active--
		mu.Unlock()
		return CommandResult{Err: ctx.Err()}
	}}
	started := time.Now()
	r := e.Run(context.Background())
	if len(r.Results) != 10 || r.ExitCode != 1 || r.Results[0].Status != "PASS" || r.Results[1].Status != "FAIL" || time.Since(started) > 2*time.Second || maxActive > 4 {
		t.Fatal(r, maxActive)
	}
	skipped := 0
	for _, v := range r.Results {
		if v.Status == "SKIP" {
			skipped++
		}
	}
	if skipped == 0 {
		t.Fatal("unstarted jobs not recorded")
	}
}

func TestDNSPlatformOptions(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		c := Defaults()
		c.DNS.Name = "example.test"
		e := NewEngine(c)
		e.Platform = Platform{platform}
		called := false
		e.Runner = fakeRunner{run: func(_ context.Context, cmd Command) CommandResult {
			called = true
			args := " " + strings.Join(cmd.Args, " ") + " "
			if strings.Contains(args, " +nocookie ") || strings.Contains(args, " -r ") != (platform == "linux") {
				t.Fatal("incompatible dig options", platform, cmd)
			}
			if !strings.Contains(args, " -6 ") || !strings.Contains(args, " +ignore ") || !strings.Contains(args, " +notcp ") {
				t.Fatal("incorrect transport", cmd)
			}
			return CommandResult{Output: dnsOK}
		}}
		r := e.dns(context.Background(), job{id: "dns_udp", target: "2001:db8::53", version: 6, kind: "A"})
		if !called || r.Status != "PASS" {
			t.Fatal(platform, r)
		}
	}
}

func TestImmediateRouteErrorHasNoInventedPacketLoss(t *testing.T) {
	c := Defaults()
	c.Ping.Count = 1
	e := NewEngine(c)
	e.Runner = fakeRunner{run: func(context.Context, Command) CommandResult {
		return CommandResult{Output: "ping6: UDP connect: No route to host", Err: &exec.ExitError{}}
	}}
	r := e.ping(context.Background(), job{target: "2001:db8::1", version: 6})
	d := r.Details.(PingDetails)
	if r.Status != "FAIL" || d.Sent != 0 || d.UnknownSent != 0 || d.LossPercent != nil {
		t.Fatal(r, d)
	}
}

func TestTracerouteNormalizesIPv6Destination(t *testing.T) {
	c := Defaults()
	c.Traceroute.MaxHops = 1
	c.Traceroute.Probes = 1
	e := NewEngine(c)
	e.Runner = fakeRunner{run: func(context.Context, Command) CommandResult { return CommandResult{Output: "1 2001:db8::1 0.5 ms\n"} }}
	r := e.traceroute(context.Background(), job{id: "traceroute", target: "2001:0db8:0:0:0:0:0:1", version: 6})
	if r.Status != "PASS" {
		t.Fatal(r)
	}
}
