package check

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"
)

type Engine struct {
	Config       Config
	Platform     Platform
	Runner       Runner
	Resolver     Resolver
	DialContext  func(context.Context, string, string) (net.Conn, error)
	TLSConfig    *tls.Config // Optional trusted roots for local tests; never disables validation.
	ASHTTPClient *http.Client
	ASEndpoint   string
}

func NewEngine(c Config) *Engine {
	return &Engine{Config: c, Platform: NativePlatform(), Runner: ExecRunner{}, Resolver: net.DefaultResolver}
}

type job struct {
	id, target, kind       string
	version, size, timeout int
}

func (e *Engine) jobs() [3][]job {
	var phases [3][]job
	c := e.Config
	for _, id := range c.Checks {
		if id == "system_dns" {
			for _, kind := range []string{"A", "AAAA"} {
				phases[0] = append(phases[0], job{id: id, target: c.DNS.Name, kind: kind, timeout: 5})
			}
			continue
		}
		for _, v := range c.IPVersions {
			switch id {
			case "connection":
				phases[0] = append(phases[0], job{id: id, target: "local", version: v, timeout: 5})
			case "https":
				phases[0] = append(phases[0], job{id: id, target: c.HTTPS.URL, version: v, timeout: c.HTTPS.TimeoutSeconds})
			case "icmp":
				for _, t := range c.Ping.Targets {
					if family(t) == v {
						phases[0] = append(phases[0], job{id: id, target: t, version: v, timeout: c.Ping.TimeoutSeconds})
					}
				}
			case "dns_udp", "dns_tcp":
				for _, t := range c.DNS.Servers {
					if family(t) == v {
						for _, kind := range []string{"A", "AAAA"} {
							phases[0] = append(phases[0], job{id: id, target: t, version: v, kind: kind, timeout: c.DNS.TimeoutSeconds})
						}
					}
				}
			case "mtu":
				for _, t := range c.MTU.Targets {
					if family(t) == v {
						sizes := append([]int{64}, c.MTU.PacketSizes...)
						sizes = slices.Compact(sizes)
						for _, size := range sizes {
							phases[1] = append(phases[1], job{id: id, target: t, version: v, size: size, timeout: c.MTU.TimeoutSeconds})
						}
					}
				}
			case "traceroute":
				for _, t := range c.Traceroute.Targets {
					if family(t) == v {
						phases[2] = append(phases[2], job{id: id, target: t, version: v, timeout: c.Traceroute.TimeoutSeconds})
					}
				}
			}
		}
	}
	return phases
}
func (e *Engine) execute(ctx context.Context, j job) Result {
	started := time.Now()
	r := Result{Check: j.id, Target: j.target, IPVersion: j.version, Status: "SKIP", Reason: "期限到達・未実行", Details: map[string]any{"record_type": j.kind, "ip_packet_bytes": j.size}}
	if ctx.Err() != nil {
		return r
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(j.timeout)*time.Second)
	defer cancel()
	switch j.id {
	case "connection":
		r = e.connection(ctx, j)
	case "icmp", "mtu":
		r = e.ping(ctx, j)
	case "dns_udp", "dns_tcp":
		r = e.dns(ctx, j)
	case "system_dns":
		r = e.systemDNS(ctx, j)
	case "https":
		r = e.https(ctx, j)
	case "traceroute":
		r = e.traceroute(ctx, j)
	}
	r.ElapsedMS = float64(time.Since(started)) / float64(time.Millisecond)
	return r
}
func (e *Engine) Run(ctx context.Context) Report {
	start := time.Now()
	r := Report{SchemaVersion: 1, StartedAt: start.UTC(), Config: e.Config, Results: []Result{}}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(e.Config.TotalSeconds)*time.Second)
	defer cancel()
	phases := e.jobs()
	for phase, jobs := range phases {
		seconds := []int{35, 65, 60}[phase]
		pc, stop := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
		results := make([]Result, len(jobs))
		var wg sync.WaitGroup
		// Group ICMP/MTU by destination so separate sizes never violate per-target pacing.
		groups := [][]int{}
		keys := map[string]int{}
		for i, j := range jobs {
			key := j.id + ":" + j.target
			if j.id != "icmp" && j.id != "mtu" {
				groups = append(groups, []int{i})
				continue
			}
			idx, ok := keys[key]
			if !ok {
				idx = len(groups)
				keys[key] = idx
				groups = append(groups, nil)
			}
			groups[idx] = append(groups[idx], i)
		}
		queue := make(chan []int, len(groups))
		for _, g := range groups {
			queue <- g
		}
		close(queue)
		workers := 4
		if phase == 2 {
			workers = 2
		}
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for group := range queue {
					for n, i := range group {
						results[i] = e.execute(pc, jobs[i])
						if jobs[i].id == "mtu" && n < len(group)-1 {
							waitUntil(pc, time.Now().Add(time.Duration(e.Config.MTU.IntervalSeconds)*time.Second))
						}
					}
				}
			}()
		}
		wg.Wait()
		stop()
		r.Results = append(r.Results, results...)
	}
	// Interpret ICMP failure only when every selected direct DNS query on that
	// family succeeds and HTTPS also succeeds. OS DNS has no known transport family.
	for i := range r.Results {
		p := &r.Results[i]
		if p.Check != "icmp" || p.Status != "FAIL" {
			continue
		}
		pd, ok := p.Details.(PingDetails)
		if !ok || pd.Received != 0 {
			continue
		}
		dnsSeen, dnsOK, httpOK := false, true, false
		for _, v := range r.Results {
			if v.IPVersion != p.IPVersion {
				continue
			}
			if v.Check == "dns_udp" || v.Check == "dns_tcp" {
				dnsSeen = true
				dnsOK = dnsOK && v.Status == "PASS"
			}
			if v.Check == "https" && v.Status == "PASS" {
				httpOK = true
			}
		}
		if dnsSeen && dnsOK && httpOK {
			p.Status = "WARN"
			p.Reason = "ICMP応答なし。ただし同じIP経路の直接DNS・HTTPSは成功"
		}
	}
	baseline := map[string]string{}
	for _, v := range r.Results {
		if d, ok := v.Details.(PingDetails); ok && v.Check == "mtu" && d.PacketSize == 64 {
			baseline[v.Target] = v.Status
		}
	}
	for i := range r.Results {
		if d, ok := r.Results[i].Details.(PingDetails); ok && r.Results[i].Check == "mtu" {
			d.BaselineStatus = baseline[r.Results[i].Target]
			r.Results[i].Details = d
			if d.BaselineStatus != "PASS" {
				r.Results[i].Reason += "; 小パケットの比較条件を満たしません"
			}
		}
	}
	ac, stop := context.WithTimeout(ctx, 15*time.Second)
	e.enrichAS(ac, r.Results)
	stop()
	r.ElapsedMS = float64(time.Since(start)) / float64(time.Millisecond)
	r.Summarize()
	return r
}
