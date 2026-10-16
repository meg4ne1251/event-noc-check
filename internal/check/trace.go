package check

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type HopProbe struct {
	Number     int      `json:"number"`
	IP         string   `json:"ip,omitempty"`
	RTTMS      *float64 `json:"rtt_ms"`
	Annotation string   `json:"annotation,omitempty"`
	Status     string   `json:"status"`
	Reason     string   `json:"reason"`
	AS         *ASInfo  `json:"as,omitempty"`
}
type Hop struct {
	TTL    int        `json:"ttl"`
	Probes []HopProbe `json:"probes"`
}
type TraceDetails struct {
	Hops       []Hop  `json:"hops"`
	Reached    bool   `json:"reached"`
	Method     string `json:"method"`
	StopReason string `json:"stop_reason,omitempty"`
}

func parseHop(out string, ttl, n int) (HopProbe, bool) {
	p := HopProbe{Number: n, Status: "WARN", Reason: "無応答 (*)"}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != strconv.Itoa(ttl) {
			continue
		}
		for i := 1; i < len(f); i++ {
			if a, err := netip.ParseAddr(strings.Trim(f[i], "()")); err == nil {
				p.IP = a.String()
			}
			if f[i] == "ms" && i > 1 {
				if v, err := strconv.ParseFloat(f[i-1], 64); err == nil {
					p.RTTMS = &v
				}
			}
			if strings.HasPrefix(f[i], "!") {
				p.Annotation = f[i]
			}
		}
		if p.IP != "" && p.RTTMS != nil {
			p.Status = "PASS"
			p.Reason = "ホップ応答"
			if p.Annotation != "" {
				p.Status = "WARN"
				p.Reason = "ICMPエラー注記あり"
			}
		}
		return p, p.IP != "" || strings.Contains(line, "*")
	}
	return p, false
}
func (e *Engine) traceroute(ctx context.Context, j job) Result {
	c := e.Config.Traceroute
	r := Result{Check: j.id, Target: j.target, IPVersion: j.version, Status: "WARN", Reason: "上限内で宛先到達を確認できません（障害箇所は未確定）"}
	d := TraceDetails{Hops: []Hop{}, Method: "UDP/33434から増加、逆引きなし、毎秒最大10プローブ"}
	next := time.Now()
	stop := false
	for ttl := 1; ttl <= c.MaxHops; ttl++ {
		h := Hop{TTL: ttl, Probes: []HopProbe{}}
		for n := 1; n <= c.Probes; n++ {
			p := HopProbe{Number: n, Status: "SKIP", Reason: "期限到達・未実行"}
			if !stop && waitUntil(ctx, next) {
				cmd, err := e.Platform.trace(j.target, ttl, 33434+(ttl-1)*c.Probes+n-1, c.WaitSeconds)
				if err != nil {
					p.Reason = err.Error()
					stop = true
					r.Status = "SKIP"
					r.Reason = p.Reason
				} else {
					start := time.Now()
					pc, cancel := context.WithTimeout(ctx, time.Duration(c.WaitSeconds)*time.Second+500*time.Millisecond)
					o := e.Runner.Run(pc, cmd)
					cancel()
					next = start.Add(100 * time.Millisecond)
					parsed, ok := parseHop(o.Output, ttl, n)
					if ok {
						p = parsed
						if p.IP == netip.MustParseAddr(j.target).String() && p.Annotation == "" && p.RTTMS != nil {
							d.Reached = true
						}
					} else {
						status, reason := commandFailure(o)
						p.Status = status
						p.Reason = reason
						if status == "SKIP" || status == "ERROR" {
							stop = true
							r.Status = status
							r.Reason = reason
						} else if o.Err == nil {
							p.Status = "ERROR"
							p.Reason = "traceroute出力を解析できません"
							r.Status = "ERROR"
							r.Reason = p.Reason
							stop = true
						} else {
							p.Status = "WARN"
						}
					}
				}
			}
			h.Probes = append(h.Probes, p)
		}
		d.Hops = append(d.Hops, h)
		if d.Reached {
			break
		}
	}
	if ctx.Err() != nil {
		d.StopReason = "期限到達・部分結果。SKIPのプローブは未確認"
	}
	if d.Reached && r.Status == "WARN" {
		r.Status = "PASS"
		r.Reason = "宛先の応答を確認。途中の無応答は個別記録を参照"
	}
	r.Details = d
	return r
}
