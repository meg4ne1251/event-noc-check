package check

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Probe struct {
	Number        int      `json:"number"`
	Status        string   `json:"status"`
	Reason        string   `json:"reason"`
	Sent          *bool    `json:"sent"`
	RTTMS         *float64 `json:"rtt_ms"`
	RTTUpperBound bool     `json:"rtt_upper_bound,omitempty"`
}
type PingDetails struct {
	Planned        int      `json:"planned"`
	Sent           int      `json:"confirmed_sent"`
	UnknownSent    int      `json:"unknown_sent"`
	Received       int      `json:"received"`
	LossPercent    *float64 `json:"loss_percent"`
	MinMS          *float64 `json:"min_ms"`
	AverageMS      *float64 `json:"average_ms"`
	MaxMS          *float64 `json:"max_ms"`
	PacketSize     int      `json:"ip_packet_bytes"`
	PayloadSize    int      `json:"icmp_payload_bytes"`
	Fragmentation  string   `json:"fragmentation"`
	Probes         []Probe  `json:"probes"`
	BaselineStatus string   `json:"baseline_status,omitempty"`
}

var rttPattern = regexp.MustCompile(`time([=<])\s*([0-9.]+)\s*ms`)
var sentPattern = regexp.MustCompile(`(?m)(\d+) packets transmitted`)

func parseProbe(n int, o CommandResult) Probe {
	p := Probe{Number: n}
	p.Status, p.Reason = commandFailure(o)
	if m := sentPattern.FindStringSubmatch(o.Output); m != nil {
		v := m[1] != "0"
		p.Sent = &v
	}
	if m := rttPattern.FindStringSubmatch(o.Output); m != nil {
		v, e := strconv.ParseFloat(m[2], 64)
		if e == nil {
			p.RTTMS = &v
			p.RTTUpperBound = m[1] == "<"
			sent := true
			p.Sent = &sent
			p.Status = "PASS"
			p.Reason = "Echo応答を確認"
		}
	}
	if p.Status == "SKIP" || (p.Sent == nil && (p.Reason == "経路なし・到達不能" || p.Reason == "パケットサイズ制限（ローカルまたは経路上）")) {
		v := false
		p.Sent = &v
	}
	// A successful exit without a parseable echo must not invent a latency.
	if o.Err == nil && p.RTTMS == nil && p.Status != "SKIP" {
		p.Status = "ERROR"
		p.Reason = "ping出力に解析可能なEcho応答がありません"
	}
	return p
}
func (e *Engine) ping(ctx context.Context, j job) Result {
	c := e.Config.Ping
	id := "icmp"
	df := j.size > 0
	if df {
		id = "mtu"
		m := e.Config.MTU
		c = PingConfig{Targets: m.Targets, Count: m.Count, WaitSeconds: m.WaitSeconds, TimeoutSeconds: m.TimeoutSeconds, IntervalSeconds: m.IntervalSeconds}
	}
	r := Result{Check: id, Target: j.target, IPVersion: j.version, Status: "PASS", Reason: "全試行のEcho応答を確認"}
	d := PingDetails{Planned: c.Count, PacketSize: j.size, Probes: []Probe{}, Fragmentation: "既定"}
	if df {
		d.PayloadSize = j.size - 28
		if j.version == 6 {
			d.PayloadSize = j.size - 48
		}
		d.Fragmentation = "IPv4 DF / IPv6送信元断片化禁止"
	}
	cmd, err := e.Platform.ping(j.target, j.size, df)
	if err != nil {
		r.Status = "SKIP"
		r.Reason = err.Error()
		return r
	}
	sum := 0.0
	minimum := 0.0
	maximum := 0.0
	next := time.Now()
	for n := 1; n <= c.Count; n++ {
		p := Probe{Number: n, Status: "SKIP", Reason: "期限到達・未実行"}
		if waitUntil(ctx, next) {
			begin := time.Now()
			pc, cancel := context.WithTimeout(ctx, time.Duration(c.WaitSeconds)*time.Second)
			o := e.Runner.Run(pc, cmd)
			cancel()
			p = parseProbe(n, o)
			next = begin.Add(time.Duration(c.IntervalSeconds) * time.Second)
		}
		d.Probes = append(d.Probes, p)
		if p.Sent == nil && p.Status != "SKIP" {
			d.UnknownSent++
		} else if p.Sent != nil && *p.Sent {
			d.Sent++
		}
		if p.RTTMS != nil {
			v := *p.RTTMS
			sum += v
			if d.Received == 0 || v < minimum {
				minimum = v
			}
			if v > maximum {
				maximum = v
			}
			d.Received++
		}
	}
	if d.Received > 0 {
		avg := sum / float64(d.Received)
		d.AverageMS = &avg
		d.MinMS = &minimum
		d.MaxMS = &maximum
	}
	if d.Sent > 0 && d.UnknownSent == 0 {
		loss := 100 * float64(d.Sent-d.Received) / float64(d.Sent)
		d.LossPercent = &loss
	}
	if d.Received != c.Count {
		r.Status = "WARN"
		r.Reason = "一部の応答を確認できません"
		if d.Received == 0 {
			r.Status = "FAIL"
			r.Reason = "Echo応答なし（原因は未確定）"
		}
	}
	for _, p := range d.Probes {
		if p.Status == "SKIP" || p.Status == "ERROR" {
			r.Status = p.Status
			r.Reason = p.Reason
			if p.Status == "ERROR" {
				break
			}
		}
	}
	if d.UnknownSent > 0 && r.Status != "ERROR" && r.Status != "SKIP" {
		r.Status = "SKIP"
		r.Reason = "送信数を確認できない試行があり未確認です"
	}
	if !df && r.Status == "PASS" && d.AverageMS != nil && (*d.AverageMS >= c.WarnAverageMS || *d.MaxMS >= c.WarnMaxMS) {
		r.Status = "WARN"
		r.Reason = "RTTが設定された注意閾値以上です"
	}
	if df && (r.Status == "FAIL" || r.Status == "WARN") {
		r.Status = "WARN"
		r.Reason = "指定サイズの全応答は未確認。MTU障害とは断定できません"
		for _, s := range e.Config.MTU.RequiredSizes {
			if s == j.size {
				r.Status = "FAIL"
				r.Reason = "必須パケットサイズの通過条件を満たしません"
			}
		}
	}
	// Preserve concrete failure classifications without including unbounded command output.
	reasons := map[string]bool{}
	for _, p := range d.Probes {
		if p.Status != "PASS" {
			reasons[p.Reason] = true
		}
	}
	for _, s := range []string{"パケットサイズ制限（ローカルまたは経路上）", "経路なし・到達不能"} {
		if reasons[s] && !strings.Contains(r.Reason, s) {
			r.Reason += "; " + s
		}
	}
	r.Details = d
	return r
}
