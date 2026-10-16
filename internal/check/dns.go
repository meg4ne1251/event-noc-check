package check

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type DNSDetails struct {
	Name       string   `json:"name"`
	RecordType string   `json:"record_type"`
	Transport  string   `json:"transport"`
	Attempts   int      `json:"attempts"`
	RCode      string   `json:"rcode"`
	Truncated  bool     `json:"truncated"`
	Records    []string `json:"records"`
}

var dnsStatus = regexp.MustCompile(`status: ([A-Z0-9]+),`)

func parseDNS(out, name, kind string) DNSDetails {
	d := DNSDetails{Name: name, RecordType: kind, Records: []string{}}
	if m := dnsStatus.FindStringSubmatch(out); m != nil {
		d.RCode = m[1]
	}
	answer := false
	// Accept addresses only in the answer section, following a bounded CNAME chain.
	owners := map[string]bool{strings.ToLower(strings.TrimSuffix(name, ".")): true}
	lines := []string{}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, ";; flags:") {
			f := strings.Split(strings.TrimPrefix(line, ";; flags:"), ";")[0]
			for _, s := range strings.Fields(f) {
				if s == "tc" {
					d.Truncated = true
				}
			}
		}
		if strings.HasPrefix(line, ";; ANSWER SECTION:") {
			answer = true
			continue
		}
		if strings.HasPrefix(line, ";;") {
			answer = false
		}
		if answer && strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	for range 16 {
		changed := false
		for _, line := range lines {
			f := strings.Fields(line)
			if len(f) >= 5 && f[2] == "IN" && f[3] == "CNAME" && owners[strings.ToLower(strings.TrimSuffix(f[0], "."))] {
				n := strings.ToLower(strings.TrimSuffix(f[4], "."))
				if !owners[n] {
					owners[n] = true
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) < 5 || f[2] != "IN" || f[3] != kind || !owners[strings.ToLower(strings.TrimSuffix(f[0], "."))] {
			continue
		}
		a, e := netip.ParseAddr(f[4])
		if e == nil && (kind == "A" && a.Is4() || kind == "AAAA" && a.Is6()) {
			d.Records = append(d.Records, a.String())
		}
	}
	return d
}
func (e *Engine) dns(ctx context.Context, j job) Result {
	c := e.Config.DNS
	transport := strings.TrimPrefix(j.id, "dns_")
	r := Result{Check: j.id, Target: j.target, IPVersion: j.version, Status: "FAIL"}
	d := DNSDetails{Name: c.Name, RecordType: j.kind, Transport: transport, Records: []string{}}
	// Apple BIND dig has no -r. Do not silently inherit a user .digrc that
	// could enable tracing, change destinations, or inject additional queries.
	if e.Platform.OS == "darwin" {
		home, err := os.UserHomeDir()
		if err != nil {
			r.Status = "SKIP"
			r.Reason = "dig個人設定の有無を確認できません"
			r.Details = d
			return r
		}
		if _, err = os.Stat(filepath.Join(home, ".digrc")); !os.IsNotExist(err) {
			r.Status = "SKIP"
			r.Reason = "macOS digは個人設定を無効化できないため、.digrcが存在または確認不能の場合は未実行"
			r.Details = d
			return r
		}
	}
	for n := 1; n <= c.Attempts; n++ {
		if ctx.Err() != nil {
			r.Status = "SKIP"
			r.Reason = "期限到達・未実行のDNS試行あり"
			break
		}
		args := []string{"-" + strconv.Itoa(j.version), "@" + j.target, c.Name, j.kind, "+time=" + strconv.Itoa(c.WaitSeconds), "+tries=1", "+noedns", "+nosearch", "+ignore"}
		if e.Platform.OS == "linux" {
			args = append([]string{"-r"}, args...)
		}
		if transport == "tcp" {
			args = append(args, "+tcp")
		} else {
			args = append(args, "+notcp")
		}
		o := e.Runner.Run(ctx, Command{"dig", args})
		d = parseDNS(o.Output, c.Name, j.kind)
		d.Transport = transport
		d.Attempts = n
		if d.RCode != "" {
			switch {
			case d.Truncated:
				r.Reason = "UDP応答は切り詰め（TC）。TCPの結果を別途確認してください"
			case d.RCode != "NOERROR":
				r.Reason = "DNS応答: " + d.RCode
			case len(d.Records) == 0:
				r.Reason = "NOERRORですが必要なレコードがありません"
			case o.Err != nil:
				r.Status, r.Reason = commandFailure(o)
			default:
				r.Status = "PASS"
				r.Reason = "指定DNSから必要なレコードを取得"
			}
			break
		}
		r.Status, r.Reason = commandFailure(o)
		if r.Status == "SKIP" || r.Status == "ERROR" {
			break
		}
		s := strings.ToLower(o.Output)
		if !strings.Contains(s, "timed out") {
			break
		}
		r.Reason = "DNSタイムアウト（無応答）"
	}
	r.Details = d
	return r
}
func (e *Engine) systemDNS(ctx context.Context, j job) Result {
	r := Result{Check: j.id, Target: e.Config.DNS.Name, IPVersion: 0, Status: "FAIL"}
	network := "ip4"
	if j.kind == "AAAA" {
		network = "ip6"
	}
	ips, err := e.Resolver.LookupIP(ctx, network, e.Config.DNS.Name)
	d := DNSDetails{Name: e.Config.DNS.Name, RecordType: j.kind, Transport: "OS設定経由・通信経路不明", Records: []string{}}
	for _, a := range ips {
		d.Records = append(d.Records, a.String())
	}
	if err != nil {
		r.Reason = "OS設定による名前解決失敗: " + err.Error()
	} else if len(ips) == 0 {
		r.Reason = "必要なレコードがありません"
	} else {
		r.Status = "PASS"
		r.Reason = "OS設定で名前解決成功（通信経路は不明）"
	}
	r.Details = d
	return r
}

type Resolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}
