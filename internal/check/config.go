package check

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
)

var CheckIDs = []string{"connection", "icmp", "dns_udp", "dns_tcp", "system_dns", "mtu", "https", "traceroute"}

type PingConfig struct {
	Targets         []string `json:"targets"`
	Count           int      `json:"count"`
	WaitSeconds     int      `json:"wait_seconds"`
	TimeoutSeconds  int      `json:"timeout_seconds"`
	IntervalSeconds int      `json:"interval_seconds"`
	WarnAverageMS   float64  `json:"warn_average_ms"`
	WarnMaxMS       float64  `json:"warn_max_ms"`
}
type DNSConfig struct {
	Servers        []string `json:"servers"`
	Name           string   `json:"name"`
	Attempts       int      `json:"attempts"`
	WaitSeconds    int      `json:"wait_seconds"`
	TimeoutSeconds int      `json:"timeout_seconds"`
}
type MTUConfig struct {
	Targets         []string `json:"targets"`
	PacketSizes     []int    `json:"packet_sizes"`
	RequiredSizes   []int    `json:"required_sizes"`
	Count           int      `json:"count"`
	WaitSeconds     int      `json:"wait_seconds"`
	TimeoutSeconds  int      `json:"timeout_seconds"`
	IntervalSeconds int      `json:"interval_seconds"`
}
type HTTPSConfig struct {
	URL            string `json:"url"`
	Status         int    `json:"status"`
	EmptyBody      bool   `json:"empty_body"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}
type TraceConfig struct {
	Targets        []string `json:"targets"`
	MaxHops        int      `json:"max_hops"`
	Probes         int      `json:"probes"`
	WaitSeconds    int      `json:"wait_seconds"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	ASLookup       bool     `json:"as_lookup"`
}
type OutputConfig struct {
	TextLog   bool   `json:"text_log"`
	Directory string `json:"directory"`
}
type Config struct {
	SchemaVersion int          `json:"schema_version"`
	Name          string       `json:"name"`
	Checks        []string     `json:"checks"`
	IPVersions    []int        `json:"ip_versions"`
	Ping          PingConfig   `json:"ping"`
	DNS           DNSConfig    `json:"dns"`
	MTU           MTUConfig    `json:"mtu"`
	HTTPS         HTTPSConfig  `json:"https"`
	Traceroute    TraceConfig  `json:"traceroute"`
	Output        OutputConfig `json:"output"`
	TotalSeconds  int          `json:"total_seconds"`
}

func Defaults() Config {
	targets := func() []string { return []string{"1.1.1.1", "2606:4700:4700::1111"} }
	return Config{1, "", slices.Clone(CheckIDs), []int{4, 6},
		PingConfig{targets(), 5, 2, 12, 1, 300, 1000}, DNSConfig{targets(), "google.com", 2, 2, 5},
		MTUConfig{targets(), []int{1200, 1280, 1400, 1450, 1480, 1492, 1500}, []int{}, 3, 2, 8, 1},
		HTTPSConfig{"https://www.google.com/generate_204", 204, true, 15},
		TraceConfig{targets(), 30, 3, 1, 60, true}, OutputConfig{false, "results"}, 180}
}
func Load(path string) (Config, error) {
	c := Defaults()
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil {
		return c, e
	}
	if len(b) > 65536 {
		return c, fmt.Errorf("プロファイルは64KiB以下にしてください")
	}
	if e = validateJSON(b); e != nil {
		return c, e
	}
	c.SchemaVersion = 0
	c.Checks = nil
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	return c, nil
}

// Reject duplicate keys and nulls rather than silently replacing/defaulting values.
func validateJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var walk func() error
	walk = func() error {
		t, e := d.Token()
		if e != nil {
			return e
		}
		if t == nil {
			return fmt.Errorf("nullは指定できません")
		}
		if v, ok := t.(json.Delim); ok {
			if v == '{' {
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return e
					}
					s, ok := k.(string)
					if !ok || seen[s] {
						return fmt.Errorf("重複または不正なキー: %v", k)
					}
					seen[s] = true
					if e = walk(); e != nil {
						return e
					}
				}
			} else if v == '[' {
				for d.More() {
					if e := walk(); e != nil {
						return e
					}
				}
			} else {
				return fmt.Errorf("不正なJSON")
			}
			_, e = d.Token()
			return e
		}
		return nil
	}
	if len(bytes.TrimSpace(b)) == 0 || bytes.TrimSpace(b)[0] != '{' {
		return fmt.Errorf("プロファイルはJSONオブジェクトで指定してください")
	}
	if e := walk(); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return fmt.Errorf("JSONの末尾に余分なデータがあります")
	}
	return nil
}
func family(s string) int {
	a, e := netip.ParseAddr(s)
	if e != nil {
		return 0
	}
	if a.Is4() {
		return 4
	}
	return 6
}
func (c Config) selected(id string) bool { return slices.Contains(c.Checks, id) }
func unique[T comparable](a []T) bool {
	m := map[T]bool{}
	for _, v := range a {
		if m[v] {
			return false
		}
		m[v] = true
	}
	return true
}
func (c *Config) Validate() error {
	bad := func(s string) error { return fmt.Errorf("設定エラー: %s", s) }
	if c.SchemaVersion != 1 {
		return bad("schema_versionは1が必要です")
	}
	if len(c.Checks) == 0 || !unique(c.Checks) {
		return bad("checksは重複のない空でない配列が必要です")
	}
	for _, s := range c.Checks {
		if !slices.Contains(CheckIDs, s) {
			return bad("未知の検査ID: " + s)
		}
	}
	if len(c.IPVersions) == 0 || !unique(c.IPVersions) {
		return bad("ip_versionsが不正です")
	}
	for _, v := range c.IPVersions {
		if v != 4 && v != 6 {
			return bad("IPバージョンは4または6です")
		}
	}
	for _, x := range []struct {
		id      string
		targets []string
	}{{"icmp", c.Ping.Targets}, {"dns_udp", c.DNS.Servers}, {"dns_tcp", c.DNS.Servers}, {"mtu", c.MTU.Targets}, {"traceroute", c.Traceroute.Targets}} {
		if len(x.targets) == 0 || len(x.targets) > 16 {
			return bad(x.id + "の宛先は1〜16件です")
		}
		seen := map[netip.Addr]bool{}
		for _, s := range x.targets {
			a, e := netip.ParseAddr(s)
			if e != nil || a.Is4In6() || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() || seen[a] {
				return bad(x.id + "の宛先IPが不正または重複しています")
			}
			seen[a] = true
		}
		if c.selected(x.id) {
			for _, v := range c.IPVersions {
				found := false
				for _, s := range x.targets {
					found = found || family(s) == v
				}
				if !found {
					return bad(fmt.Sprintf("%sのIPv%d宛先がありません", x.id, v))
				}
			}
		}
	}
	for _, x := range []struct {
		n         string
		v, lo, hi int
	}{
		{"ping.count", c.Ping.Count, 1, 10}, {"mtu.count", c.MTU.Count, 1, 5}, {"dns.attempts", c.DNS.Attempts, 1, 2},
		{"ping.wait_seconds", c.Ping.WaitSeconds, 1, 5}, {"dns.wait_seconds", c.DNS.WaitSeconds, 1, 5}, {"mtu.wait_seconds", c.MTU.WaitSeconds, 1, 5},
		{"ping.interval_seconds", c.Ping.IntervalSeconds, 1, 5}, {"mtu.interval_seconds", c.MTU.IntervalSeconds, 1, 5},
		{"ping.timeout_seconds", c.Ping.TimeoutSeconds, 1, 35}, {"dns.timeout_seconds", c.DNS.TimeoutSeconds, 1, 15}, {"mtu.timeout_seconds", c.MTU.TimeoutSeconds, 1, 15},
		{"https.timeout_seconds", c.HTTPS.TimeoutSeconds, 1, 35}, {"traceroute.timeout_seconds", c.Traceroute.TimeoutSeconds, 1, 60},
		{"traceroute.max_hops", c.Traceroute.MaxHops, 1, 30}, {"traceroute.probes", c.Traceroute.Probes, 1, 3}, {"traceroute.wait_seconds", c.Traceroute.WaitSeconds, 1, 3}, {"total_seconds", c.TotalSeconds, 1, 180},
	} {
		if x.v < x.lo || x.v > x.hi {
			return bad(fmt.Sprintf("%sは%d〜%dです", x.n, x.lo, x.hi))
		}
	}
	if c.Ping.WarnAverageMS <= 0 || c.Ping.WarnMaxMS <= 0 {
		return bad("RTT閾値は正の数です")
	}
	if len(c.MTU.PacketSizes) == 0 || len(c.MTU.PacketSizes) > 16 || !unique(c.MTU.PacketSizes) || !unique(c.MTU.RequiredSizes) {
		return bad("packet_sizesが不正です")
	}
	for _, s := range c.MTU.PacketSizes {
		if s < 64 || s > 9000 {
			return bad("パケットサイズは64〜9000です")
		}
	}
	for _, s := range c.MTU.RequiredSizes {
		if !slices.Contains(c.MTU.PacketSizes, s) {
			return bad("required_sizesはpacket_sizesに含めてください")
		}
	}
	slices.Sort(c.MTU.PacketSizes)
	n := strings.TrimSuffix(c.DNS.Name, ".")
	if len(n) == 0 || len(n) > 253 {
		return bad("DNS名が不正です")
	}
	for _, l := range strings.Split(n, ".") {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return bad("DNSラベルが不正です")
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return bad("DNS名はASCIIで指定してください")
			}
		}
	}
	u, e := url.Parse(c.HTTPS.URL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return bad("HTTPS URLは認証・クエリ・フラグメントを含まないhttps URLが必要です")
	}
	if c.HTTPS.Status < 200 || c.HTTPS.Status > 599 {
		return bad("HTTPS statusが不正です")
	}
	if c.Output.TextLog && strings.TrimSpace(c.Output.Directory) == "" {
		return bad("ログ保存先が空です")
	}
	return nil
}
