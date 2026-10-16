package check

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

type ASRecord struct {
	Number    string `json:"number"`
	Holder    string `json:"holder"`
	Reason    string `json:"reason,omitempty"`
	IPVersion int    `json:"lookup_ip_version"`
	DataTime  string `json:"data_time,omitempty"`
}
type ASInfo struct {
	Status    string     `json:"status"`
	Reason    string     `json:"reason,omitempty"`
	Source    string     `json:"source"`
	FetchedAt time.Time  `json:"fetched_at"`
	DataTime  string     `json:"data_time,omitempty"`
	IPVersion int        `json:"lookup_ip_version"`
	Prefix    string     `json:"prefix,omitempty"`
	ASNs      []ASRecord `json:"asns"`
}

// Conservative exclusion of special-use ranges. For IPv6 only global unicast
// 2000::/3 is eligible, with special-purpose subranges excluded.
var excludedPrefixes = func() []netip.Prefix {
	values := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.175.48.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "2620:4f:8000::/48"}
	p := []netip.Prefix{}
	for _, s := range values {
		p = append(p, netip.MustParsePrefix(s))
	}
	return p
}()

func publicIP(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Is4In6() || a.Zone() != "" || !a.IsGlobalUnicast() {
		return false
	}
	if a.Is6() && !netip.MustParsePrefix("2000::/3").Contains(a) {
		return false
	}
	for _, p := range excludedPrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

type asEnvelope struct {
	Status string `json:"status"`
	Data   struct {
		ASNs      []json.RawMessage `json:"asns"`
		Prefix    string            `json:"prefix"`
		Holder    string            `json:"holder"`
		QueryTime string            `json:"query_time"`
	} `json:"data"`
}
type asClient struct {
	client   *http.Client
	endpoint string
	next     time.Time
	count    int
}

func (a *asClient) get(ctx context.Context, endpoint, resource string) (asEnvelope, int, error) {
	var data asEnvelope
	if a.count >= 128 {
		return data, 0, fmt.Errorf("照会回数上限")
	}
	if !waitUntil(ctx, a.next) {
		return data, 0, ctx.Err()
	}
	a.count++
	a.next = time.Now().Add(250 * time.Millisecond)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var mu sync.Mutex
	v := 0
	trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) {
		host, _, _ := net.SplitHostPort(i.Conn.RemoteAddr().String())
		mu.Lock()
		v = family(host)
		mu.Unlock()
	}}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "GET", a.endpoint+"/"+endpoint+"/data.json?resource="+url.QueryEscape(resource), nil)
	if err != nil {
		return data, 0, err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return data, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return data, 0, fmt.Errorf("AS API HTTP %d", resp.StatusCode)
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 262144)).Decode(&data)
	if err == nil && data.Status != "ok" {
		err = fmt.Errorf("AS API応答が正常ではありません")
	}
	mu.Lock()
	version := v
	mu.Unlock()
	return data, version, err
}
func (e *Engine) enrichAS(ctx context.Context, results []Result) {
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := e.ASHTTPClient
	if client == nil {
		client = &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	endpoint := e.ASEndpoint
	if endpoint == "" {
		endpoint = "https://stat.ripe.net/data"
	}
	api := asClient{client: client, endpoint: endpoint}
	ips := map[string]*ASInfo{}
	asns := map[string]ASRecord{}
	for i := range results {
		d, ok := results[i].Details.(TraceDetails)
		if !ok {
			continue
		}
		for hi := range d.Hops {
			for pi := range d.Hops[hi].Probes {
				p := &d.Hops[hi].Probes[pi]
				if p.IP == "" {
					continue
				}
				if previous, ok := ips[p.IP]; ok {
					p.AS = previous
					continue
				}
				info := &ASInfo{Status: "unknown", Source: "RIPEstat Network Info / AS Overview", ASNs: []ASRecord{}}
				ips[p.IP] = info
				p.AS = info
				if !e.Config.Traceroute.ASLookup {
					info.Status = "disabled"
					info.Reason = "AS照会無効"
					continue
				}
				if !publicIP(p.IP) {
					info.Status = "excluded"
					info.Reason = "公開AS照会対象外"
					continue
				}
				if ctx.Err() != nil {
					info.Status = "not_queried"
					info.Reason = "AS照会期限到達"
					continue
				}
				data, v, err := api.get(ctx, "network-info", p.IP)
				info.FetchedAt = time.Now().UTC()
				info.IPVersion = v
				if err != nil {
					info.Reason = "AS情報取得失敗"
					continue
				}
				info.Prefix = data.Data.Prefix
				info.DataTime = data.Data.QueryTime
				for _, raw := range data.Data.ASNs {
					num := strings.Trim(string(raw), `"`)
					valid := len(num) > 0 && len(num) <= 10
					for _, r := range num {
						valid = valid && r >= '0' && r <= '9'
					}
					if !valid {
						continue
					}
					record, ok := asns[num]
					if !ok {
						record = ASRecord{Number: num}
						detail, version, err := api.get(ctx, "as-overview", "AS"+num)
						record.IPVersion = version
						if err != nil {
							record.Reason = "AS登録組織名取得失敗"
						} else {
							record.Holder = detail.Data.Holder
							record.DataTime = detail.Data.QueryTime
						}
						asns[num] = record
					}
					info.ASNs = append(info.ASNs, record)
				}
				if len(info.ASNs) > 0 {
					info.Status = "available"
				} else {
					info.Reason = "広告元ASが不明"
				}
			}
		}
		results[i].Details = d
	}
}
