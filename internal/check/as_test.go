package check

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicIPFilter(t *testing.T) {
	for _, s := range []string{"192.0.2.1", "2001:db8::1", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "224.0.0.1", "198.18.0.1", "2001::1", "2002::1", "fc00::1", "fe80::1", "3fff::1", "::ffff:1.1.1.1"} {
		if publicIP(s) {
			t.Errorf("special address allowed: %s", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		if !publicIP(s) {
			t.Errorf("public address rejected: %s", s)
		}
	}
}
func TestASEnrichmentPrivacyCachingAndFailure(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		resource := r.URL.Query().Get("resource")
		if strings.Contains(resource, "192.0.2") {
			t.Error("special IP sent to service")
		}
		if strings.Contains(r.URL.Path, "network-info") {
			fmt.Fprint(w, `{"status":"ok","data":{"prefix":"1.1.1.0/24","asns":["13335",64496],"query_time":"fixture"}}`)
		} else {
			fmt.Fprint(w, `{"status":"ok","data":{"holder":"EXAMPLE ORGANIZATION"}}`)
		}
	}))
	defer s.Close()
	e := NewEngine(Defaults())
	e.ASEndpoint = s.URL
	e.ASHTTPClient = s.Client()
	results := []Result{{Status: "PASS", Details: TraceDetails{Hops: []Hop{{TTL: 1, Probes: []HopProbe{{IP: "192.0.2.1"}, {IP: "1.1.1.1"}, {IP: "1.1.1.1"}}}}}}}
	e.enrichAS(context.Background(), results)
	d := results[0].Details.(TraceDetails)
	if calls != 3 || d.Hops[0].Probes[0].AS.Status != "excluded" || len(d.Hops[0].Probes[1].AS.ASNs) != 2 || d.Hops[0].Probes[1].AS != d.Hops[0].Probes[2].AS || results[0].Status != "PASS" {
		t.Fatal(calls, d)
	}
	e.Config.Traceroute.ASLookup = false
	e.enrichAS(context.Background(), results)
	if calls != 3 || results[0].Details.(TraceDetails).Hops[0].Probes[1].AS.Status != "disabled" {
		t.Fatal("disabled lookup sent request")
	}
}
