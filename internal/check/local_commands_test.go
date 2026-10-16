package check

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"
)

// Explicit opt-in only: exercises real OS tools against loopback, never public DNS.
func TestLocalOSCommands(t *testing.T) {
	if os.Getenv("NOC_CHECK_LOCAL_COMMANDS") != "1" {
		t.Skip("set NOC_CHECK_LOCAL_COMMANDS=1 for loopback OS command tests")
	}
	c := Defaults()
	c.Ping.Count = 1
	c.MTU.Count = 1
	c.Traceroute.MaxHops = 1
	c.Traceroute.Probes = 1
	c.Traceroute.ASLookup = false
	e := NewEngine(c)
	for _, target := range []string{"127.0.0.1", "::1"} {
		for _, size := range []int{0, 1500} {
			t.Run(target+"/ping/"+strconv.Itoa(size), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				r := e.ping(ctx, job{target: target, version: family(target), size: size})
				if e.Platform.OS == "darwin" && target == "::1" && size > 0 && r.Status == "SKIP" && r.Reason == "権限不足" {
					t.Log("macOS IPv6 DONTFRAG requires permission; correctly reported SKIP")
				} else if r.Status != "PASS" {
					t.Fatalf("loopback ping failed: %+v", r)
				}
			})
		}
		t.Run(target+"/trace", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			r := e.traceroute(ctx, job{id: "traceroute", target: target, version: family(target)})
			if r.Status != "PASS" {
				t.Fatalf("loopback traceroute failed: %+v", r)
			}
		})
	}
}
