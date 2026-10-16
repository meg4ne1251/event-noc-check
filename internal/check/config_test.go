package check

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func profileFile(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(p, []byte(s), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestConfigDefaultsAndOverrides(t *testing.T) {
	c := Defaults()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c, err := Load(profileFile(t, `{"schema_version":1,"checks":["icmp"],"ip_versions":[4],"ping":{"targets":["192.0.2.1"],"count":2}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Ping.Count != 2 || c.Ping.WaitSeconds != 2 || len(c.DNS.Servers) != 2 || c.Output.TextLog {
		t.Fatalf("defaults not preserved: %+v", c)
	}
}
func TestInvalidProfiles(t *testing.T) {
	cases := []string{
		`{}`, `null`, `[]`, `{"schema_version":1,"checks":[]}`, `{"schema_version":2,"checks":["icmp"]}`,
		`{"schema_version":1,"checks":["icmp","icmp"]}`, `{"schema_version":1,"checks":["unknown"]}`,
		`{"schema_version":1,"checks":["icmp"],"ping":{"count":0}}`,
		`{"schema_version":1,"checks":["icmp"],"ping":{"targets":["-f"]}}`,
		`{"schema_version":1,"checks":["icmp"],"ping":{"targets":["192.0.2.1"]}}`,
		`{"schema_version":1,"checks":["icmp"],"ping":{"targets":["2001:db8::1","2001:0db8::1"]}}`,
		`{"schema_version":1,"checks":["icmp"],"ip_versions":[4,4]}`,
		`{"schema_version":1,"checks":["icmp"],"https":{"url":"http://example.com"}}`,
		`{"schema_version":1,"checks":["icmp"],"https":{"url":"https://user:pass@example.com"}}`,
		`{"schema_version":1,"checks":["icmp"],"https":{"url":"https://example.com?token=dummy"}}`,
		`{"schema_version":1,"checks":["icmp"],"mtu":{"packet_sizes":[1500,1500]}}`,
		`{"schema_version":1,"checks":["icmp"],"mtu":{"required_sizes":[9000]}}`,
		`{"schema_version":1,"checks":["icmp"],"dns":{"name":"+tcp"}}`,
		`{"schema_version":1,"checks":["icmp"],"ping":{"surprise":true}}`,
		`{"schema_version":1,"checks":["icmp"],"ping":null}`,
		`{"schema_version":1,"checks":["icmp"],"schema_version":1}`,
		`{"schema_version":1,"checks":["icmp"]} {}`,
	}
	for _, s := range cases {
		t.Run(s, func(t *testing.T) {
			c, err := Load(profileFile(t, s))
			if err == nil {
				err = c.Validate()
			}
			if err == nil {
				t.Fatal("invalid profile accepted")
			}
		})
	}
}
func TestProfileLimits(t *testing.T) {
	_, err := Load(profileFile(t, strings.Repeat(" ", 65537)))
	if err == nil {
		t.Fatal("oversized profile accepted")
	}
	c := Defaults()
	c.Ping.Targets = append(c.Ping.Targets, "224.0.0.1")
	if c.Validate() == nil {
		t.Fatal("multicast accepted")
	}
}

func TestExampleProfile(t *testing.T) {
	c, err := Load("../../examples/setup.json")
	if err == nil {
		err = c.Validate()
	}
	if err != nil {
		t.Fatal(err)
	}
}
