package check

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMissingDependencies(t *testing.T) {
	c := Defaults()
	c.Checks = []string{"icmp"}
	runner := fakeRunner{missing: map[string]bool{"ping": true, "dig": true}}
	for _, tc := range []struct {
		policy, input   string
		interactive, ok bool
	}{{"ask", "y\n", true, true}, {"ask", "\n", true, false}, {"ask", "y", true, false}, {"ask", "y\n", false, false}, {"skip", "", false, true}, {"abort", "y\n", true, false}} {
		var stderr bytes.Buffer
		err := missingDependencies(c, Platform{"linux"}, runner, strings.NewReader(tc.input), &stderr, tc.policy, tc.interactive)
		if (err == nil) != tc.ok || strings.Contains(stderr.String(), "依存コマンド不足: dig") {
			t.Fatal(tc, err, stderr.String())
		}
	}
	c.Checks = []string{"https"}
	if err := missingDependencies(c, Platform{"linux"}, runner, strings.NewReader(""), io.Discard, "abort", false); err != nil {
		t.Fatal(err)
	}
}
func TestCLIJSONErrorsNoFiles(t *testing.T) {
	for _, args := range [][]string{{"--ipv4-only", "--ipv6-only", "--format", "json"}, {"--bad", "--format=json"}, {"--packet-size", "bad", "--format", "json"}, {"--format", "json", "positional"}, {"--format", "json", "--profile", "missing-file"}} {
		var out, stderr bytes.Buffer
		code := CLI(context.Background(), args, strings.NewReader(""), &out, &stderr, false)
		var r Report
		if code != 2 || json.Unmarshal(out.Bytes(), &r) != nil || r.SchemaVersion != 1 || r.Status != "ERROR" {
			t.Fatal(args, code, out.String())
		}
	}
}
func TestLogOptInAndUnique(t *testing.T) {
	c := Defaults()
	dir := filepath.Join(t.TempDir(), "results")
	c.Output.Directory = dir
	f, err := prepareLog(c)
	if err != nil || f != nil {
		t.Fatal(f, err)
	}
	if _, err = os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("directory created without opt-in")
	}
	c.Output.TextLog = true
	f, err = prepareLog(c)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	g, err := prepareLog(c)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if f.Name() == g.Name() {
		t.Fatal("log overwritten")
	}
	st, _ := f.Stat()
	if st.Mode().Perm() != 0600 {
		t.Fatal("log permissions", st.Mode())
	}
	r := Report{Config: c, Status: "PASS", Results: []Result{{Check: "icmp", Target: "192.0.2.1", Status: "PASS", Reason: "fixture"}}}
	if err = WriteText(f, r); err != nil {
		t.Fatal(err)
	}
}
func TestReportExitPrecedence(t *testing.T) {
	for _, tc := range []struct {
		states []string
		code   int
		status string
	}{{[]string{"PASS"}, 0, "PASS"}, {[]string{"PASS", "WARN"}, 1, "WARN"}, {[]string{"SKIP", "PASS"}, 1, "SKIP"}, {[]string{"FAIL", "ERROR", "WARN"}, 2, "ERROR"}} {
		r := Report{}
		for _, s := range tc.states {
			r.Results = append(r.Results, Result{Status: s})
		}
		r.Summarize()
		if r.ExitCode != tc.code || r.Status != tc.status {
			t.Fatal(r)
		}
	}
}
func TestInvalidConfigDoesNotCreateLog(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "results")
	c := Defaults()
	c.Ping.Count = 0
	c.Output = OutputConfig{true, dir}
	b, _ := json.Marshal(c)
	profile := profileFile(t, string(b))
	var out bytes.Buffer
	if code := CLI(context.Background(), []string{"--profile", profile, "--format", "json"}, strings.NewReader(""), &out, io.Discard, false); code != 2 {
		t.Fatal(code)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("invalid profile created directory")
	}
}

func TestCLIEndToEndJSONAndTextLog(t *testing.T) {
	tools := t.TempDir()
	scripts := map[string]string{
		"ping":       "printf '64 bytes from 192.0.2.1: icmp_seq=0 ttl=64 time=0.1 ms\\n1 packets transmitted, 1 packets received\\n'",
		"dig":        "printf ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12\\n;; flags: qr rd ra; QUERY: 1, ANSWER: 1\\n;; ANSWER SECTION:\\nexample.test. 60 IN A 192.0.2.1\\nexample.test. 60 IN AAAA 2001:db8::1\\n'",
		"traceroute": "printf '1 192.0.2.1 0.1 ms\\n'",
	}
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(tools, name), []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", tools)
	c := Defaults()
	c.Checks = []string{"icmp", "dns_udp", "dns_tcp", "mtu", "traceroute"}
	c.IPVersions = []int{4}
	c.Ping.Targets = []string{"192.0.2.1"}
	c.Ping.Count = 1
	c.DNS.Servers = []string{"192.0.2.53"}
	c.DNS.Name = "example.test"
	c.MTU.Targets = []string{"192.0.2.1"}
	c.MTU.PacketSizes = []int{64}
	c.MTU.Count = 1
	c.Traceroute.Targets = []string{"192.0.2.1"}
	c.Traceroute.MaxHops = 1
	c.Traceroute.Probes = 1
	c.Traceroute.ASLookup = false
	c.Output.Directory = filepath.Join(t.TempDir(), "results")
	for _, save := range []bool{false, true} {
		c.Output.TextLog = save
		b, _ := json.Marshal(c)
		p := profileFile(t, string(b))
		var out, stderr bytes.Buffer
		code := CLI(context.Background(), []string{"--profile", p, "--format", "json"}, strings.NewReader(""), &out, &stderr, false)
		var r Report
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatal(err, out.String())
		}
		if code != 0 || r.Status != "PASS" || len(r.Results) != 7 {
			t.Fatal(code, r, stderr.String())
		}
		entries, err := os.ReadDir(c.Output.Directory)
		if save {
			if err != nil || len(entries) != 1 {
				t.Fatal(entries, err)
			}
			data, _ := os.ReadFile(filepath.Join(c.Output.Directory, entries[0].Name()))
			if !strings.Contains(string(data), "総合: PASS") {
				t.Fatal("text log missing report")
			}
		} else if !os.IsNotExist(err) {
			t.Fatal("default run saved files")
		}
	}
}
