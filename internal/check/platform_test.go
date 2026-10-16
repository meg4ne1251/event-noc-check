package check

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPlatformArguments(t *testing.T) {
	for _, tc := range []struct {
		os, target, name string
		args             []string
	}{
		{"darwin", "192.0.2.1", "ping", []string{"-n", "-c", "1", "-D", "-s", "1472", "192.0.2.1"}},
		{"darwin", "2001:db8::1", "ping6", []string{"-n", "-c", "1", "-D", "-m", "-s", "1452", "2001:db8::1"}},
		{"linux", "2001:db8::1", "ping", []string{"-n", "-c", "1", "-6", "-M", "do", "-s", "1452", "2001:db8::1"}},
	} {
		cmd, err := (Platform{tc.os}).ping(tc.target, 1500, true)
		if err != nil || cmd.Name != tc.name || !reflect.DeepEqual(cmd.Args, tc.args) {
			t.Fatalf("%s: %+v %v", tc.os, cmd, err)
		}
	}
	cmd, err := (Platform{"darwin"}).trace("2001:db8::1", 2, 33435, 1)
	if err != nil || cmd.Name != "traceroute6" || strings.Contains(strings.Join(cmd.Args, " "), " -6") {
		t.Fatal(cmd, err)
	}
	if _, err = (Platform{"windows"}).ping("192.0.2.1", 64, true); err == nil {
		t.Fatal("unsupported OS accepted")
	}
}
func TestCommandClassifications(t *testing.T) {
	for _, tc := range []struct {
		o      CommandResult
		status string
	}{
		{CommandResult{Err: exec.ErrNotFound}, "SKIP"}, {CommandResult{Output: "Operation not permitted", Err: errors.New("exit")}, "SKIP"},
		{CommandResult{Output: "invalid option -- M", Err: errors.New("exit")}, "SKIP"},
		{CommandResult{Output: "Message too long", Err: errors.New("exit")}, "FAIL"},
		{CommandResult{Err: context.DeadlineExceeded}, "FAIL"}, {CommandResult{Err: errors.New("spawn failure")}, "ERROR"},
	} {
		s, _ := commandFailure(tc.o)
		if s != tc.status {
			t.Fatalf("%+v: %s", tc, s)
		}
	}
}
func TestExecCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	o := (ExecRunner{}).Run(ctx, Command{"sleep", []string{"10"}})
	if !errors.Is(o.Err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("cancellation failed: %+v", o)
	}
}
