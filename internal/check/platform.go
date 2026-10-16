package check

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Command struct {
	Name string
	Args []string
}
type CommandResult struct {
	Output string
	Err    error
}
type Runner interface {
	Run(context.Context, Command) CommandResult
	LookPath(string) (string, error)
}
type ExecRunner struct{}

func (ExecRunner) LookPath(s string) (string, error) { return exec.LookPath(s) }

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len() < 262144 {
		q := p
		if len(q) > 262144-b.Len() {
			q = q[:262144-b.Len()]
		}
		_, _ = b.Buffer.Write(q)
	}
	return n, nil
}
func (ExecRunner) Run(ctx context.Context, c Command) CommandResult {
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	// Graceful SIGINT lets ping flush the actual sent/received counters.
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 200 * time.Millisecond
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	var b limitedBuffer
	cmd.Stdout = &b
	cmd.Stderr = &b
	e := cmd.Run()
	if ctx.Err() != nil {
		e = ctx.Err()
	}
	return CommandResult{b.String(), e}
}

type Platform struct{ OS string }

func NativePlatform() Platform { return Platform{runtime.GOOS} }
func (p Platform) ping(target string, size int, df bool) (Command, error) {
	v := family(target)
	c := Command{"ping", []string{"-n", "-c", "1"}}
	switch p.OS {
	case "linux":
		c.Args = append(c.Args, "-"+strconv.Itoa(v))
		if df {
			c.Args = append(c.Args, "-M", "do")
		}
	case "darwin":
		if v == 6 {
			c.Name = "ping6"
		}
		if df {
			c.Args = append(c.Args, "-D")
			if v == 6 {
				c.Args = append(c.Args, "-m")
			}
		}
	default:
		return c, fmt.Errorf("未対応OS: %s", p.OS)
	}
	if size > 0 {
		header := 28
		if v == 6 {
			header = 48
		}
		c.Args = append(c.Args, "-s", strconv.Itoa(size-header))
	}
	c.Args = append(c.Args, target)
	return c, nil
}

// One probe per invocation allows identical bounded pacing on both operating systems,
// including macOS traceroute6 which has no sendwait option.
func (p Platform) trace(target string, hop, port, wait int) (Command, error) {
	c := Command{"traceroute", []string{"-n", "-f", strconv.Itoa(hop), "-m", strconv.Itoa(hop), "-q", "1", "-w", strconv.Itoa(wait), "-p", strconv.Itoa(port)}}
	switch p.OS {
	case "linux":
		c.Args = append(c.Args, "-"+strconv.Itoa(family(target)), "-N", "1", "-M", "default")
	case "darwin":
		if family(target) == 6 {
			c.Name = "traceroute6"
		}
	default:
		return c, fmt.Errorf("未対応OS: %s", p.OS)
	}
	c.Args = append(c.Args, target)
	return c, nil
}
func (p Platform) route(v int) (Command, error) {
	switch p.OS {
	case "linux":
		return Command{"ip", []string{"-" + strconv.Itoa(v), "route", "show", "default"}}, nil
	case "darwin":
		f := "-inet"
		if v == 6 {
			f = "-inet6"
		}
		return Command{"route", []string{"-n", "get", f, "default"}}, nil
	}
	return Command{}, fmt.Errorf("未対応OS: %s", p.OS)
}
func commandFailure(r CommandResult) (string, string) {
	s := strings.ToLower(r.Output)
	switch {
	case errors.Is(r.Err, exec.ErrNotFound), errors.Is(r.Err, os.ErrNotExist):
		return "SKIP", "依存コマンド不足"
	case strings.Contains(s, "operation not permitted"), strings.Contains(s, "permission denied"), strings.Contains(s, "must be root"), errors.Is(r.Err, os.ErrPermission):
		return "SKIP", "権限不足"
	case strings.Contains(s, "invalid option"), strings.Contains(s, "illegal option"), strings.Contains(s, "unrecognized option"), strings.Contains(s, "usage:"):
		return "SKIP", "コマンドの必要な機能が未対応"
	case strings.Contains(s, "message too long"), strings.Contains(s, "packet too big"), strings.Contains(s, "frag needed"):
		return "FAIL", "パケットサイズ制限（ローカルまたは経路上）"
	case strings.Contains(s, "network is unreachable"), strings.Contains(s, "no route to host"), strings.Contains(s, "unreachable"):
		return "FAIL", "経路なし・到達不能"
	case errors.Is(r.Err, context.DeadlineExceeded), errors.Is(r.Err, context.Canceled):
		return "FAIL", "応答待ち期限到達・取消"
	}
	if r.Err != nil {
		var exit *exec.ExitError
		if !errors.As(r.Err, &exit) {
			return "ERROR", "コマンドを起動できません"
		}
	}
	return "FAIL", "応答を確認できません"
}
func (p Platform) dependencies(c Config) map[string][]string {
	m := map[string][]string{}
	add := func(name, id string) {
		if name != "" {
			for _, s := range m[name] {
				if s == id {
					return
				}
			}
			m[name] = append(m[name], id)
		}
	}
	for _, id := range c.Checks {
		switch id {
		case "dns_udp", "dns_tcp":
			add("dig", id)
		case "connection":
			cmd, _ := p.route(4)
			add(cmd.Name, id)
		case "icmp", "mtu":
			for _, v := range c.IPVersions {
				t := "192.0.2.1"
				if v == 6 {
					t = "2001:db8::1"
				}
				cmd, _ := p.ping(t, 64, id == "mtu")
				add(cmd.Name, id)
			}
		case "traceroute":
			for _, v := range c.IPVersions {
				t := "192.0.2.1"
				if v == 6 {
					t = "2001:db8::1"
				}
				cmd, _ := p.trace(t, 1, 33434, 1)
				add(cmd.Name, id)
			}
		}
	}
	return m
}
func waitUntil(ctx context.Context, t time.Time) bool {
	d := time.Until(t)
	if d <= 0 {
		return ctx.Err() == nil
	}
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-tm.C:
		return true
	case <-ctx.Done():
		return false
	}
}
