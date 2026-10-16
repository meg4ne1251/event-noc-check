package check

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

type sizesFlag []int

func (s *sizesFlag) String() string { return fmt.Sprint([]int(*s)) }
func (s *sizesFlag) Set(v string) error {
	n, e := strconv.Atoi(v)
	if e != nil {
		return fmt.Errorf("サイズは整数で指定してください")
	}
	*s = append(*s, n)
	return nil
}
func dependencyGuidance(w io.Writer, p Platform) {
	if p.OS == "darwin" {
		fmt.Fprintln(w, "macOS標準のping/ping6、route、traceroute/traceroute6、digを確認してください。PATHやOSの管理者向けツールの導入手順を確認してください。")
		return
	}
	data, _ := os.ReadFile("/etc/os-release")
	s := string(data)
	switch {
	case strings.Contains(s, "ID=ubuntu"), strings.Contains(s, "ID=debian"), strings.Contains(s, "ID_LIKE=debian"):
		fmt.Fprintln(w, "Debian/Ubuntu: apt install iputils-ping iproute2 dnsutils traceroute を管理者に依頼してください。")
	case strings.Contains(s, "ID=fedora"), strings.Contains(s, "ID=rhel"), strings.Contains(s, "ID=\"rhel\""):
		fmt.Fprintln(w, "Fedora/RHEL: dnf install iputils iproute bind-utils traceroute を管理者に依頼してください。")
	default:
		fmt.Fprintln(w, "ディストリビューションの公式手順でiputils ping・iproute2・BIND dig・tracerouteの導入方法を確認してください。")
	}
}
func missingDependencies(c Config, p Platform, runner Runner, in io.Reader, errOut io.Writer, policy string, interactive bool) error {
	deps := p.dependencies(c)
	missing := []string{}
	for name := range deps {
		if _, e := runner.LookPath(name); e != nil {
			missing = append(missing, name)
		}
	}
	slices.Sort(missing)
	if len(missing) == 0 {
		return nil
	}
	for _, name := range missing {
		fmt.Fprintf(errOut, "依存コマンド不足: %s（%s）\n", name, strings.Join(deps[name], ", "))
	}
	dependencyGuidance(errOut, p)
	if policy == "skip" {
		return nil
	}
	if policy == "abort" || !interactive {
		return fmt.Errorf("依存不足のため中断。続行する場合は --on-missing skip を明示してください")
	}
	fmt.Fprint(errOut, "不足項目をスキップして続行しますか? [y/N]: ")
	line, e := bufio.NewReader(in).ReadString('\n')
	if e == nil && (strings.TrimSpace(strings.ToLower(line)) == "y" || strings.TrimSpace(strings.ToLower(line)) == "yes") {
		return nil
	}
	return fmt.Errorf("依存不足のため中断しました")
}
func prepareLog(c Config) (*os.File, error) {
	if !c.Output.TextLog {
		return nil, nil
	}
	if err := os.MkdirAll(c.Output.Directory, 0700); err != nil {
		return nil, err
	}
	return os.CreateTemp(c.Output.Directory, "noc-check-"+time.Now().UTC().Format("20060102T150405Z")+"-*.log")
}

// CLI keeps all progress/prompts on stderr and produces one JSON object on stdout.
func CLI(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer, interactive bool) int {
	fs := flag.NewFlagSet("noc-check", flag.ContinueOnError)
	fs.SetOutput(errOut)
	profile := fs.String("profile", "", "検査プロファイルJSON")
	format := fs.String("format", "text", "出力形式: text / json")
	v4 := fs.Bool("ipv4-only", false, "IPv4のみ検査")
	v6 := fs.Bool("ipv6-only", false, "IPv6のみ検査")
	noAS := fs.Bool("no-as-lookup", false, "AS情報照会を無効化")
	missing := fs.String("on-missing", "ask", "依存不足時: skip / abort（省略時は端末のみ対話）")
	var sizes sizesFlag
	fs.Var(&sizes, "packet-size", "IPパケット全体のバイト数（複数指定可能）")
	// Detect JSON mode even if parsing fails before the flag is reached.
	requestedJSON := false
	for i, a := range args {
		if a == "--format=json" || a == "-format=json" || (a == "--format" || a == "-format") && i+1 < len(args) && args[i+1] == "json" {
			requestedJSON = true
		}
	}
	fail := func(e error) int {
		if requestedJSON || *format == "json" {
			_ = json.NewEncoder(out).Encode(Report{SchemaVersion: 1, StartedAt: time.Now().UTC(), Status: "ERROR", ExitCode: 2, Error: e.Error(), Results: []Result{}})
		} else {
			fmt.Fprintln(errOut, "エラー:", e)
		}
		return 2
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return fail(err)
	}
	if fs.NArg() != 0 {
		return fail(fmt.Errorf("位置引数は指定できません"))
	}
	if *format != "text" && *format != "json" {
		return fail(fmt.Errorf("formatはtextまたはjsonです"))
	}
	if *missing != "ask" && *missing != "skip" && *missing != "abort" {
		return fail(fmt.Errorf("on-missingはskipまたはabortです"))
	}
	if *v4 && *v6 {
		return fail(fmt.Errorf("ipv4-onlyとipv6-onlyは同時指定できません"))
	}
	c := Defaults()
	if *profile != "" {
		var err error
		c, err = Load(*profile)
		if err != nil {
			return fail(err)
		}
	}
	if *v4 {
		c.IPVersions = []int{4}
	}
	if *v6 {
		c.IPVersions = []int{6}
	}
	if *noAS {
		c.Traceroute.ASLookup = false
	}
	if len(sizes) > 0 {
		c.MTU.PacketSizes = sizes
	}
	if err := c.Validate(); err != nil {
		return fail(err)
	}
	e := NewEngine(c)
	if e.Platform.OS != "linux" && e.Platform.OS != "darwin" {
		return fail(fmt.Errorf("対応対象OSはmacOS/Linuxです"))
	}
	if err := missingDependencies(c, e.Platform, e.Runner, in, errOut, *missing, interactive); err != nil {
		return fail(err)
	}
	log, err := prepareLog(c)
	if err != nil {
		return fail(fmt.Errorf("ログ保存先の準備失敗: %w", err))
	}
	r := e.Run(ctx)
	if log != nil {
		writeErr := WriteText(log, r)
		syncErr := log.Sync()
		closeErr := log.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			r.Error = "ログ保存失敗"
			r.Summarize()
		} else {
			fmt.Fprintln(errOut, "テキストログ:", filepath.Clean(log.Name()))
		}
	}
	if *format == "json" {
		err = json.NewEncoder(out).Encode(r)
	} else {
		err = WriteText(out, r)
	}
	if err != nil {
		fmt.Fprintln(errOut, "結果出力失敗:", err)
		return 2
	}
	return r.ExitCode
}
