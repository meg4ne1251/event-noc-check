package check

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type Result struct {
	Check     string  `json:"check"`
	Target    string  `json:"target"`
	IPVersion int     `json:"ip_version"`
	Status    string  `json:"status"`
	Reason    string  `json:"reason"`
	ElapsedMS float64 `json:"elapsed_ms"`
	Details   any     `json:"details,omitempty"`
}
type Report struct {
	SchemaVersion int       `json:"schema_version"`
	StartedAt     time.Time `json:"started_at"`
	Config        Config    `json:"config"`
	Results       []Result  `json:"results"`
	Status        string    `json:"status"`
	ExitCode      int       `json:"exit_code"`
	ElapsedMS     float64   `json:"elapsed_ms"`
	Error         string    `json:"error,omitempty"`
}

func (r *Report) Summarize() {
	r.Status = "PASS"
	r.ExitCode = 0
	rank := map[string]int{"PASS": 0, "WARN": 1, "SKIP": 2, "FAIL": 3, "ERROR": 4}
	for _, v := range r.Results {
		if rank[v.Status] > rank[r.Status] {
			r.Status = v.Status
		}
		if v.Status == "ERROR" {
			r.ExitCode = 2
		} else if v.Status != "PASS" && r.ExitCode == 0 {
			r.ExitCode = 1
		}
	}
	if r.Error != "" {
		r.Status = "ERROR"
		r.ExitCode = 2
	}
}
func WriteText(w io.Writer, r Report) error {
	b, e := json.Marshal(r.Config)
	if e != nil {
		return e
	}
	if _, e = fmt.Fprintf(w, "noc-check %s\nプロファイル: %s\n適用条件: %s\n", r.StartedAt.Format(time.RFC3339), r.Config.Name, b); e != nil {
		return e
	}
	for _, v := range r.Results {
		path := fmt.Sprintf("IPv%d", v.IPVersion)
		if v.IPVersion == 0 {
			path = "OS設定経由・通信経路不明"
		}
		if _, e = fmt.Fprintf(w, "[%s] %s %s %s (%.1f ms): %s\n", v.Status, v.Check, path, v.Target, v.ElapsedMS, v.Reason); e != nil {
			return e
		}
		if v.Details != nil {
			b, e = json.MarshalIndent(v.Details, "  ", "  ")
			if e != nil {
				return e
			}
			if _, e = fmt.Fprintf(w, "  %s\n", b); e != nil {
				return e
			}
		}
	}
	_, e = fmt.Fprintf(w, "総合: %s / 終了コード: %d（設定された検査条件の判定）\n", r.Status, r.ExitCode)
	if r.Error != "" {
		_, e = fmt.Fprintln(w, "エラー:", r.Error)
	}
	return e
}
