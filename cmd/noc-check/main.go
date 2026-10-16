package main

import (
	"context"
	"event-noc-check/internal/check"
	"os"
	"os/signal"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	// Opening the controlling terminal prevents redirected stdin from becoming an
	// accidental interactive input source.
	in := os.Stdin
	interactive := false
	if st, err := os.Stdin.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
		if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
			defer tty.Close()
			in = tty
			interactive = true
		}
	}
	os.Exit(check.CLI(ctx, os.Args[1:], in, os.Stdout, os.Stderr, interactive))
}
