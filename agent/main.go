package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/siddhaarthaa/ebpf-sentinel/agent/tracer"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	events := make(chan tracer.AcceptEvent, 128)
	errCh := make(chan error, 1)

	go func() {
		errCh <- tracer.RunAccept(ctx, events)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-errCh:
			if err != nil {
				fmt.Fprintf(os.Stderr, "sentinel: %v\n", err)
				os.Exit(1)
			}
			return
		case event := <-events:
			fmt.Printf(
				"[ACCEPT] pid=%d comm=%s fd=%d remote=%s:%d\n",
				event.PID,
				event.Command(),
				event.FD,
				event.RemoteIP(),
				event.Port,
			)
		}
	}
}
