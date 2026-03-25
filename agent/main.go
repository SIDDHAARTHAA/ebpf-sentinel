package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/siddhaarthaa/ebpf-sentinel/agent/tracer"
)

type tracerResult struct {
	name string
	err  error
}

// main starts the active tracers, prints their events, and exits cleanly on shutdown.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	acceptEvents := make(chan tracer.AcceptEvent, 128)
	connectEvents := make(chan tracer.ConnectEvent, 128)
	execEvents := make(chan tracer.ExecEvent, 128)
	errCh := make(chan tracerResult, 3)

	go runAcceptTracer(ctx, acceptEvents, errCh)
	go runConnectTracer(ctx, connectEvents, errCh)
	go runExecTracer(ctx, execEvents, errCh)

	for {
		select {
		case <-ctx.Done():
			return
		case result := <-errCh:
			if result.err != nil {
				fmt.Fprintf(os.Stderr, "sentinel (%s): %v\n", result.name, result.err)
				os.Exit(1)
			}
		case event := <-acceptEvents:
			printAcceptEvent(event)
		case event := <-connectEvents:
			printConnectEvent(event)
		case event := <-execEvents:
			printExecEvent(event)
		}
	}
}

// runAcceptTracer starts the accept tracer and reports its exit status.
func runAcceptTracer(ctx context.Context, events chan<- tracer.AcceptEvent, errCh chan<- tracerResult) {
	errCh <- tracerResult{name: "accept", err: tracer.RunAccept(ctx, events)}
}

// runConnectTracer starts the connect tracer and reports its exit status.
func runConnectTracer(ctx context.Context, events chan<- tracer.ConnectEvent, errCh chan<- tracerResult) {
	errCh <- tracerResult{name: "connect", err: tracer.RunConnect(ctx, events)}
}

// runExecTracer starts the exec tracer and reports its exit status.
func runExecTracer(ctx context.Context, events chan<- tracer.ExecEvent, errCh chan<- tracerResult) {
	errCh <- tracerResult{name: "exec", err: tracer.RunExec(ctx, events)}
}

// printAcceptEvent renders an accepted inbound connection event.
func printAcceptEvent(event tracer.AcceptEvent) {
	fmt.Printf(
		"[ACCEPT] pid=%d comm=%s fd=%d remote=%s:%d\n",
		event.PID,
		event.Command(),
		event.FD,
		event.RemoteIP(),
		event.Port,
	)
}

// printConnectEvent renders an outbound connection attempt event.
func printConnectEvent(event tracer.ConnectEvent) {
	fmt.Printf(
		"[CONNECT] pid=%d comm=%s fd=%d remote=%s:%d\n",
		event.PID,
		event.Command(),
		event.FD,
		event.RemoteIP(),
		event.Port,
	)
}

// printExecEvent renders a process execution event with parent-child context.
func printExecEvent(event tracer.ExecEvent) {
	fmt.Printf(
		"[EXEC] pid=%d ppid=%d comm=%s\n",
		event.PID,
		event.PPID,
		event.Command(),
	)
}
