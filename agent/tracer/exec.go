package tracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86 -I../../ebpf" Exec ../../ebpf/exec.bpf.c

type ExecEvent struct {
	PID  uint32
	PPID uint32
	Comm [16]byte
}

// Command returns the executed process name without trailing null bytes.
func (e ExecEvent) Command() string {
	return strings.TrimRight(string(e.Comm[:]), "\x00")
}

// RunExec loads the sched_process_exec tracepoint and forwards execution events.
func RunExec(ctx context.Context, sink chan<- ExecEvent) error {
	_ = rlimit.RemoveMemlock()

	var objs ExecObjects
	if err := LoadExecObjects(&objs, nil); err != nil {
		return fmt.Errorf("load exec objects: %w", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceSchedProcessExec, nil)
	if err != nil {
		return fmt.Errorf("attach exec tracepoint: %w", err)
	}
	defer tp.Close()

	reader, err := ringbuf.NewReader(objs.ExecEvents)
	if err != nil {
		return fmt.Errorf("open exec ring buffer: %w", err)
	}
	defer reader.Close()

	probeStats := registerProbeRuntime("exec")
	probeStats.setRingbufCapacity(reader.BufferSize())
	go pollDropCounter(ctx, probeStats, objs.ExecDropStats)
	go closeReaderOnDone(ctx, reader)

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, context.Canceled) {
				return nil
			}
			return fmt.Errorf("read exec ring buffer: %w", err)
		}

		var event ExecEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("decode exec event: %w", err)
		}

		select {
		case sink <- event:
		case <-ctx.Done():
			if total, err := lookupDropCounter(objs.ExecDropStats); err == nil {
				probeStats.setEventsDroppedTotal(total)
			}
			return nil
		}
	}
}
