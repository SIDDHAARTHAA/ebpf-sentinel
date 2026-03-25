package tracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86 -I../../ebpf" Accept ../../ebpf/accept.bpf.c

type AcceptEvent struct {
	PID    uint32
	FD     uint32
	Family uint16
	Port   uint16
	Addr   [16]byte
	Comm   [16]byte
}

// Command returns the process name without trailing null bytes.
func (e AcceptEvent) Command() string {
	return strings.TrimRight(string(e.Comm[:]), "\x00")
}

// RemoteIP formats the captured peer address into a printable IP string.
func (e AcceptEvent) RemoteIP() string {
	switch e.Family {
	case 2:
		return net.IP(e.Addr[:4]).String()
	case 10:
		return net.IP(e.Addr[:]).String()
	default:
		return "unknown"
	}
}

// RunAccept loads the accept probe, reads events from the ring buffer, and forwards them.
func RunAccept(ctx context.Context, sink chan<- AcceptEvent) error {
	_ = rlimit.RemoveMemlock()

	var objs AcceptObjects
	if err := LoadAcceptObjects(&objs, nil); err != nil {
		return fmt.Errorf("load accept objects: %w", err)
	}
	defer objs.Close()

	entryLink, entrySymbol, err := attachKprobe(objs.TraceAccept4Enter, accept4Symbols())
	if err != nil {
		return fmt.Errorf("attach accept entry probe: %w", err)
	}
	defer entryLink.Close()

	exitLink, exitSymbol, err := attachKretprobe(objs.TraceAccept4Exit, accept4Symbols())
	if err != nil {
		return fmt.Errorf("attach accept exit probe: %w", err)
	}
	defer exitLink.Close()

	reader, err := ringbuf.NewReader(objs.AcceptEvents)
	if err != nil {
		return fmt.Errorf("open accept ring buffer: %w", err)
	}
	defer reader.Close()

	go closeReaderOnDone(ctx, reader)

	_ = entrySymbol
	_ = exitSymbol

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, context.Canceled) {
				return nil
			}
			return fmt.Errorf("read accept ring buffer: %w", err)
		}

		var event AcceptEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("decode accept event: %w", err)
		}

		select {
		case sink <- event:
		case <-ctx.Done():
			return nil
		}
	}
}

// accept4Symbols lists the syscall symbols used for accept4 across common x86 kernels.
func accept4Symbols() []string {
	return []string{
		"__x64_sys_accept4",
		"__sys_accept4",
		"sys_accept4",
		"__se_sys_accept4",
	}
}
