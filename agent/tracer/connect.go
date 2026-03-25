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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86 -I../../ebpf" Connect ../../ebpf/connect.bpf.c

type ConnectEvent struct {
	PID    uint32
	FD     uint32
	Family uint16
	Port   uint16
	Addr   [16]byte
	Comm   [16]byte
}

// Command returns the process name without trailing null bytes.
func (e ConnectEvent) Command() string {
	return strings.TrimRight(string(e.Comm[:]), "\x00")
}

// RemoteIP formats the captured destination address into a printable IP string.
func (e ConnectEvent) RemoteIP() string {
	switch e.Family {
	case 2:
		return net.IP(e.Addr[:4]).String()
	case 10:
		return net.IP(e.Addr[:]).String()
	default:
		return "unknown"
	}
}

// RunConnect loads the connect probe, reads events from the ring buffer, and forwards them.
func RunConnect(ctx context.Context, sink chan<- ConnectEvent) error {
	_ = rlimit.RemoveMemlock()

	var objs ConnectObjects
	if err := LoadConnectObjects(&objs, nil); err != nil {
		return fmt.Errorf("load connect objects: %w", err)
	}
	defer objs.Close()

	connectLink, connectSymbol, err := attachKprobe(objs.TraceConnectEnter, connectSymbols())
	if err != nil {
		return fmt.Errorf("attach connect probe: %w", err)
	}
	defer connectLink.Close()

	reader, err := ringbuf.NewReader(objs.ConnectEvents)
	if err != nil {
		return fmt.Errorf("open connect ring buffer: %w", err)
	}
	defer reader.Close()

	go closeReaderOnDone(ctx, reader)

	_ = connectSymbol

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, context.Canceled) {
				return nil
			}
			return fmt.Errorf("read connect ring buffer: %w", err)
		}

		var event ConnectEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("decode connect event: %w", err)
		}

		select {
		case sink <- event:
		case <-ctx.Done():
			return nil
		}
	}
}

// connectSymbols lists the syscall symbols used for connect across common x86 kernels.
func connectSymbols() []string {
	return []string{
		"__sys_connect",
		"__x64_sys_connect",
		"sys_connect",
		"__se_sys_connect",
	}
}
