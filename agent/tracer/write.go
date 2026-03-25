package tracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86 -I../../ebpf" Write ../../ebpf/write.bpf.c

const (
	ioOpRead  = 1
	ioOpWrite = 2
)

type IOEvent struct {
	PID     uint32
	FD      uint32
	TSNs    uint64
	DataLen uint32
	Op      uint8
	Pad     [3]byte
	Comm    [16]byte
	Data    [256]byte
}

// Command returns the process name without trailing null bytes.
func (e IOEvent) Command() string {
	return strings.TrimRight(string(e.Comm[:]), "\x00")
}

// Payload returns only the valid captured bytes for this IO event.
func (e IOEvent) Payload() []byte {
	dataLen := int(e.DataLen)
	if dataLen > len(e.Data) {
		dataLen = len(e.Data)
	}
	return e.Data[:dataLen]
}

// IsRead reports whether this event came from a read syscall.
func (e IOEvent) IsRead() bool {
	return e.Op == ioOpRead
}

// IsWrite reports whether this event came from a write syscall.
func (e IOEvent) IsWrite() bool {
	return e.Op == ioOpWrite
}

// Timestamp converts the kernel monotonic timestamp into a Go time.Time surrogate.
func (e IOEvent) Timestamp() time.Time {
	return time.Unix(0, int64(e.TSNs))
}

// RunWrite loads the IO probes, reads events from the ring buffer, and forwards them.
func RunWrite(ctx context.Context, sink chan<- IOEvent) error {
	_ = rlimit.RemoveMemlock()

	var objs WriteObjects
	if err := LoadWriteObjects(&objs, nil); err != nil {
		return fmt.Errorf("load write objects: %w", err)
	}
	defer objs.Close()

	writeLink, writeSymbol, err := attachKprobe(objs.TraceWriteEnter, writeSymbols())
	if err != nil {
		return fmt.Errorf("attach write probe: %w", err)
	}
	defer writeLink.Close()

	sendtoLink, sendtoSymbol, err := attachKprobe(objs.TraceSendtoEnter, sendtoSymbols())
	if err != nil {
		return fmt.Errorf("attach sendto probe: %w", err)
	}
	defer sendtoLink.Close()

	readEntryLink, readEntrySymbol, err := attachKprobe(objs.TraceReadEnter, readSymbols())
	if err != nil {
		return fmt.Errorf("attach read entry probe: %w", err)
	}
	defer readEntryLink.Close()

	readExitLink, readExitSymbol, err := attachKretprobe(objs.TraceReadExit, readSymbols())
	if err != nil {
		return fmt.Errorf("attach read exit probe: %w", err)
	}
	defer readExitLink.Close()

	recvfromEntryLink, recvfromEntrySymbol, err := attachKprobe(objs.TraceRecvfromEnter, recvfromSymbols())
	if err != nil {
		return fmt.Errorf("attach recvfrom entry probe: %w", err)
	}
	defer recvfromEntryLink.Close()

	recvfromExitLink, recvfromExitSymbol, err := attachKretprobe(objs.TraceRecvfromExit, recvfromSymbols())
	if err != nil {
		return fmt.Errorf("attach recvfrom exit probe: %w", err)
	}
	defer recvfromExitLink.Close()

	reader, err := ringbuf.NewReader(objs.IoEvents)
	if err != nil {
		return fmt.Errorf("open io ring buffer: %w", err)
	}
	defer reader.Close()

	go closeReaderOnDone(ctx, reader)

	_ = writeSymbol
	_ = sendtoSymbol
	_ = readEntrySymbol
	_ = readExitSymbol
	_ = recvfromEntrySymbol
	_ = recvfromExitSymbol

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, context.Canceled) {
				return nil
			}
			return fmt.Errorf("read io ring buffer: %w", err)
		}

		var event IOEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("decode io event: %w", err)
		}

		select {
		case sink <- event:
		case <-ctx.Done():
			return nil
		}
	}
}

// writeSymbols lists the syscall symbols used for write across common x86 kernels.
func writeSymbols() []string {
	return []string{
		"__sys_write",
		"__x64_sys_write",
		"sys_write",
		"__se_sys_write",
	}
}

// sendtoSymbols lists the syscall symbols used for sendto across common x86 kernels.
func sendtoSymbols() []string {
	return []string{
		"__sys_sendto",
		"__x64_sys_sendto",
		"sys_sendto",
		"__se_sys_sendto",
	}
}

// readSymbols lists the syscall symbols used for read across common x86 kernels.
func readSymbols() []string {
	return []string{
		"__sys_read",
		"__x64_sys_read",
		"sys_read",
		"__se_sys_read",
	}
}

// recvfromSymbols lists the syscall symbols used for recvfrom across common x86 kernels.
func recvfromSymbols() []string {
	return []string{
		"__sys_recvfrom",
		"__x64_sys_recvfrom",
		"sys_recvfrom",
		"__se_sys_recvfrom",
	}
}
