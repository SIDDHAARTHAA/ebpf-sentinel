package tracer

import (
	"context"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// closeReaderOnDone closes a ring buffer reader when the tracer context is canceled.
func closeReaderOnDone(ctx context.Context, reader *ringbuf.Reader) {
	<-ctx.Done()
	reader.Close()
}

// attachKprobe attaches a program to the first syscall symbol that exists on this kernel.
func attachKprobe(program *ebpf.Program, symbols []string) (link.Link, string, error) {
	var errs []string

	for _, symbol := range symbols {
		kp, err := link.Kprobe(symbol, program, nil)
		if err == nil {
			return kp, symbol, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", symbol, err))
	}

	return nil, "", fmt.Errorf("no usable kprobe symbol found (%s)", strings.Join(errs, "; "))
}

// attachKretprobe attaches a program to the first matching syscall return symbol.
func attachKretprobe(program *ebpf.Program, symbols []string) (link.Link, string, error) {
	var errs []string

	for _, symbol := range symbols {
		kp, err := link.Kretprobe(symbol, program, nil)
		if err == nil {
			return kp, symbol, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", symbol, err))
	}

	return nil, "", fmt.Errorf("no usable kretprobe symbol found (%s)", strings.Join(errs, "; "))
}
