package flow

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/siddhaarthaa/ebpf-sentinel/agent/tracer"
)

var httpMethods = []string{
	"GET ",
	"POST ",
	"PUT ",
	"PATCH ",
	"DELETE ",
	"HEAD ",
	"OPTIONS ",
}

type FlowTracker struct {
	mu       sync.Mutex
	ttl      time.Duration
	partials map[ConnectionKey]PartialFlow
}

// NewFlowTracker creates the in-memory state used to match HTTP requests and responses.
func NewFlowTracker(ttl time.Duration) *FlowTracker {
	return &FlowTracker{
		ttl:      ttl,
		partials: make(map[ConnectionKey]PartialFlow),
	}
}

// RunEvicter periodically removes stale partial flows so the tracker does not grow forever.
func (t *FlowTracker) RunEvicter(ctx context.Context) {
	ticker := time.NewTicker(t.ttl / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			t.evictOlderThan(now.Add(-t.ttl))
		}
	}
}

// HandleIOEvent updates tracker state and returns a completed flow when a response closes it.
func (t *FlowTracker) HandleIOEvent(event tracer.IOEvent) *HTTPFlow {
	if event.IsWrite() {
		return t.handleWrite(event)
	}

	if event.IsRead() {
		return t.handleRead(event)
	}

	return nil
}

// handleWrite opens a partial flow when it sees an HTTP request line.
func (t *FlowTracker) handleWrite(event tracer.IOEvent) *HTTPFlow {
	method, path, ok := parseHTTPRequestLine(event.Payload())
	if !ok {
		return nil
	}

	now := event.Timestamp()
	key := ConnectionKey{PID: event.PID, FD: event.FD}

	t.mu.Lock()
	defer t.mu.Unlock()

	// TODO: Handle requests whose headers span multiple write syscalls.
	t.partials[key] = PartialFlow{
		Key:       key,
		Comm:      event.Command(),
		Method:    method,
		Path:      path,
		StartedAt: now,
		UpdatedAt: now,
	}

	return nil
}

// handleRead closes a partial flow when it sees an HTTP response status line.
func (t *FlowTracker) handleRead(event tracer.IOEvent) *HTTPFlow {
	statusCode, ok := parseHTTPStatusLine(event.Payload())
	if !ok {
		return nil
	}

	now := event.Timestamp()
	key := ConnectionKey{PID: event.PID, FD: event.FD}

	t.mu.Lock()
	defer t.mu.Unlock()

	partial, exists := t.partials[key]
	if !exists {
		return nil
	}

	delete(t.partials, key)

	return &HTTPFlow{
		PID:        partial.Key.PID,
		FD:         partial.Key.FD,
		Comm:       partial.Comm,
		Method:     partial.Method,
		Path:       partial.Path,
		StatusCode: statusCode,
		StartedAt:  partial.StartedAt,
		FinishedAt: now,
		Duration:   now.Sub(partial.StartedAt),
	}
}

// evictOlderThan drops partial flows that have not been updated within the configured TTL.
func (t *FlowTracker) evictOlderThan(cutoff time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for key, partial := range t.partials {
		if partial.UpdatedAt.Before(cutoff) {
			delete(t.partials, key)
		}
	}
}

// parseHTTPRequestLine extracts the method and path from the first HTTP request line.
func parseHTTPRequestLine(payload []byte) (string, string, bool) {
	line := firstLine(payload)
	if line == "" {
		return "", "", false
	}

	for _, prefix := range httpMethods {
		if strings.HasPrefix(line, prefix) {
			parts := strings.Split(line, " ")
			if len(parts) < 2 {
				return "", "", false
			}
			return parts[0], parts[1], true
		}
	}

	return "", "", false
}

// parseHTTPStatusLine extracts the numeric status code from the first HTTP response line.
func parseHTTPStatusLine(payload []byte) (int, bool) {
	line := firstLine(payload)
	if !strings.HasPrefix(line, "HTTP/1.") {
		return 0, false
	}

	parts := strings.Split(line, " ")
	if len(parts) < 2 {
		return 0, false
	}

	statusCode, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, false
	}

	return statusCode, true
}

// firstLine returns the first newline-delimited line from a captured payload.
func firstLine(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}

	line, _, _ := bytes.Cut(payload, []byte("\n"))
	return strings.TrimSpace(string(line))
}
