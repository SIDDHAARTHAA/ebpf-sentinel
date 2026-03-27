package flow

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/siddhaarthaa/ebpf-sentinel/agent/k8s"
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
	mu          sync.Mutex
	ttl         time.Duration
	partials    map[ConnectionKey]PartialFlow
	connections map[ConnectionKey]Connection
}

// NewFlowTracker creates the in-memory state used to match HTTP requests and responses.
func NewFlowTracker(ttl time.Duration) *FlowTracker {
	return &FlowTracker{
		ttl:         ttl,
		partials:    make(map[ConnectionKey]PartialFlow),
		connections: make(map[ConnectionKey]Connection),
	}
}

// HandleAccept stores metadata for an inbound connection so completed flows can be enriched later.
func (t *FlowTracker) HandleAccept(event tracer.AcceptEvent, metadata k8s.ProcessMetadata) {
	t.storeConnection(connectionFromAccept(event, metadata))
}

// HandleConnect stores metadata for an outbound connection so completed flows can be enriched later.
func (t *FlowTracker) HandleConnect(event tracer.ConnectEvent, metadata k8s.ProcessMetadata) {
	t.storeConnection(connectionFromConnect(event, metadata))
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

	connection := t.connectionForEvent(event, now)

	// TODO: Handle requests whose headers span multiple write syscalls.
	t.partials[key] = PartialFlow{
		Key:        key,
		Connection: connection,
		Method:     method,
		Path:       path,
		StartedAt:  now,
		UpdatedAt:  now,
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
		PID:           partial.Key.PID,
		FD:            partial.Key.FD,
		Comm:          partial.Connection.Comm,
		Namespace:     partial.Connection.Namespace,
		PodName:       partial.Connection.PodName,
		ContainerID:   partial.Connection.ContainerID,
		ContainerName: partial.Connection.ContainerName,
		Method:        partial.Method,
		Path:          partial.Path,
		StatusCode:    statusCode,
		RemoteIP:      partial.Connection.RemoteIP,
		RemotePort:    partial.Connection.RemotePort,
		StartedAt:     partial.StartedAt,
		FinishedAt:    now,
		Duration:      now.Sub(partial.StartedAt),
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

	for key, connection := range t.connections {
		if connection.LastSeen.Before(cutoff) {
			delete(t.connections, key)
		}
	}
}

// storeConnection caches per-fd metadata for later HTTP flow enrichment.
func (t *FlowTracker) storeConnection(connection Connection) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.connections[connection.Key] = connection
}

// connectionForEvent finds the latest connection metadata for an IO event or synthesizes a fallback.
func (t *FlowTracker) connectionForEvent(event tracer.IOEvent, now time.Time) Connection {
	key := ConnectionKey{PID: event.PID, FD: event.FD}

	connection, exists := t.connections[key]
	if !exists {
		return defaultConnectionForEvent(event, now)
	}

	connection.LastSeen = now
	t.connections[key] = connection
	return connection
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

// connectionFromAccept converts an accept event into reusable connection metadata.
func connectionFromAccept(event tracer.AcceptEvent, metadata k8s.ProcessMetadata) Connection {
	now := time.Now()

	return Connection{
		Key:           ConnectionKey{PID: event.PID, FD: event.FD},
		Comm:          event.Command(),
		Namespace:     metadata.Namespace,
		PodName:       metadata.PodName,
		ContainerID:   metadata.ContainerID,
		ContainerName: metadata.ContainerName,
		RemoteIP:      event.RemoteIP(),
		RemotePort:    event.Port,
		LastSeen:      now,
		Direction:     "inbound",
	}
}

// connectionFromConnect converts a connect event into reusable connection metadata.
func connectionFromConnect(event tracer.ConnectEvent, metadata k8s.ProcessMetadata) Connection {
	now := time.Now()

	return Connection{
		Key:           ConnectionKey{PID: event.PID, FD: event.FD},
		Comm:          event.Command(),
		Namespace:     metadata.Namespace,
		PodName:       metadata.PodName,
		ContainerID:   metadata.ContainerID,
		ContainerName: metadata.ContainerName,
		RemoteIP:      event.RemoteIP(),
		RemotePort:    event.Port,
		LastSeen:      now,
		Direction:     "outbound",
	}
}

// defaultConnectionForEvent synthesizes fallback connection metadata when no socket event was seen.
func defaultConnectionForEvent(event tracer.IOEvent, now time.Time) Connection {
	return Connection{
		Key:        ConnectionKey{PID: event.PID, FD: event.FD},
		Comm:       event.Command(),
		Namespace:  "host",
		PodName:    "host",
		RemoteIP:   "unknown",
		RemotePort: 0,
		LastSeen:   now,
		Direction:  "unknown",
	}
}
