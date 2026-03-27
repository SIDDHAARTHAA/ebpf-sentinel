package tracer

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
)

type ProbeSnapshot struct {
	Probe                string
	EventsDroppedTotal   uint64
	RingbufCapacityBytes int
}

type probeRuntime struct {
	ringbufCapacityBytes atomic.Int64
	eventsDroppedTotal   atomic.Uint64
}

var (
	probeRuntimeMu sync.Mutex
	probeRuntimes  = make(map[string]*probeRuntime)
)

// registerProbeRuntime creates or reuses a metrics bucket for one probe.
func registerProbeRuntime(probe string) *probeRuntime {
	probeRuntimeMu.Lock()
	defer probeRuntimeMu.Unlock()

	stats, exists := probeRuntimes[probe]
	if exists {
		return stats
	}

	stats = &probeRuntime{}
	probeRuntimes[probe] = stats
	return stats
}

// setRingbufCapacity records the ring buffer size for one probe.
func (p *probeRuntime) setRingbufCapacity(size int) {
	p.ringbufCapacityBytes.Store(int64(size))
}

// setEventsDroppedTotal records the latest kernel-side drop counter for one probe.
func (p *probeRuntime) setEventsDroppedTotal(total uint64) {
	p.eventsDroppedTotal.Store(total)
}

// SnapshotProbeMetrics returns a stable snapshot of per-probe runtime metrics.
func SnapshotProbeMetrics() []ProbeSnapshot {
	probeRuntimeMu.Lock()
	defer probeRuntimeMu.Unlock()

	probes := make([]string, 0, len(probeRuntimes))
	for probe := range probeRuntimes {
		probes = append(probes, probe)
	}
	sort.Strings(probes)

	snapshots := make([]ProbeSnapshot, 0, len(probes))
	for _, probe := range probes {
		stats := probeRuntimes[probe]
		snapshots = append(snapshots, ProbeSnapshot{
			Probe:                probe,
			EventsDroppedTotal:   stats.eventsDroppedTotal.Load(),
			RingbufCapacityBytes: int(stats.ringbufCapacityBytes.Load()),
		})
	}

	return snapshots
}

// pollDropCounter keeps a userspace snapshot of the kernel drop counter map up to date.
func pollDropCounter(ctx context.Context, stats *probeRuntime, dropMap *ebpf.Map) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	readCounter := func() {
		var key uint32
		var total uint64

		err := dropMap.Lookup(&key, &total)
		if err == nil {
			stats.setEventsDroppedTotal(total)
		}
	}

	readCounter()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			readCounter()
		}
	}
}

// lookupDropCounter reads a drop counter map once and tolerates closed-map shutdown races.
func lookupDropCounter(dropMap *ebpf.Map) (uint64, error) {
	var key uint32
	var total uint64

	err := dropMap.Lookup(&key, &total)
	if err != nil {
		return 0, err
	}

	return total, nil
}
