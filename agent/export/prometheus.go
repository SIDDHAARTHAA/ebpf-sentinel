package export

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/siddhaarthaa/ebpf-sentinel/agent/anomaly"
	"github.com/siddhaarthaa/ebpf-sentinel/agent/flow"
	"github.com/siddhaarthaa/ebpf-sentinel/agent/k8s"
	"github.com/siddhaarthaa/ebpf-sentinel/agent/tracer"
)

type PrometheusExporter struct {
	registry            *prometheus.Registry
	acceptedConnections *prometheus.CounterVec
	httpRequests        *prometheus.CounterVec
	httpDurationSeconds *prometheus.HistogramVec
	anomalies           *prometheus.CounterVec
}

type probeMetricsCollector struct {
	eventsDroppedDesc   *prometheus.Desc
	ringbufCapacityDesc *prometheus.Desc
}

// NewPrometheusExporter constructs the metrics registry and all sentinel metric families.
func NewPrometheusExporter() *PrometheusExporter {
	registry := prometheus.NewRegistry()

	exporter := &PrometheusExporter{
		registry: registry,
		acceptedConnections: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "sentinel_accepted_connections_total",
				Help: "Total accepted inbound connections seen by the sentinel.",
			},
			[]string{"comm", "namespace", "pod"},
		),
		httpRequests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "sentinel_http_requests_total",
				Help: "Total completed HTTP requests reconstructed by the sentinel.",
			},
			[]string{"comm", "method", "status", "path", "namespace", "pod"},
		),
		httpDurationSeconds: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "sentinel_http_duration_seconds",
				Help:    "Latency of completed HTTP requests reconstructed by the sentinel.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"comm", "method", "path", "namespace", "pod"},
		),
		anomalies: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "sentinel_anomalies_total",
				Help: "Total anomaly alerts emitted by the sentinel.",
			},
			[]string{"comm", "type", "namespace", "pod"},
		),
	}

	registry.MustRegister(exporter.acceptedConnections)
	registry.MustRegister(exporter.httpRequests)
	registry.MustRegister(exporter.httpDurationSeconds)
	registry.MustRegister(exporter.anomalies)
	registry.MustRegister(newProbeMetricsCollector())

	return exporter
}

// Run starts the HTTP metrics endpoint and shuts it down when the context is canceled.
func (e *PrometheusExporter) Run(ctx context.Context, addr string) error {
	server := &http.Server{
		Addr:    addr,
		Handler: promhttp.HandlerFor(e.registry, promhttp.HandlerOpts{}),
	}

	go shutdownServerOnDone(ctx, server)

	err := server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}

	return fmt.Errorf("serve prometheus metrics: %w", err)
}

// ObserveAccept records an accepted connection against the Prometheus counters.
func (e *PrometheusExporter) ObserveAccept(event tracer.AcceptEvent, metadata k8s.ProcessMetadata) {
	e.acceptedConnections.WithLabelValues(event.Command(), metadata.Namespace, metadata.PodName).Inc()
}

// ObserveHTTPFlow records a completed HTTP flow against request and latency metrics.
func (e *PrometheusExporter) ObserveHTTPFlow(httpFlow flow.HTTPFlow) {
	status := strconv.Itoa(httpFlow.StatusCode)

	e.httpRequests.WithLabelValues(httpFlow.Comm, httpFlow.Method, status, httpFlow.Path, httpFlow.Namespace, httpFlow.PodName).Inc()
	e.httpDurationSeconds.WithLabelValues(httpFlow.Comm, httpFlow.Method, httpFlow.Path, httpFlow.Namespace, httpFlow.PodName).Observe(httpFlow.Duration.Seconds())
}

// ObserveAlert records an anomaly alert against the Prometheus counters.
func (e *PrometheusExporter) ObserveAlert(alert anomaly.Alert, metadata k8s.ProcessMetadata) {
	e.anomalies.WithLabelValues(alert.Comm, alert.Type, metadata.Namespace, metadata.PodName).Inc()
}

// newProbeMetricsCollector creates a collector that scrapes per-probe runtime metrics on demand.
func newProbeMetricsCollector() *probeMetricsCollector {
	return &probeMetricsCollector{
		eventsDroppedDesc: prometheus.NewDesc(
			"sentinel_events_dropped_total",
			"Total events dropped because a probe's ring buffer could not reserve space.",
			[]string{"probe"},
			nil,
		),
		ringbufCapacityDesc: prometheus.NewDesc(
			"sentinel_ringbuf_capacity_bytes",
			"Configured ring buffer capacity for a probe in bytes.",
			[]string{"probe"},
			nil,
		),
	}
}

// Describe sends the exported metric descriptors to Prometheus.
func (c *probeMetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.eventsDroppedDesc
	ch <- c.ringbufCapacityDesc
}

// Collect snapshots live probe metrics and exports them as Prometheus samples.
func (c *probeMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	for _, snapshot := range tracer.SnapshotProbeMetrics() {
		ch <- prometheus.MustNewConstMetric(
			c.eventsDroppedDesc,
			prometheus.CounterValue,
			float64(snapshot.EventsDroppedTotal),
			snapshot.Probe,
		)
		ch <- prometheus.MustNewConstMetric(
			c.ringbufCapacityDesc,
			prometheus.GaugeValue,
			float64(snapshot.RingbufCapacityBytes),
			snapshot.Probe,
		)
	}
}

// shutdownServerOnDone stops the HTTP server once the parent context is canceled.
func shutdownServerOnDone(ctx context.Context, server *http.Server) {
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = server.Shutdown(shutdownCtx)
}
