package export

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/siddhaarthaa/ebpf-sentinel/agent/config"
	"github.com/siddhaarthaa/ebpf-sentinel/agent/flow"
)

type OTLPExporter struct {
	enabled  bool
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
}

// NewOTLPExporter configures an OTLP trace exporter when an endpoint is provided.
func NewOTLPExporter(ctx context.Context, cfg config.Config) (*OTLPExporter, error) {
	if strings.TrimSpace(cfg.OTLPEndpoint) == "" {
		return &OTLPExporter{}, nil
	}

	endpoint, insecure, err := parseOTLPEndpoint(cfg.OTLPEndpoint)
	if err != nil {
		return nil, err
	}

	options := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(endpoint),
	}
	if insecure {
		options = append(options, otlptracegrpc.WithInsecure())
	}

	exporter, err := otlptracegrpc.New(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("create otlp exporter: %w", err)
	}

	res := resource.NewWithAttributes(
		"",
		attribute.String("service.name", cfg.ServiceName),
		attribute.String("service.namespace", "sentinel"),
	)

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	return &OTLPExporter{
		enabled:  true,
		provider: provider,
		tracer:   provider.Tracer(cfg.ServiceName),
	}, nil
}

// ExportHTTPFlow converts a completed HTTP flow into an OTLP span and sends it downstream.
func (e *OTLPExporter) ExportHTTPFlow(httpFlow flow.HTTPFlow) {
	if !e.enabled {
		return
	}

	ctx := context.Background()
	spanName := fmt.Sprintf("%s %s", httpFlow.Method, httpFlow.Path)
	_, span := e.tracer.Start(
		ctx,
		spanName,
		trace.WithTimestamp(httpFlow.StartedAt),
		trace.WithSpanKind(trace.SpanKindClient),
	)

	span.SetAttributes(
		attribute.String("http.method", httpFlow.Method),
		attribute.String("http.url", flowURL(httpFlow)),
		attribute.Int("http.status_code", httpFlow.StatusCode),
		attribute.String("net.peer.ip", httpFlow.RemoteIP),
		attribute.Int("net.peer.port", int(httpFlow.RemotePort)),
		attribute.Int("process.pid", int(httpFlow.PID)),
		attribute.String("process.executable.name", httpFlow.Comm),
		attribute.String("sentinel.source", "ebpf"),
	)

	span.End(trace.WithTimestamp(httpFlow.FinishedAt))
}

// Shutdown flushes and closes the OTLP trace pipeline.
func (e *OTLPExporter) Shutdown(ctx context.Context) error {
	if !e.enabled || e.provider == nil {
		return nil
	}

	return e.provider.Shutdown(ctx)
}

// parseOTLPEndpoint normalizes a raw endpoint into host:port plus transport security settings.
func parseOTLPEndpoint(raw string) (string, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false, fmt.Errorf("empty otlp endpoint")
	}

	if !strings.Contains(raw, "://") {
		return raw, true, nil
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", false, fmt.Errorf("parse otlp endpoint: %w", err)
	}

	if parsed.Host == "" {
		return "", false, fmt.Errorf("parse otlp endpoint: missing host")
	}

	return parsed.Host, parsed.Scheme != "https", nil
}

// flowURL builds the most complete HTTP URL available from a reconstructed flow.
func flowURL(httpFlow flow.HTTPFlow) string {
	if httpFlow.RemoteIP == "" || httpFlow.RemoteIP == "unknown" || httpFlow.RemotePort == 0 {
		return httpFlow.Path
	}

	return fmt.Sprintf("http://%s:%d%s", httpFlow.RemoteIP, httpFlow.RemotePort, httpFlow.Path)
}
