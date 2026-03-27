package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	ProfilePath    string
	PrometheusAddr string
	OTLPEndpoint   string
	ServiceName    string
}

// Load reads defaults, an optional config file, and environment overrides for the agent.
func Load() (Config, error) {
	values := map[string]string{
		"SENTINEL_PROFILE_PATH":       "profiles/default.yaml",
		"PROMETHEUS_PORT":             "9090",
		"OTEL_EXPORTER_OTLP_ENDPOINT": "",
		"OTEL_SERVICE_NAME":           "ebpf-sentinel",
	}

	if configPath := strings.TrimSpace(os.Getenv("SENTINEL_CONFIG_FILE")); configPath != "" {
		fileValues, err := loadConfigFile(configPath)
		if err != nil {
			return Config{}, err
		}
		for key, value := range fileValues {
			values[key] = value
		}
	}

	for key := range values {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			values[key] = value
		}
	}

	return Config{
		ProfilePath:    values["SENTINEL_PROFILE_PATH"],
		PrometheusAddr: normalizePrometheusAddr(values["PROMETHEUS_PORT"]),
		OTLPEndpoint:   strings.TrimSpace(values["OTEL_EXPORTER_OTLP_ENDPOINT"]),
		ServiceName:    values["OTEL_SERVICE_NAME"],
	}, nil
}

// loadConfigFile parses a simple KEY=VALUE config file into a string map.
func loadConfigFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config file: %w", err)
	}
	defer file.Close()

	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("config line %d: expected KEY=VALUE", lineNo)
		}

		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan config file: %w", err)
	}

	return values, nil
}

// normalizePrometheusAddr turns a bare port into a usable listen address.
func normalizePrometheusAddr(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ":9090"
	}

	if strings.Contains(value, ":") {
		return value
	}

	return ":" + value
}
