package anomaly

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

type ProcessProfile struct {
	Name                 string
	ExpectedSubnets      []string
	ExpectedPorts        []int
	AllowExec            bool
	AlertOnUnknownDest   bool
	expectedSubnetRanges []*net.IPNet
}

type ProfileSet struct {
	Profiles map[string]ProcessProfile
}

// LoadProfiles reads the default profile file and parses the supported YAML subset.
func LoadProfiles(path string) (*ProfileSet, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open profiles file: %w", err)
	}
	defer file.Close()

	profiles := make(map[string]ProcessProfile)
	scanner := bufio.NewScanner(file)
	var current *ProcessProfile
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") || trimmed == "profiles:" {
			continue
		}

		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") && strings.HasSuffix(trimmed, ":") {
			if current != nil {
				storeProfile(profiles, *current)
			}

			name := strings.TrimSuffix(trimmed, ":")
			current = &ProcessProfile{Name: name}
			continue
		}

		if current == nil {
			return nil, fmt.Errorf("profiles line %d: expected a profile name before fields", lineNo)
		}

		field, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			return nil, fmt.Errorf("profiles line %d: invalid field syntax", lineNo)
		}

		field = strings.TrimSpace(field)
		value = strings.TrimSpace(value)

		if err := applyProfileField(current, field, value); err != nil {
			return nil, fmt.Errorf("profiles line %d: %w", lineNo, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan profiles file: %w", err)
	}

	if current != nil {
		storeProfile(profiles, *current)
	}

	return &ProfileSet{Profiles: profiles}, nil
}

// applyProfileField parses one supported profile field and stores it on the current profile.
func applyProfileField(profile *ProcessProfile, field string, value string) error {
	switch field {
	case "expected_subnets":
		items, err := parseStringList(value)
		if err != nil {
			return err
		}
		profile.ExpectedSubnets = items
		for _, item := range items {
			_, ipNet, err := net.ParseCIDR(item)
			if err != nil {
				return fmt.Errorf("invalid subnet %q: %w", item, err)
			}
			profile.expectedSubnetRanges = append(profile.expectedSubnetRanges, ipNet)
		}
	case "expected_ports":
		items, err := parseIntList(value)
		if err != nil {
			return err
		}
		profile.ExpectedPorts = items
	case "allow_exec":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid allow_exec value %q", value)
		}
		profile.AllowExec = parsed
	case "alert_on_unknown_dest":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid alert_on_unknown_dest value %q", value)
		}
		profile.AlertOnUnknownDest = parsed
	default:
		return fmt.Errorf("unsupported profile field %q", field)
	}

	return nil
}

// parseStringList converts a bracketed YAML string list into Go strings.
func parseStringList(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if value == "[]" {
		return nil, nil
	}

	if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
		return nil, fmt.Errorf("expected bracketed string list, got %q", value)
	}

	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(value, "["), "]"))
	if inner == "" {
		return nil, nil
	}

	parts := strings.Split(inner, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.Trim(strings.TrimSpace(part), `"'`)
		if item != "" {
			items = append(items, item)
		}
	}

	return items, nil
}

// parseIntList converts a bracketed YAML integer list into Go ints.
func parseIntList(value string) ([]int, error) {
	value = strings.TrimSpace(value)
	if value == "[]" {
		return nil, nil
	}

	if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
		return nil, fmt.Errorf("expected bracketed int list, got %q", value)
	}

	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(value, "["), "]"))
	if inner == "" {
		return nil, nil
	}

	parts := strings.Split(inner, ",")
	items := make([]int, 0, len(parts))
	for _, part := range parts {
		parsed, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("invalid int value %q", part)
		}
		items = append(items, parsed)
	}

	return items, nil
}

// storeProfile normalizes the profile name and stores it in the profile set.
func storeProfile(profiles map[string]ProcessProfile, profile ProcessProfile) {
	profiles[truncateComm(profile.Name)] = profile
}

// truncateComm matches the kernel TASK_COMM_LEN truncation used by comm values.
func truncateComm(name string) string {
	if len(name) <= 15 {
		return name
	}
	return name[:15]
}
