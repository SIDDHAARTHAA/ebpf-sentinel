package anomaly

import (
	"fmt"
	"net"
	"time"

	"github.com/siddhaarthaa/ebpf-sentinel/agent/tracer"
)

type Alert struct {
	Time    time.Time
	Type    string
	Comm    string
	PID     uint32
	Summary string
}

type Detector struct {
	profiles      map[string]ProcessProfile
	lastAlertByID map[string]time.Time
	cooldown      time.Duration
}

// NewDetector creates a detector from the loaded process profiles.
func NewDetector(profileSet *ProfileSet) *Detector {
	return &Detector{
		profiles:      profileSet.Profiles,
		lastAlertByID: make(map[string]time.Time),
		cooldown:      30 * time.Second,
	}
}

// HandleAccept inspects inbound network activity for unknown-process alerts.
func (d *Detector) HandleAccept(event tracer.AcceptEvent) []Alert {
	comm := event.Command()
	if _, exists := d.profileForComm(comm); exists {
		return nil
	}

	return d.emitUnknownProcessAlert(comm, event.PID, "accept", event.RemoteIP(), int(event.Port))
}

// HandleConnect inspects outbound connections for profile mismatches and risky access patterns.
func (d *Detector) HandleConnect(event tracer.ConnectEvent) []Alert {
	comm := event.Command()
	profile, exists := d.profileForComm(comm)
	if !exists {
		return d.emitUnknownProcessAlert(comm, event.PID, "connect", event.RemoteIP(), int(event.Port))
	}

	var alerts []Alert
	now := time.Now()
	remoteIP := event.RemoteIP()
	port := int(event.Port)

	if port > 0 && port < 1024 && !portAllowed(profile, port) {
		if alert, ok := d.makeAlert(
			now,
			fmt.Sprintf("privileged:%s:%d", comm, port),
			"privileged_port_access",
			comm,
			event.PID,
			fmt.Sprintf("connected to privileged port %d", port),
		); ok {
			alerts = append(alerts, alert)
		}
	}

	if port > 0 && len(profile.ExpectedPorts) > 0 && !portAllowed(profile, port) {
		if alert, ok := d.makeAlert(
			now,
			fmt.Sprintf("outbound-port:%s:%d", comm, port),
			"unexpected_outbound_connection",
			comm,
			event.PID,
			fmt.Sprintf("connected to unexpected port %d", port),
		); ok {
			alerts = append(alerts, alert)
		}
	}

	if remoteIP != "unknown" && shouldCheckDestination(profile) && !ipAllowed(profile, remoteIP) {
		if alert, ok := d.makeAlert(
			now,
			fmt.Sprintf("outbound-dest:%s:%s:%d", comm, remoteIP, port),
			"unexpected_outbound_connection",
			comm,
			event.PID,
			fmt.Sprintf("connected to unexpected destination %s:%d", remoteIP, port),
		); ok {
			alerts = append(alerts, alert)
		}
	}

	return alerts
}

// HandleExec inspects process-spawn activity against the loaded allow_exec rules.
func (d *Detector) HandleExec(event tracer.ExecEvent) []Alert {
	comm := event.Command()
	profile, exists := d.profileForComm(comm)
	if !exists || profile.AllowExec {
		return nil
	}

	alert, ok := d.makeAlert(
		time.Now(),
		fmt.Sprintf("exec:%s:%d", comm, event.PID),
		"unexpected_process_spawn",
		comm,
		event.PID,
		fmt.Sprintf("process executed with parent pid %d while allow_exec=false", event.PPID),
	)
	if !ok {
		return nil
	}

	return []Alert{alert}
}

// emitUnknownProcessAlert creates unknown-process alerts for network syscalls without profiles.
func (d *Detector) emitUnknownProcessAlert(comm string, pid uint32, syscall string, remoteIP string, port int) []Alert {
	alert, ok := d.makeAlert(
		time.Now(),
		fmt.Sprintf("unknown:%s:%s", syscall, comm),
		"unknown_process",
		comm,
		pid,
		fmt.Sprintf("process has no profile but made %s activity toward %s:%d", syscall, remoteIP, port),
	)
	if !ok {
		return nil
	}

	return []Alert{alert}
}

// makeAlert applies cooldown-based deduplication before returning an alert.
func (d *Detector) makeAlert(now time.Time, dedupeKey string, alertType string, comm string, pid uint32, summary string) (Alert, bool) {
	lastSeen, exists := d.lastAlertByID[dedupeKey]
	if exists && now.Sub(lastSeen) < d.cooldown {
		return Alert{}, false
	}

	d.lastAlertByID[dedupeKey] = now

	return Alert{
		Time:    now,
		Type:    alertType,
		Comm:    comm,
		PID:     pid,
		Summary: summary,
	}, true
}

// profileForComm looks up a process profile using the kernel-truncated comm value.
func (d *Detector) profileForComm(comm string) (ProcessProfile, bool) {
	profile, exists := d.profiles[truncateComm(comm)]
	return profile, exists
}

// shouldCheckDestination reports whether a profile wants outbound destinations validated.
func shouldCheckDestination(profile ProcessProfile) bool {
	return profile.AlertOnUnknownDest || len(profile.expectedSubnetRanges) > 0
}

// portAllowed checks whether a destination port is explicitly allowed by the profile.
func portAllowed(profile ProcessProfile, port int) bool {
	for _, allowedPort := range profile.ExpectedPorts {
		if port == allowedPort {
			return true
		}
	}
	return false
}

// ipAllowed checks whether a destination IP falls inside one of the expected subnets.
func ipAllowed(profile ProcessProfile, ipText string) bool {
	ip := net.ParseIP(ipText)
	if ip == nil {
		return false
	}

	for _, subnet := range profile.expectedSubnetRanges {
		if subnet.Contains(ip) {
			return true
		}
	}

	return false
}
