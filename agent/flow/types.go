package flow

import "time"

type ConnectionKey struct {
	PID uint32
	FD  uint32
}

type Connection struct {
	Key           ConnectionKey
	Comm          string
	Namespace     string
	PodName       string
	ContainerID   string
	ContainerName string
	RemoteIP      string
	RemotePort    uint16
	LastSeen      time.Time
	Direction     string
}

type PartialFlow struct {
	Key        ConnectionKey
	Connection Connection
	Method     string
	Path       string
	StartedAt  time.Time
	UpdatedAt  time.Time
}

type HTTPFlow struct {
	PID           uint32
	FD            uint32
	Comm          string
	Namespace     string
	PodName       string
	ContainerID   string
	ContainerName string
	Method        string
	Path          string
	StatusCode    int
	RemoteIP      string
	RemotePort    uint16
	StartedAt     time.Time
	FinishedAt    time.Time
	Duration      time.Duration
}
