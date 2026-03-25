package flow

import "time"

type ConnectionKey struct {
	PID uint32
	FD  uint32
}

type PartialFlow struct {
	Key       ConnectionKey
	Comm      string
	Method    string
	Path      string
	StartedAt time.Time
	UpdatedAt time.Time
}

type HTTPFlow struct {
	PID        uint32
	FD         uint32
	Comm       string
	Method     string
	Path       string
	StatusCode int
	StartedAt  time.Time
	FinishedAt time.Time
	Duration   time.Duration
}
