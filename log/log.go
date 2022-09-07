package log

import (
	"time"
)

type Event struct {
	Offset        uint64 // byte offset in file at which event starts
	OffsetEnd     uint64 // byte offset in file at which event ends
	Ts            string // timestamp of event
	Admin         bool   // true if Query is admin command
	Query         string // SQL query or admin command
	User          string
	Host          string
	Db            string
	Server        string
	LabelsKey     []string
	LabelsValue   []string
	TimeMetrics   map[string]float64 // *_time and *_wait metrics
	NumberMetrics map[string]uint64  // most metrics
	BoolMetrics   map[string]bool    // yes/no metrics
	RateType      string             // Percona Server rate limit type
	RateLimit     uint               // Percona Server rate limit value
}

// NewEvent returns a new Event with initialized metric maps.
func NewEvent() *Event {
	event := new(Event)
	event.TimeMetrics = make(map[string]float64)
	event.NumberMetrics = make(map[string]uint64)
	event.BoolMetrics = make(map[string]bool)
	return event
}

// Options encapsulate common options for making a new LogParser.
type Options struct {
	StartOffset        uint64                                // byte offset in file at which to start parsing
	FilterAdminCommand map[string]bool                       // admin commands to ignore
	Debug              bool                                  // print trace info to STDERR with standard library logger
	Debugf             func(format string, v ...interface{}) // use this function for logging instead of log.Printf (Debug still should be true)
	DefaultLocation    *time.Location                        // DefaultLocation to assume for logs in MySQL < 5.7 format.
}
