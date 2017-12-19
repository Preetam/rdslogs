package publisher

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/honeycombio/honeytail/event"
	"github.com/honeycombio/honeytail/parsers"
	libhoney "github.com/honeycombio/libhoney-go"
)

// Publisher is an interface to write rdslogs entries to a target. Current
// implementations are STDOUT and Honeycomb
type Publisher interface {
	// Write accepts a long blob of text and writes it to the target
	Write(blob string)
}

// HoneycombPublisher implements Publisher and sends the entries provided to
// Honeycomb
type HoneycombPublisher struct {
	Writekey     string
	Dataset      string
	APIHost      string
	ScrubQuery   bool
	SampleRate   int
	Parser       parsers.Parser
	AddFields    map[string]string
	initialized  bool
	lines        chan string
	eventsToSend chan event.Event
}

func (h *HoneycombPublisher) Write(chunk string) {
	if !h.initialized {
		fmt.Fprintln(os.Stderr, "initializing honeycomb")
		h.initialized = true
		libhoney.Init(libhoney.Config{
			WriteKey:   h.Writekey,
			Dataset:    h.Dataset,
			APIHost:    h.APIHost,
			SampleRate: uint(h.SampleRate),
		})
		h.lines = make(chan string)
		h.eventsToSend = make(chan event.Event)
		go func() {
			h.Parser.ProcessLines(h.lines, h.eventsToSend, nil)
			close(h.eventsToSend)
		}()
		go func() {
			fmt.Fprintln(os.Stderr, "spinning up goroutine to send events")
			for ev := range h.eventsToSend {
				if h.ScrubQuery {
					if val, ok := ev.Data["query"]; ok {
						// generate a sha256 hash
						newVal := sha256.Sum256([]byte(fmt.Sprintf("%v", val)))
						// and use the base16 string version of it
						ev.Data["query"] = fmt.Sprintf("%x", newVal)
					}
				}
				libhEv := libhoney.NewEvent()
				libhEv.Timestamp = ev.Timestamp

				// add extra fields first so they don't override anything parsed
				// in the log file
				if err := libhEv.Add(h.AddFields); err != nil {
					logrus.WithFields(logrus.Fields{
						"add_fields": h.AddFields,
						"error":      err,
					}).Error("Unexpected error adding extra fields data to libhoney event")
				}

				if err := libhEv.Add(ev.Data); err != nil {
					logrus.WithFields(logrus.Fields{
						"event": ev,
						"error": err,
					}).Error("Unexpected error adding data to libhoney event")
				}
				// sampling is handled by the mysql parser
				// TODO make this work for postgres too
				if err := libhEv.SendPresampled(); err != nil {
					logrus.WithFields(logrus.Fields{
						"event": ev,
						"error": err,
					}).Error("Unexpected error event to libhoney send")
				}

			}
		}()
	}
	lines := strings.Split(chunk, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		h.lines <- line
	}
}

// Close flushes outstanding sends
func (h *HoneycombPublisher) Close() {
	libhoney.Close()
}

// STDOUTPublisher implements Publisher and prints to stdout.
type STDOUTPublisher struct {
}

func (s *STDOUTPublisher) Write(line string) {
	io.WriteString(os.Stdout, line)
}

// JSONStdout implements Publisher and prints JSON events to stdout.
type JSONStdout struct {
	initialized  bool
	Parser       parsers.Parser
	lines        chan string
	eventsToSend chan event.Event
}

func (s *JSONStdout) Write(chunk string) {
	if !s.initialized {
		fmt.Fprintln(os.Stderr, "initializing JSONStdout")
		s.initialized = true
		s.lines = make(chan string)
		s.eventsToSend = make(chan event.Event)
		go func() {
			s.Parser.ProcessLines(s.lines, s.eventsToSend, nil)
			close(s.eventsToSend)
		}()
		go func() {
			fmt.Fprintln(os.Stderr, "spinning up goroutine to send events")
			for ev := range s.eventsToSend {
				ev.Data["timestamp"] = ev.Timestamp
				if err := json.NewEncoder(os.Stdout).Encode(ev.Data); err != nil {
					logrus.WithFields(logrus.Fields{
						"event": ev,
						"error": err,
					}).Error("Unexpected error printing event to stdout")
				}
			}
		}()
	}
	lines := strings.Split(chunk, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		s.lines <- line
	}
}
