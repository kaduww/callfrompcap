package main

import (
	"fmt"
	"time"
)

const (
	progressCheckInterval = 10_000       // check every N packets
	progressPrintInterval = 2 * time.Second
)

// Progress prints an updating status line periodically.
type Progress struct {
	n          int64
	totalBytes int64
	t0         time.Time
	tLast      time.Time
	printed    bool
}

// newProgress creates a new Progress tracker.
// totalBytes is the file size; used to compute percentage.
func newProgress(totalBytes int64) *Progress {
	now := time.Now()
	return &Progress{
		totalBytes: totalBytes,
		t0:         now,
		tLast:      now,
	}
}

// tick increments the packet counter and prints progress if enough time has elapsed.
// Only active when --verbose is not set; in verbose mode the event log already shows activity.
func (p *Progress) tick(bytesRead int64, extra string) {
	p.n++
	if verboseMode {
		return
	}
	if p.n%progressCheckInterval != 0 {
		return
	}
	now := time.Now()
	if now.Sub(p.tLast) < progressPrintInterval {
		return
	}
	p.tLast = now
	p.render(now, bytesRead, extra, "")
}

// done prints the final status line if anything was printed.
func (p *Progress) done(bytesRead int64, extra string) {
	if p.printed {
		p.render(time.Now(), bytesRead, extra, "\n")
	}
}

// render prints the progress line.
func (p *Progress) render(now time.Time, bytesRead int64, extra, end string) {
	elapsed := now.Sub(p.t0).Seconds()
	rate := 0.0
	if elapsed > 0 {
		rate = float64(p.n) / elapsed / 1000
	}
	pct := 0
	if p.totalBytes > 0 {
		pct = int(bytesRead * 100 / p.totalBytes)
	}
	fmt.Printf("\r  %5.0fs  %12s pkts  (%.0fk/s)  %3d%%  %s   %s",
		elapsed,
		formatInt(p.n),
		rate,
		pct,
		extra,
		end,
	)
	p.printed = true
}

// formatInt formats an int64 with comma separators (e.g. 1,234,567).
func formatInt(n int64) string {
	s := fmt.Sprintf("%d", n)
	result := make([]byte, 0, len(s)+len(s)/3)
	for i, ch := range s {
		pos := len(s) - i
		if i > 0 && pos%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(ch))
	}
	return string(result)
}
