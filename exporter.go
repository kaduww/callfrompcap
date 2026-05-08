package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// writeCSV writes index.csv with columns: call_id, request_user, final_code, final_reason, duration, directory.
// codeFilter: set of allowed final SIP codes (empty = include all calls).
// Returns the path to the written file and the number of rows written.
func writeCSV(calls map[string]*Call, outputDir string, codeFilter map[int]struct{}) (string, int, error) {
	indexPath := filepath.Join(outputDir, "index.csv")

	f, err := os.Create(indexPath)
	if err != nil {
		return "", 0, fmt.Errorf("creating index.csv: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{"call_id", "request_user", "final_code", "final_reason", "duration", "mos", "jitter_ms", "loss_pct", "media_flow", "directory"}); err != nil {
		return "", 0, fmt.Errorf("writing csv header: %w", err)
	}

	written := 0
	for _, call := range calls {
		if len(codeFilter) > 0 {
			if _, ok := codeFilter[call.FinalCode]; !ok {
				continue
			}
		}
		row := []string{
			call.CallID,
			call.RequestUser,
			codeToString(call.FinalCode),
			call.FinalReason,
			callDuration(call),
			formatRTPFloat(call.MOSMin, 2),
			formatRTPFloat(call.JitterMs, 2),
			formatRTPFloat(call.LossPct, 2),
			mediaFlow(call),
			call.Directory,
		}
		if err := w.Write(row); err != nil {
			return "", 0, fmt.Errorf("writing csv row: %w", err)
		}
		written++
	}

	if err := w.Error(); err != nil {
		return "", 0, fmt.Errorf("csv flush error: %w", err)
	}

	return indexPath, written, nil
}

// mediaFlow returns the media flow direction for debug purposes.
func mediaFlow(call *Call) string {
	switch {
	case call.HadCallerRTP && call.HadCalleeRTP:
		return "both"
	case call.HadCallerRTP:
		return "caller-only"
	case call.HadCalleeRTP:
		return "callee-only"
	default:
		return ""
	}
}

// formatRTPFloat formats a float metric for CSV.
// Returns empty string when value is zero (metric not available).
func formatRTPFloat(v float64, prec int) string {
	if v == 0 {
		return ""
	}
	return strconv.FormatFloat(v, 'f', prec, 64)
}

func codeToString(code int) string {
	if code == 0 {
		return ""
	}
	return strconv.Itoa(code)
}

// callDuration returns the call duration in seconds as a string,
// or empty string if the call was never established or the end was not seen.
func callDuration(call *Call) string {
	if call.ConnectedAt == 0 || call.DisconnectedAt == 0 {
		return ""
	}
	secs := call.DisconnectedAt - call.ConnectedAt
	if secs < 0 {
		return ""
	}
	return strconv.Itoa(int(secs))
}
