package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// writeCSV writes index.csv with columns: call_id, request_user, final_code, final_reason, directory.
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

	if err := w.Write([]string{"call_id", "request_user", "final_code", "final_reason", "directory"}); err != nil {
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

func codeToString(code int) string {
	if code == 0 {
		return ""
	}
	return strconv.Itoa(code)
}
