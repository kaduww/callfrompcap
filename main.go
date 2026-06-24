package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// verboseMode enables per-event output when true (set by --verbose flag).
// Default false: events are hidden, \r progress is shown.
// When true: events are printed, \r progress is hidden.
var verboseMode bool

// logEvent prints a timestamped event line to stdout only when --verbose is set.
func logEvent(format string, args ...any) {
	if !verboseMode {
		return
	}
	fmt.Printf(time.Now().Format("15:04:05")+"  "+format+"\n", args...)
}

// warnTruncated reports a truncated/corrupt capture to stderr. Printed
// regardless of --verbose because it signals incomplete input: processing
// stops at the last complete packet and results reflect only what was read.
func warnTruncated(pcapFile string, err error) {
	fmt.Fprintf(os.Stderr, "\nWARNING: %s: truncated capture, stopping at last complete packet (%v); results reflect data read so far\n",
		filepath.Base(pcapFile), err)
}

func main() {
	// Define flags
	outputDir := flag.String("o", "./output", "output directory")
	sipOnly := flag.Bool("sip-only", false, "extract only SIP traces, skip RTP")
	twoPass := flag.Bool("two-pass", false, "read file twice (SIP then RTP)")
	methodFlag := flag.String("method", "", "comma-separated SIP methods to include (e.g. INVITE,REGISTER); default: all")
	codeFlag   := flag.String("sip-code", "", "comma-separated final SIP response codes to include in CSV (e.g. 200,486); default: all")
	verboseFlag  := flag.Bool("verbose", false, "print per-event output; hides the progress line")
	mixAudioFlag := flag.Bool("mix-audio", false, "mix per-SSRC WAV files into a single rtp_mixed.wav per call (requires ffmpeg)")
	trimRingFlag  := flag.Bool("trim-ring", false, "remove ring-tone bursts from the beginning of early-media audio streams")
	noRTPPcapFlag := flag.Bool("no-rtp-pcap", false, "skip writing per-SSRC RTP PCAP files (keep WAV only)")
	rtpIdleFlag   := flag.Float64("rtp-idle-seconds", 60.0, "close RTP stream files after this many seconds of capture-time inactivity (0 = never)")

	// Support long form --output as alias for -o
	flag.StringVar(outputDir, "output", "./output", "output directory (long form)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: callfrompcap [options] <file.pcap> [file2.pcap ...]\n\n")
		fmt.Fprintf(os.Stderr, "       callfrompcap [options] '*.pcap'\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -o, --output <dir>   output directory (default: ./output)\n")
		fmt.Fprintf(os.Stderr, "  --sip-only           extract only SIP traces, skip RTP\n")
		fmt.Fprintf(os.Stderr, "  --two-pass           read file twice (SIP then RTP)\n")
		fmt.Fprintf(os.Stderr, "  --method <methods>   SIP methods to include, comma-separated (default: all)\n")
		fmt.Fprintf(os.Stderr, "                       examples: INVITE  |  INVITE,REGISTER  |  OPTIONS\n")
		fmt.Fprintf(os.Stderr, "  --sip-code <codes>   final SIP response codes to include in CSV (default: all)\n")
		fmt.Fprintf(os.Stderr, "                       examples: 200  |  200,486  |  404,480,486\n")
		fmt.Fprintf(os.Stderr, "  --verbose            print per-event output; hides the progress line\n")
		fmt.Fprintf(os.Stderr, "  --mix-audio          mix per-SSRC WAV files into rtp_mixed.wav per call (requires ffmpeg)\n")
		fmt.Fprintf(os.Stderr, "  --trim-ring          remove ring-tone bursts from early-media audio streams\n")
		fmt.Fprintf(os.Stderr, "  --no-rtp-pcap        skip per-SSRC RTP PCAP files (WAV only)\n")
		fmt.Fprintf(os.Stderr, "  --rtp-idle-seconds <n>  close RTP streams after n seconds of capture-time inactivity (default: 60, 0 = never)\n")
	}

	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	verboseMode = *verboseFlag
	out := *outputDir

	// Expand globs (needed on Windows; harmless on Unix where the shell already expands)
	var pcapFiles []string
	for _, arg := range args {
		matches, err := filepath.Glob(arg)
		if err != nil || len(matches) == 0 {
			pcapFiles = append(pcapFiles, arg) // keep as-is; Stat below will report the error
		} else {
			pcapFiles = append(pcapFiles, matches...)
		}
	}
	sort.Strings(pcapFiles)

	for _, f := range pcapFiles {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "ERROR: file not found: %s\n", f)
			os.Exit(1)
		}
	}

	// Parse --method flag into a lookup set (uppercase)
	methodFilter := make(map[string]struct{})
	if *methodFlag != "" {
		for _, m := range strings.Split(*methodFlag, ",") {
			if m = strings.TrimSpace(strings.ToUpper(m)); m != "" {
				methodFilter[m] = struct{}{}
			}
		}
	}

	// Parse --sip-code flag into a lookup set
	codeFilter := make(map[int]struct{})
	if *codeFlag != "" {
		for _, c := range strings.Split(*codeFlag, ",") {
			c = strings.TrimSpace(c)
			if code, err := strconv.Atoi(c); err == nil && code > 0 {
				codeFilter[code] = struct{}{}
			} else if c != "" {
				fmt.Fprintf(os.Stderr, "WARNING: invalid SIP code %q ignored\n", c)
			}
		}
	}

	nFiles := len(pcapFiles)

	if *sipOnly {
		// SIP-only: single pass, no RTP
		fmt.Printf("[1/2] Extracting SIP traces from %d file(s)  →  %s\n", nFiles, out)
		_, calls, err := extractCalls(pcapFiles, out, methodFilter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("      %d call(s) found\n", len(calls))

		fmt.Println("[2/2] Writing index.csv ...")
		indexPath, n, err := writeCSV(calls, out, codeFilter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("      %s  (%d rows)\n", indexPath, n)

	} else if *twoPass {
		// Two-pass: read files twice (SIP then RTP)
		fmt.Printf("[1/3] Extracting SIP traces from %d file(s)  →  %s\n", nFiles, out)
		endpointMap, calls, err := extractCalls(pcapFiles, out, methodFilter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("      %d call(s) found\n", len(calls))

		fmt.Printf("[2/3] Extracting RTP streams from %d file(s) ...\n", nFiles)
		if err := extractRTP(pcapFiles, endpointMap, *trimRingFlag, *noRTPPcapFlag, *rtpIdleFlag); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("      done")

		if *mixAudioFlag {
			fmt.Println("[3/4] Mixing audio streams ...")
			mixCallsAudio(calls)
		}

		fmt.Println("[3/3] Writing index.csv ...")
		indexPath, n, err := writeCSV(calls, out, codeFilter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("      %s  (%d rows)\n", indexPath, n)

	} else {
		// Default: single-pass (reads files once each)
		fmt.Printf("[1/2] Analyzing %d file(s)  →  %s  (single-pass SIP + RTP)\n", nFiles, out)
		calls, err := analyze(pcapFiles, out, methodFilter, *trimRingFlag, *noRTPPcapFlag, *rtpIdleFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("      %d call(s) found\n", len(calls))

		if *mixAudioFlag {
			fmt.Println("[2/3] Mixing audio streams ...")
			mixCallsAudio(calls)
		}

		fmt.Println("[2/2] Writing index.csv ...")
		indexPath, n, err := writeCSV(calls, out, codeFilter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("      %s  (%d rows)\n", indexPath, n)
	}

	fmt.Println("\nFinished.")
}
