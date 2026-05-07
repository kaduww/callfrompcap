import argparse
import sys
from pathlib import Path

from analyzer import analyze
from exporter import write_index_csv
from rtp_extractor import extract_rtp
from sip_extractor import extract_calls


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Analyze a PCAP file and export SIP traces + RTP streams per call.'
    )
    parser.add_argument('pcap', help='Path to the PCAP file (supports files > 40 GB)')
    parser.add_argument(
        '--output', '-o',
        default='./output',
        help='Output directory (default: ./output)',
    )
    parser.add_argument(
        '--sip-only',
        action='store_true',
        help='Extract only SIP traces, skip RTP (fastest)',
    )
    parser.add_argument(
        '--two-pass',
        action='store_true',
        help='Read the file twice (SIP pass, then RTP pass) instead of the default single-pass',
    )
    args = parser.parse_args()

    pcap_file = args.pcap
    output_dir = Path(args.output)

    if not Path(pcap_file).exists():
        print(f'ERROR: file not found: {pcap_file}', file=sys.stderr)
        sys.exit(1)

    if args.sip_only:
        # SIP-only: single pass, no RTP
        print(f'[1/2] Extracting SIP traces  →  {output_dir}')
        _, calls = extract_calls(pcap_file, output_dir)
        print(f'      {len(calls)} call(s) found')
        print('[2/2] Writing index.csv ...')
        index_path = write_index_csv(calls, output_dir)
        print(f'      {index_path}')

    elif args.two_pass:
        # Legacy two-pass: reads file twice
        print(f'[1/3] Extracting SIP traces  →  {output_dir}  (pass 1/2)')
        endpoint_map, calls = extract_calls(pcap_file, output_dir)
        print(f'      {len(calls)} call(s) found')
        print('[2/3] Extracting RTP streams ...  (pass 2/2)')
        extract_rtp(pcap_file, endpoint_map)
        print('      done')
        print('[3/3] Writing index.csv ...')
        index_path = write_index_csv(calls, output_dir)
        print(f'      {index_path}')

    else:
        # Default: single-pass (reads file once)
        print(f'[1/2] Analyzing  →  {output_dir}  (single-pass SIP + RTP)')
        calls = analyze(pcap_file, output_dir)
        print(f'      {len(calls)} call(s) found')
        print('[2/2] Writing index.csv ...')
        index_path = write_index_csv(calls, output_dir)
        print(f'      {index_path}')

    print('\nFinished.')


if __name__ == '__main__':
    main()
