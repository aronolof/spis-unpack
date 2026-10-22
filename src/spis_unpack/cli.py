from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .errors import SpisError
from .unpack import (
    DEFAULT_MAX_OUTPUT,
    inspect_file,
    reports_to_json,
    test_file,
    unpack_to_dir,
    unpack_to_file,
)


def _print_reports(reports: list, as_json: bool, input_path: Path) -> None:
    if as_json:
        print(reports_to_json(input_path, reports))
        return

    print("index\toffset\tmethod\tcompressed\tdecompressed\tlocked\toutput")
    for report in reports:
        output = report.output or ""
        print(
            f"{report.index}\t{report.offset}\t{report.method}\t{report.compressed_size}\t"
            f"{report.decompressed_size}\t{report.locked}\t{output}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Unpack SPIS containers and decompress SPIS payloads.",
    )
    parser.add_argument("input", type=Path, help="Input file")
    parser.add_argument("-o", "--output", type=Path, help="Output file")
    parser.add_argument("-d", "--out-dir", type=Path, help="Output directory for split blocks")
    parser.add_argument("--list", action="store_true", help="List SPIS blocks")
    parser.add_argument(
        "--split-blocks",
        action="store_true",
        help="Write one output file per block",
    )
    parser.add_argument("--json", action="store_true", help="Print metadata as JSON")
    parser.add_argument("--force", action="store_true", help="Overwrite existing outputs")
    parser.add_argument("--test", action="store_true", help="Decode without writing output")
    parser.add_argument("--verify", action="store_true", help="Check TCompress additive checksums")
    parser.add_argument(
        "--max-output",
        type=int,
        default=DEFAULT_MAX_OUTPUT,
        help="Maximum total decoded bytes (default: 1 GiB; 0: unlimited)",
    )
    parser.add_argument(
        "--framing",
        choices=("scan", "length-prefixed"),
        default="scan",
        help="Signature recovery or declared external block lengths",
    )
    parser.add_argument("--start", type=int, default=0, help="Framed stream start offset")
    parser.add_argument("--length", type=int, help="Framed stream byte extent")
    args = parser.parse_args(argv)
    if args.start < 0 or (args.length is not None and args.length < 0):
        parser.error("--start and --length must be non-negative")
    if args.framing == "scan" and (args.start or args.length is not None):
        parser.error("--start/--length require --framing length-prefixed")

    if args.max_output < 0:
        parser.error("--max-output must be non-negative")
    if args.out_dir and not args.split_blocks:
        parser.error("--out-dir requires --split-blocks")
    if args.test and (args.output or args.out_dir or args.split_blocks or args.list):
        parser.error("--test cannot be combined with output options or --list")
    if args.list and (args.output or args.out_dir or args.split_blocks or args.verify):
        parser.error("--list cannot be combined with extraction options or --verify")
    framing = {"framing": args.framing, "start": args.start, "length": args.length}
    options = {"verify": args.verify, "max_output": args.max_output or None, **framing}

    if not args.input.exists():
        print(f"Input file not found: {args.input}", file=sys.stderr)
        return 1
    if args.output and args.split_blocks:
        print("--output cannot be used with --split-blocks", file=sys.stderr)
        return 1

    try:
        if args.test:
            reports = test_file(args.input, **options)
            _print_reports(reports, args.json, args.input)
            return 0
        if args.list:
            reports = inspect_file(args.input, **framing)
            _print_reports(reports, args.json, args.input)
            if not args.output and not args.out_dir and not args.split_blocks:
                return 0

        if args.split_blocks:
            output_dir = args.out_dir or args.input.with_suffix("")
            if output_dir.exists() and not args.force:
                print(f"Output directory already exists: {output_dir}", file=sys.stderr)
                return 1
            reports = unpack_to_dir(args.input, output_dir, **options)
            if args.json:
                print(reports_to_json(args.input, reports))
            return 0

        output_path = args.output or args.input.with_suffix(".bin")
        if output_path.exists() and not args.force:
            print(f"Output file already exists: {output_path}", file=sys.stderr)
            return 1
        reports = unpack_to_file(args.input, output_path, **options)
        if args.json:
            print(reports_to_json(args.input, reports))
        return 0
    except (SpisError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
