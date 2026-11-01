"""Command-line entry point."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from webheaders import __version__
from webheaders.checks import evaluate
from webheaders.fetch import fetch_headers
from webheaders.report import to_html, to_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webheaders",
        description="Audit HTTP security headers. Use only on sites you own or are authorized to test.",
    )
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--format", choices=["json", "html"], default="json")
    parser.add_argument("-o", "--output", type=Path, help="Write report to this file instead of stdout")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        headers = fetch_headers(args.url, timeout=args.timeout)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = evaluate(args.url, headers)
    text = to_json(report) if args.format == "json" else to_html(report)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
