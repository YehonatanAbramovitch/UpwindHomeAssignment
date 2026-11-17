"""Scan an email file from the command line and print a report.

Usage:
    python cli.py samples/phishing_paypal.txt
"""

import argparse
import sys
from pathlib import Path

from detector import config
from detector.analyzer import analyze
from detector.models import ScanResult, printable

BODY_PREVIEW_LINES = 15  # a long email shows only its first lines


def main() -> int:
    # A character the terminal cannot show is printed as "?", instead of crashing.
    sys.stdout.reconfigure(errors="replace")

    arguments = argparse.ArgumentParser(description="Scan an email file for signs of phishing.")
    arguments.add_argument("file", help="the email file to scan (.txt or .eml)")
    path = Path(arguments.parse_args().file)

    try:
        raw = path.read_bytes()
    except OSError as error:
        print(f"Cannot read {path}: {error.strerror}", file=sys.stderr)
        return 1
    if not raw.strip():
        print(f"{path} is empty, there is nothing to scan.", file=sys.stderr)
        return 1

    print(format_report(path, analyze(raw)))
    return 0


def format_report(path: Path, result: ScanResult) -> str:
    """The report, in a fixed order: which email, its content, then the verdict."""
    lines = [
        "Phishing scan report",
        "====================",
        f"File:     {path}",
        f"From:     {printable(result.sender) or '(unknown)'}",
        *_no_headers_note(result),
        f"Subject:  {printable(result.subject) or '(no subject)'}",
        "",
        "Email content",
        "-------------",
        *_body_preview(result.body),
        "",
        f"Verdict:  {result.verdict.upper()}",
        f"Score:    {result.score} / {config.MAX_SCORE}{_cap_note(result)}",
        "",
        "Detected indicators:",
    ]
    if not result.findings:
        lines.append("  none")
    for finding in result.findings:
        lines.append(f"  [+{finding.points}] {finding.indicator}: {finding.description}")
        lines.extend(f"          - {printable(item)}" for item in finding.evidence)
    return "\n".join(lines)


def _no_headers_note(result: ScanResult) -> list[str]:
    """Explain a lower score when the file has no sender, so it is not read as a miss."""
    if result.sender:
        return []
    return ["          Note: no email headers found, so the sender checks were skipped."]


def _cap_note(result: ScanResult) -> str:
    """Explain the score when the points add up to more than MAX_SCORE.

    Without it, 13 findings that add up to 270 next to a score of 100 look like a calculation error.
    """
    total = sum(finding.points for finding in result.findings)
    if total <= config.MAX_SCORE:
        return ""
    return f"  ({total} points detected, capped at {config.MAX_SCORE})"


def _body_preview(body: str) -> list[str]:
    """The first lines of the body, and how many more were left out."""
    if not body:
        return ["(empty)"]
    body_lines = [printable(line) for line in body.splitlines()]
    preview = body_lines[:BODY_PREVIEW_LINES]
    hidden = len(body_lines) - len(preview)
    if hidden:
        preview.append(f"... ({hidden} more lines)")
    return preview


if __name__ == "__main__":
    sys.exit(main())
