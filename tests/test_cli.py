"""Tests for the command line report."""

import sys
from pathlib import Path

import cli

SAMPLES = Path(__file__).parent.parent / "samples"


def run_cli(monkeypatch, capsys, *arguments):
    monkeypatch.setattr(sys, "argv", ["cli.py", *arguments])
    exit_code = cli.main()
    return exit_code, capsys.readouterr()


def test_report_of_the_phishing_sample(monkeypatch, capsys):
    exit_code, output = run_cli(monkeypatch, capsys, str(SAMPLES / "phishing_paypal.txt"))
    assert exit_code == 0
    assert "Verdict:  LIKELY PHISHING" in output.out
    assert "(270 points detected, capped at 100)" in output.out


def test_hidden_character_is_shown_as_a_code(monkeypatch, capsys):
    _, output = run_cli(monkeypatch, capsys, str(SAMPLES / "disguised_attachment.txt"))
    assert "[U+202E]" in output.out
    assert "‮" not in output.out


def test_missing_file(monkeypatch, capsys):
    exit_code, output = run_cli(monkeypatch, capsys, "no_such_file.txt")
    assert exit_code == 1
    assert "Cannot read" in output.err


def test_empty_file(monkeypatch, capsys, tmp_path):
    empty = tmp_path / "empty.txt"
    empty.write_text("")
    exit_code, output = run_cli(monkeypatch, capsys, str(empty))
    assert exit_code == 1
    assert "empty" in output.err


def test_long_body_is_cut_but_fully_scanned(monkeypatch, capsys, tmp_path):
    body = "\n".join(f"line {number}" for number in range(40)) + "\nhttps://bit.ly/late-link\n"
    long_email = tmp_path / "long.txt"
    long_email.write_text("From: a@example.com\nSubject: Long\n\n" + body)
    _, output = run_cli(monkeypatch, capsys, str(long_email))
    assert "more lines)" in output.out
    assert "bit.ly/late-link" not in output.out.split("Verdict:")[0]  # not shown in the preview
    assert "URL shortener" in output.out  # but found by the scan
