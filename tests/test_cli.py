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


def test_report_lists_attachments_and_links(monkeypatch, capsys):
    _, output = run_cli(monkeypatch, capsys, str(SAMPLES / "phishing_paypal.txt"))
    attachments = output.out.split("Attachments")[1].split("Links")[0]
    links = output.out.split("Links")[1].split("Verdict:")[0]
    assert "PayPal_Invoice.pdf.exe" in attachments
    assert "http://203.0.113.45/paypal/login" in links
    assert "https://paypal.com.account-verify.xyz/signin" in links


def test_report_shows_none_without_links_or_attachments(monkeypatch, capsys, tmp_path):
    plain = tmp_path / "plain.txt"
    plain.write_text("From: a@example.com\nSubject: Hi\n\nHello.\n")
    _, output = run_cli(monkeypatch, capsys, str(plain))
    assert output.out.count("(none)") == 2


def test_note_when_there_are_no_headers(monkeypatch, capsys, tmp_path):
    body_only = tmp_path / "body.txt"
    body_only.write_text("Dear customer, verify your password.\n")
    _, output = run_cli(monkeypatch, capsys, str(body_only))
    assert "no email headers found" in output.out


def test_no_note_when_there_is_a_sender(monkeypatch, capsys):
    _, output = run_cli(monkeypatch, capsys, str(SAMPLES / "legit_colleague.txt"))
    assert "no email headers found" not in output.out


def test_long_body_is_cut_but_fully_scanned(monkeypatch, capsys, tmp_path):
    body = "\n".join(f"line {number}" for number in range(40)) + "\nhttps://bit.ly/late-link\n"
    long_email = tmp_path / "long.txt"
    long_email.write_text("From: a@example.com\nSubject: Long\n\n" + body)
    _, output = run_cli(monkeypatch, capsys, str(long_email))
    assert "more lines)" in output.out
    content = output.out.split("Email content")[1].split("Attachments")[0]
    links = output.out.split("Links")[1].split("Verdict:")[0]
    assert "bit.ly/late-link" not in content  # cut from the content preview,
    assert "bit.ly/late-link" in links  # but still listed under Links,
    assert "URL shortener" in output.out  # and found by the scan
