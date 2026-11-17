"""Tests for the web app and the history storage."""

import io
import sys
from pathlib import Path

import pytest

import cli
from web.app import create_app

SAMPLES = Path(__file__).parent.parent / "samples"
PHISHING = (SAMPLES / "phishing_paypal.txt").read_bytes()


def database_url(folder: Path) -> str:
    return "sqlite:///" + (folder / "test.db").as_posix()


@pytest.fixture
def client(tmp_path):
    return create_app(database_url(tmp_path)).test_client()


def scan_text(client, text: str):
    return client.post("/scan", data={"email_text": text})


def scan_file(client, content: bytes, name: str):
    return client.post("/scan", data={"email_file": (io.BytesIO(content), name)},
                       content_type="multipart/form-data")


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.text == "OK"


def test_scan_page_and_served_by(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Served by:" in response.text


def test_scan_pasted_text(client):
    response = scan_text(client, PHISHING.decode())
    assert response.status_code == 200
    assert "Likely phishing" in response.text
    assert "270 points detected, capped at 100" in response.text


def test_scan_uploaded_file(client):
    response = scan_file(client, PHISHING, "phishing.eml")
    assert response.status_code == 200
    assert "Likely phishing" in response.text


def test_wrong_file_type(client):
    response = scan_file(client, b"%PDF-1.4", "invoice.pdf")
    assert response.status_code == 400
    assert "Please upload a .eml or .txt file." in response.text


def test_nothing_to_scan(client):
    response = scan_text(client, "   ")
    assert response.status_code == 400
    assert "Please choose a file or paste the email content." in response.text


def test_file_too_large(tmp_path):
    app = create_app(database_url(tmp_path))
    app.config["MAX_CONTENT_LENGTH"] = 1024  # a small limit, so the test stays fast
    response = scan_file(app.test_client(), b"x" * 5000, "big.eml")
    assert response.status_code == 413
    assert "The file is too large" in response.text


def test_html_in_an_email_is_shown_as_text(client):
    response = scan_text(client, "Subject: Hi\n\n<script>alert('stolen')</script>")
    assert "<script>alert" not in response.text  # it must not run
    assert "&lt;script&gt;" in response.text  # it is shown as text


def test_page_lists_attachments_and_links(client):
    response = scan_text(client, PHISHING.decode())
    assert "PayPal_Invoice.pdf.exe" in response.text
    assert "https://paypal.com.account-verify.xyz/signin" in response.text


def test_hidden_link_address_is_shown_next_to_its_text(client):
    html_email = (
        "From: a@example.com\nSubject: Hi\nContent-Type: text/html\n\n"
        '<a href="https://tinyurl.com/abc">Best projects 2020</a>'
    )
    response = scan_text(client, html_email)
    assert '"Best projects 2020" &rarr;' in response.text
    assert "https://tinyurl.com/abc" in response.text


def test_links_in_the_email_cannot_be_clicked(client):
    response = scan_text(client, PHISHING.decode())
    assert 'href="http://203.0.113.45' not in response.text


def test_hidden_direction_character_is_shown_as_a_code(client):
    response = scan_file(client, (SAMPLES / "disguised_attachment.txt").read_bytes(), "x.txt")
    assert "[U+202E]" in response.text
    assert "‮" not in response.text


def test_note_when_there_are_no_headers(client):
    response = scan_text(client, "Dear customer, verify your password.")
    assert "No email headers found" in response.text


def test_history_page_lists_scans(client):
    scan_text(client, PHISHING.decode())
    response = client.get("/history")
    assert response.status_code == 200
    assert "Urgent: your account has been limited" in response.text


def test_second_scan_of_the_same_phishing_email_is_seen_before(client):
    first = scan_text(client, (SAMPLES / "phishing_paypal.txt").read_text())
    assert "Seen before" not in first.text
    second = scan_text(client, (SAMPLES / "phishing_paypal.txt").read_text())
    assert "Seen before" in second.text


def test_legitimate_scan_is_saved_but_not_remembered(client):
    scan_text(client, (SAMPLES / "legit_colleague.txt").read_text())
    again = scan_text(client, (SAMPLES / "legit_colleague.txt").read_text())
    assert "Seen before" not in again.text
    assert "Notes from today" in client.get("/history").text


def test_scan_still_works_when_the_database_is_down(tmp_path):
    # A folder that does not exist: the database cannot be opened.
    broken = "sqlite:///" + (tmp_path / "missing" / "folder" / "x.db").as_posix()
    client = create_app(broken).test_client()

    response = scan_text(client, PHISHING.decode())
    assert response.status_code == 200
    assert "Likely phishing" in response.text
    assert "History is unavailable right now" in response.text

    assert client.get("/history").status_code == 503
    assert client.get("/health").status_code == 200  # the server itself is fine


def test_cli_history_flag(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("DATABASE_URL", database_url(tmp_path))
    sample = str(SAMPLES / "phishing_paypal.txt")

    for _ in range(2):
        monkeypatch.setattr(sys, "argv", ["cli.py", "--history", sample])
        assert cli.main() == 0
    output = capsys.readouterr().out
    assert output.count("Seen before") == 2  # sender and link domain, on the second scan


def test_cli_without_history_flag_saves_nothing(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("DATABASE_URL", database_url(tmp_path))
    monkeypatch.setattr(sys, "argv", ["cli.py", str(SAMPLES / "phishing_paypal.txt")])
    cli.main()
    assert not (tmp_path / "test.db").exists()
