"""Tests for reading a raw email into its parts."""

from detector.parser import parse_email

SIMPLE = """From: PayPal Security <Security@Paypa1.com>
Reply-To: help@mail-verify.xyz
Subject: Account notice
Attachments: invoice.pdf.exe, notes.zip
Authentication-Results: mx.example.com; spf=fail

Visit https://example.com/page, or http://203.0.113.45/login.
"""


def test_simple_text_email():
    email = parse_email(SIMPLE)
    assert email.sender_name == "PayPal Security"
    assert email.sender_address == "security@paypa1.com"  # lower case
    assert email.reply_to == "help@mail-verify.xyz"
    assert email.subject == "Account notice"
    assert email.attachments == ["invoice.pdf.exe", "notes.zip"]
    assert "spf=fail" in email.auth_results
    # Punctuation after a URL is not part of it.
    assert [link.url for link in email.links] == ["https://example.com/page", "http://203.0.113.45/login"]


def test_html_email_keeps_link_text_and_hides_scripts():
    raw = (
        "From: a@example.com\nSubject: Hi\nContent-Type: text/html\n\n"
        '<p>Hello</p><a href="https://account-review.top/x">paypal.com</a>'
        "<script>var hidden = 1;</script>"
    )
    email = parse_email(raw)
    assert email.links[0].url == "https://account-review.top/x"
    assert email.links[0].text == "paypal.com"
    assert "hidden" not in email.body


def test_email_without_headers():
    email = parse_email("\njust some text with https://example.com")
    assert email.sender_address == ""
    assert email.links[0].url == "https://example.com"


def test_hebrew_email():
    email = parse_email("From: בנק לאומי <info@leumi.co.il>\nSubject: הודעה\n\nשלום, זו הודעה.")
    assert email.sender_name == "בנק לאומי"
    assert "שלום" in email.body


HEADERS = "From: PayPal <x@paypa1.com>\nSubject: Verify\n\nbody text\n"


def test_empty_lines_before_the_headers():
    assert parse_email("\n\n" + HEADERS).sender_address == "x@paypa1.com"


def test_spaces_before_the_headers():
    indented = "  From: PayPal <x@paypa1.com>\n  Subject: Verify\n\nbody text\n"
    email = parse_email(indented)
    assert email.sender_address == "x@paypa1.com"
    assert email.subject == "Verify"


def test_byte_order_mark_from_notepad():
    assert parse_email(b"\xef\xbb\xbf" + HEADERS.encode()).sender_address == "x@paypa1.com"


def test_long_header_continued_on_the_next_line_is_kept():
    # In a real .eml file, a long header continues on a line that starts with
    # a space. That must still be read as one header.
    raw = "From: PayPal <x@paypa1.com>\nSubject: Your account\n  has been limited\n\nbody\n"
    assert parse_email(raw).subject.split() == ["Your", "account", "has", "been", "limited"]


def test_empty_input_does_not_crash():
    email = parse_email(b"")
    assert email.body == ""
    assert email.links == []
