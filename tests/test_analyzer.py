"""Tests for what the analyzer passes on to the report."""

from detector.analyzer import analyze

REPEATED = (
    "From: a@example.com\nSubject: Hi\nAttachments: a.pdf, a.pdf, b.zip\n\n"
    "https://example.com/x and again https://example.com/x\n"
)


def test_links_and_attachments_are_listed_once():
    result = analyze(REPEATED)
    assert [link.url for link in result.links] == ["https://example.com/x"]
    assert result.attachments == ["a.pdf", "b.zip"]
