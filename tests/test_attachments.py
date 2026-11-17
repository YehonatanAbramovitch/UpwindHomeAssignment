"""Tests for the attachment check."""

import pytest

from detector.checks.attachments import check_attachments
from detector.models import ParsedEmail
from tests.helpers import rules

RLO = "‮"  # hidden character that reverses the display order


def attachment_rules(*names):
    return rules(check_attachments(ParsedEmail(attachments=list(names))))


@pytest.mark.parametrize("name, expected", [
    ("invoice.pdf", set()),
    ("setup.exe", {"attachment_runs_code"}),
    ("  SETUP.EXE  ", {"attachment_runs_code"}),  # capital letters do not hide it
    ("Report.PDF.JS", {"attachment_runs_code", "attachment_disguised_name"}),
    ("invoice.pdf.exe", {"attachment_runs_code", "attachment_disguised_name"}),
    ("version.2.exe", {"attachment_runs_code"}),  # "2" is not a document type
    (f"invoice{RLO}fdp.exe", {"attachment_runs_code", "attachment_disguised_name"}),
    ("report.pdf      .exe", {"attachment_runs_code", "attachment_disguised_name"}),
    ("my   file.pdf", set()),  # spaces count only when they hide code
    ("budget.xlsm", {"attachment_macro"}),
    ("login.html", {"attachment_html"}),
    ("backup.tar.gz", {"attachment_archive"}),
    ("noextension", set()),
])
def test_attachment_rules(name, expected):
    assert attachment_rules(name) == expected


def test_hidden_character_is_shown_as_a_code_in_the_evidence():
    findings = check_attachments(ParsedEmail(attachments=[f"invoice{RLO}fdp.exe"]))
    assert findings[0].evidence == ["invoice[U+202E]fdp.exe"]


def test_two_archives_count_once():
    findings = check_attachments(ParsedEmail(attachments=["a.zip", "b.zip"]))
    assert len(findings) == 1
    assert findings[0].evidence == ["a.zip", "b.zip"]
