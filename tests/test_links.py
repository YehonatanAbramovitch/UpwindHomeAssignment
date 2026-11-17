"""Tests for the link check."""

import pytest

from detector.checks.links import check_links
from detector.models import Link, ParsedEmail
from tests.helpers import rules


def link_rules(url, text=""):
    return rules(check_links(ParsedEmail(links=[Link(url, text)])))


@pytest.mark.parametrize("url, text, expected", [
    ("http://203.0.113.45/login", "", {"link_public_ip", "link_no_encryption"}),
    ("http://10.0.0.5/grafana", "", {"link_no_encryption"}),  # private IP is not flagged
    ("https://paypal.com@evil.net/login", "", {"link_at_sign"}),
    ("https://account-review.top/x", "paypal.com", {"link_text_mismatch", "link_unusual_tld"}),
    ("https://www.paypal.com/x", "paypal.com", set()),
    ("https://evil.com/x", "Click here", set()),  # text that is not an address
    ("https://files.example.com/r", "report.pdf", set()),  # a file name, not a site
    ("https://paypa1.com/login", "", {"link_lookalike_domain"}),
    ("https://paypal.com.account-verify.xyz/signin", "", {"link_brand_misplaced", "link_unusual_tld"}),
    ("https://bit.ly/3xParcel", "", {"link_shortener"}),
    ("https://login.secure.account.update.example.com/", "", {"link_long_structure"}),
    ("https://www.login.leumi.co.il/", "", set()),
    ("https://example.com/" + "a" * 250, "", {"link_long_structure"}),
    ("https://www.irs.gov/", "", set()),
    ("http://[::1", "", set()),  # a broken URL must not crash the scan
])
def test_link_rules(url, text, expected):
    assert link_rules(url, text) == expected


def test_each_rule_counts_once_with_all_links_as_evidence():
    email = ParsedEmail(links=[Link("http://a.example.com"), Link("http://b.example.com")])
    findings = check_links(email)
    assert len(findings) == 1
    assert findings[0].points == 10
    assert findings[0].evidence == ["http://a.example.com", "http://b.example.com"]
