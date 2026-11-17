"""Tests for the history check and for what is remembered after a scan."""

from detector.checks.history import check_history, domains_to_remember, sender_to_remember
from detector.models import Link, ParsedEmail
from tests.helpers import rules

EMAIL = ParsedEmail(
    sender_address="security@paypa1-support.com",
    links=[Link("https://evil.xyz/login"), Link("https://bit.ly/abc"), Link("https://www.paypal.com/help")],
)


def test_flagged_sender_and_domain():
    findings = check_history(EMAIL, {"security@paypa1-support.com"}, {"evil.xyz"})
    assert rules(findings) == {"history_sender", "history_link_domain"}
    assert all(finding.points == 20 for finding in findings)


def test_nothing_flagged():
    assert check_history(EMAIL, set(), set()) == []


def test_full_address_not_domain():
    # One bad Gmail user must not mark every Gmail user.
    assert check_history(ParsedEmail(sender_address="dana@gmail.com"), {"bad@gmail.com"}, set()) == []


def test_remembers_only_links_that_broke_a_rule():
    # bit.ly is a shortener and paypal.com is a real link: neither is remembered.
    assert domains_to_remember(EMAIL) == {"evil.xyz"}


def test_never_remembers_a_brand_domain():
    email = ParsedEmail(links=[Link("http://drive.google.com/file/123")])
    assert domains_to_remember(email) == set()


def test_remembers_an_ip_address():
    email = ParsedEmail(links=[Link("http://203.0.113.45/login")])
    assert domains_to_remember(email) == {"203.0.113.45"}


def test_sender_to_remember():
    assert sender_to_remember(EMAIL) == "security@paypa1-support.com"
    forged = ParsedEmail(sender_address="service@paypal.com", auth_results="spf=fail; dmarc=fail")
    assert sender_to_remember(forged) is None  # a forged address is not the attacker's
    assert sender_to_remember(ParsedEmail()) is None
