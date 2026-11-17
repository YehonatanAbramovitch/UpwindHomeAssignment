"""Checks the email against previous scans.

This module does not read the database itself. The caller passes in what was
flagged before (from SQLite locally, from RDS on AWS), so the check works the
same with any storage and is easy to test.
"""

from typing import Optional

from detector import config, domains
from detector.checks.links import rules_broken_by
from detector.checks.sender import AUTH_FAIL_PATTERN
from detector.models import Finding, ParsedEmail

INDICATOR = "Seen before"

DESCRIPTIONS = {
    "history_sender": "This sender was in an email flagged as phishing before",
    "history_link_domain": "A link goes to a domain flagged as phishing before",
}


def check_history(
    email: ParsedEmail, flagged_senders: set[str], flagged_link_domains: set[str]
) -> list[Finding]:
    """Compare the email with what earlier scans flagged.

    flagged_senders: full sender addresses of earlier emails that scored
        PHISHING_THRESHOLD or more.
    flagged_link_domains: domains of suspicious links in those emails.
    """
    findings = []

    if email.sender_address and email.sender_address in flagged_senders:
        findings.append(_finding("history_sender", [email.sender_address]))

    seen = sorted(link_domains(email) & flagged_link_domains)
    if seen:
        findings.append(_finding("history_link_domain", seen))

    return findings


def sender_to_remember(email: ParsedEmail) -> Optional[str]:
    """The sender address to save from this email, if it is judged as phishing.

    Nothing is saved when sender authentication failed: 
    the address was then most likely forged, and it belongs to someone else, not to the attacker.
    Saving "service@paypal.com" from a forged email would add points to every real PayPal email from then on.
    """
    if not email.sender_address or AUTH_FAIL_PATTERN.search(email.auth_results):
        return None
    return email.sender_address


def domains_to_remember(email: ParsedEmail) -> set[str]:
    """The domains to save from this email, if it is judged as phishing.

    Only links that broke a link rule themselves: phishing emails also contain
    real links to look trustworthy, and those must not be remembered.
    """
    return {
        domain
        for link in email.links
        if rules_broken_by(link)
        for domain in _remembered_domain(link.url)
    }


def link_domains(email: ParsedEmail) -> set[str]:
    """The domains of all links in the email, in the form they are remembered."""
    return {domain for link in email.links for domain in _remembered_domain(link.url)}


def _remembered_domain(url: str) -> list[str]:
    """[registered domain] of a link, or [] if it must never be remembered.

    Skipped: shorteners and the real domains of known brands (drive.google.com).
    They are services everyone uses, and one bad user must not mark them.
    An attacker may host a page there, but the domain is not the attacker's.
    A broken URL is skipped too. An IP address is kept as it is.
    """
    host = domains.host_of(url)
    if not host:
        return []
    domain = domains.registered_domain(host)
    if domain in config.URL_SHORTENERS or host.removeprefix("www.") in config.URL_SHORTENERS:
        return []
    if any(domains.brand_owns(brand, domain) for brand in config.KNOWN_BRANDS):
        return []
    return [domain]


def _finding(rule: str, evidence: list[str]) -> Finding:
    return Finding(INDICATOR, rule, DESCRIPTIONS[rule], config.RULE_POINTS[rule], evidence)
