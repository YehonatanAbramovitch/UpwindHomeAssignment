"""Runs the whole scan: read the email, run every check, score it.

The command line and the web app both call analyze(), so there is only one version of the detection logic.
""" 

from typing import Union

from detector.checks.attachments import check_attachments
from detector.checks.history import check_history
from detector.checks.links import check_links
from detector.checks.sender import check_sender
from detector.checks.wording import check_wording
from detector.models import ScanResult
from detector.parser import parse_email
from detector.scoring import risk_score, verdict


def analyze(
    raw: Union[bytes, str],
    flagged_senders: frozenset[str] = frozenset(),
    flagged_link_domains: frozenset[str] = frozenset(),
) -> ScanResult:
    """Scan one email and return the full result.

    The two flagged_* sets come from the history of earlier scans. Without
    them (for example on the command line, which has no database) the
    history check simply finds nothing.
    """
    email = parse_email(raw)

    findings = (
        check_sender(email)
        + check_links(email)
        + check_attachments(email)
        + check_wording(email)
        + check_history(email, set(flagged_senders), set(flagged_link_domains))
    )
    # Strongest evidence first. The sort is stable, so findings with the same
    # points keep the order of the checks above.
    findings.sort(key=lambda finding: finding.points, reverse=True)

    score = risk_score(findings)
    return ScanResult(
        sender=_sender_line(email.sender_name, email.sender_address),
        subject=email.subject,
        body=email.body,
        score=score,
        verdict=verdict(score),
        findings=findings,
        links=_unique(email.links),
        attachments=_unique(email.attachments),
    )


def _unique(items: list) -> list:
    """Each item once, in its first order: an email often repeats the same link."""
    unique = []
    for item in items:
        if item not in unique:
            unique.append(item)
    return unique


def _sender_line(name: str, address: str) -> str:
    """"PayPal Security <security@paypa1.com>", or just the address without a name."""
    if name and address:
        return f"{name} <{address}>"
    return name or address
