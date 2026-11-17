"""Turns the detected findings into a risk score and a verdict."""

from detector import config
from detector.models import Finding

LIKELY_LEGITIMATE = "Likely legitimate"
SUSPICIOUS = "Suspicious"
LIKELY_PHISHING = "Likely phishing"


def risk_score(findings: list[Finding]) -> int:
    """The sum of the points of all findings, capped at MAX_SCORE.

    Each check already returns a rule at most once, so every rule counts once per email.
    """
    return min(sum(finding.points for finding in findings), config.MAX_SCORE)


def verdict(score: int) -> str:
    """0-29 likely legitimate, 30-59 suspicious, 60-100 likely phishing."""
    if score >= config.PHISHING_THRESHOLD:  
        return LIKELY_PHISHING
    if score >= config.SUSPICIOUS_THRESHOLD:
        return SUSPICIOUS
    return LIKELY_LEGITIMATE
