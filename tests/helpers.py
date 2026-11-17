"""Small helpers shared by the tests."""

from detector.models import Finding


def rules(findings: list[Finding]) -> set[str]:
    """The rule ids that fired, so a test can compare them with a simple set."""
    return {finding.rule for finding in findings}