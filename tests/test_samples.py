"""End-to-end tests: every sample email gets the verdict it was written for."""

from pathlib import Path

import pytest

from detector.analyzer import analyze
from detector.scoring import LIKELY_LEGITIMATE, LIKELY_PHISHING, SUSPICIOUS

SAMPLES = Path(__file__).parent.parent / "samples"


@pytest.mark.parametrize("file_name, expected_score, expected_verdict", [
    ("legit_colleague.txt", 0, LIKELY_LEGITIMATE),
    ("legit_marketing.txt", 20, LIKELY_LEGITIMATE),  # time pressure alone is not enough
    ("internal_private_ip.txt", 10, LIKELY_LEGITIMATE),  # the private IP itself is not flagged
    ("suspicious_delivery.txt", 50, SUSPICIOUS),
    ("disguised_attachment.txt", 60, LIKELY_PHISHING),
    ("phishing_paypal.txt", 100, LIKELY_PHISHING),
])
def test_sample(file_name, expected_score, expected_verdict):
    result = analyze((SAMPLES / file_name).read_bytes())
    assert result.score == expected_score
    assert result.verdict == expected_verdict


def test_findings_are_sorted_strongest_first():
    result = analyze((SAMPLES / "phishing_paypal.txt").read_bytes())
    points = [finding.points for finding in result.findings]
    assert points == sorted(points, reverse=True)


def test_history_adds_points_on_a_repeated_scan():
    raw = (SAMPLES / "suspicious_delivery.txt").read_bytes()
    result = analyze(raw, flagged_senders=frozenset({"notify@parcel-update.top"}))
    assert result.score == 70  # 50 + 20 for the sender seen before
