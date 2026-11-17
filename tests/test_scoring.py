"""Tests for the score and the verdict."""

import pytest

from detector.models import Finding
from detector.scoring import LIKELY_LEGITIMATE, LIKELY_PHISHING, SUSPICIOUS, risk_score, verdict


def findings_worth(*points):
    return [Finding("x", "x", "x", value) for value in points]


@pytest.mark.parametrize("points, expected_score", [
    ((), 0),
    ((10,), 10),
    ((30, 20), 50),
    ((30,) * 9, 100),  # capped
])
def test_risk_score(points, expected_score):
    assert risk_score(findings_worth(*points)) == expected_score


@pytest.mark.parametrize("score, expected", [
    (0, LIKELY_LEGITIMATE),
    (29, LIKELY_LEGITIMATE),
    (30, SUSPICIOUS),  # one HIGH finding alone is only suspicious
    (59, SUSPICIOUS),
    (60, LIKELY_PHISHING),  # two HIGH findings
    (100, LIKELY_PHISHING),
])
def test_verdict_thresholds(score, expected):
    assert verdict(score) == expected
