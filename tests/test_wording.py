"""Tests for the wording check."""

import pytest

from detector.checks.wording import check_wording
from detector.models import ParsedEmail
from tests.helpers import rules


def wording_rules(subject, body):
    return rules(check_wording(ParsedEmail(subject=subject, body=body)))


@pytest.mark.parametrize("subject, body, expected", [
    ("Your order", "Thanks for your order.", set()),
    ("Sale ends today", "Last chance! Act now.", {"wording_time_pressure"}),
    ("FINAL NOTICE", "URGENT!!! PAY NOW", {"wording_time_pressure", "wording_shouting"}),
    ("PDF", "PDF PDF PDF", set()),  # the same capital word three times is not shouting
    # Capital letters inside a link are part of an address, not shouting.
    ("Hi", "Watch https://youtube.com/channel/UCdg-AA and https://x.com/ABC/DEF", set()),
    ("Hi", "WATCH THIS NOW https://youtube.com/channel/UCdg-AA", {"wording_shouting"}),
    # AM and PM are times, not shouting: only two real capital words are left.
    ("Re: Notes", "On Thu at 11:23 AM, until 5 PM, about the BPP and the CLASS", set()),
    ("Hi", "I wonder about it", set()),  # "you won" must not match inside "wonder"
    ("Hi", "Congratulations, you won!", {"wording_prize_or_refund"}),
    ("Refund processed", "Your refund was processed.", {"wording_prize_or_refund"}),
    ("החזרת מוצר", "קיבלנו את החזרת המוצר שלך", set()),  # "החזר" alone is not a phrase
    ("הזמנה", "קיבלת זיכוי על ההזמנה", {"wording_prize_or_refund"}),  # like "refund" alone
    ("זיכוי", "הזיכוי יועבר אליך", {"wording_prize_or_refund"}),  # Hebrew prefixes still match
    ("זיכוי", "לזיכוי החשבון לחץ כאן", {"wording_prize_or_refund"}),
    ("מס", "ההחזר הכספי ממתין לך", {"wording_prize_or_refund"}),
    ("מס", "החזר המס שלך אושר", {"wording_prize_or_refund"}),
    ("החזר מס", "לקוח יקר, הזן את הסיסמה תוך 24 שעות",
     {"wording_prize_or_refund", "wording_generic_greeting", "wording_sensitive_info", "wording_time_pressure"}),
    ("Help", "Please install AnyDesk", {"wording_install_or_permissions"}),
])
def test_wording_rules(subject, body, expected):
    assert wording_rules(subject, body) == expected


def test_every_wording_category_is_worth_10():
    findings = check_wording(ParsedEmail(subject="URGENT!!!", body="Dear customer, you have won a refund"))
    assert findings
    assert all(finding.points == 10 for finding in findings)
