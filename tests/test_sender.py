"""Tests for the sender check."""

import pytest

from detector.checks.sender import check_sender
from detector.models import ParsedEmail
from tests.helpers import rules


def sender_rules(name="", address="", reply_to="", auth=""):
    email = ParsedEmail(sender_name=name, sender_address=address, reply_to=reply_to, auth_results=auth)
    return rules(check_sender(email))


@pytest.mark.parametrize("name, address, expected", [
    ("PayPal Security", "x@evil.net", {"sender_name_domain_mismatch"}),
    ("PayPal", "service@mail.paypal.com", set()),
    ("PayPa1 Security", "x@evil.net", {"sender_name_domain_mismatch"}),
    ("", "security@paypa1.com", {"sender_lookalike_domain"}),
    ("PayPal Security", "security@paypa1.com", {"sender_name_domain_mismatch", "sender_lookalike_domain"}),
    ("", "paypal-billing@random-shop.com", {"sender_brand_before_at"}),
    ("", "info@free-prizes.xyz", {"sender_unusual_tld"}),
    ("Dana Levi", "dana@gmail.com", set()),
    ("Pineapple Store", "shop@pineapple.com", set()),
    ("בנק לאומי", "info@leumi.co.il", set()),
    ("בנק לאומי", "info@leumi-secure.com", {"sender_name_domain_mismatch"}),
    ("GOV.UK Notify", "no-reply@notifications.service.gov.uk", set()),
    ("", "", set()),
])
def test_sender_rules(name, address, expected):
    assert sender_rules(name, address) == expected


@pytest.mark.parametrize("name, address, expected", [
    # The display name is checked by one rule only, by its kind.
    ("support@paypal.com", "x@evil.net", {"sender_name_is_other_address"}),
    ("billing@acme-corp.com", "x@evil.net", {"sender_name_is_other_address"}),
    ("support@paypal.com", "no-reply@paypal.com", set()),
    ("dana@gmail.com", "dana@gmail.com", set()),
])
def test_display_name_that_is_an_address(name, address, expected):
    assert sender_rules(name, address) == expected


def test_reply_to_compares_domains_not_addresses():
    assert sender_rules(address="no-reply@company.com", reply_to="support@company.com") == set()
    assert sender_rules(address="no-reply@company.com", reply_to="x@mail-verify.xyz") == {
        "sender_reply_to_other_domain"
    }


def test_authentication_failure():
    assert sender_rules(address="a@b.com", auth="spf=fail; dkim=pass; dmarc=fail") == {"sender_auth_failed"}
    assert sender_rules(address="a@b.com", auth="spf=softfail; dkim=pass") == set()


def test_known_limitation_free_mail_of_the_brand_itself():
    # FREE_MAIL_PROVIDERS was removed on purpose: this is not caught.
    assert sender_rules("Google Security", "google-security@gmail.com") == set()
