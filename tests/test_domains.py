"""Tests for the domain helpers."""

import pytest

from detector import domains


@pytest.mark.parametrize("host, expected", [
    ("paypal.com", "paypal.com"),
    ("login.paypal.com", "paypal.com"),
    ("paypal.com.account-verify.xyz", "account-verify.xyz"),
    ("www.login.leumi.co.il", "leumi.co.il"),  # two-part Israeli suffix
    ("203.0.113.45", "203.0.113.45"),  # an IP address stays as it is
])
def test_registered_domain(host, expected):
    assert domains.registered_domain(host) == expected


@pytest.mark.parametrize("host, expected", [
    ("www.login.leumi.co.il", ["login"]),  # "www" is not counted
    ("login.secure.account.update.example.com", ["login", "secure", "account", "update"]),
    ("paypal.com", []),
])
def test_subdomains(host, expected):
    assert domains.subdomains(host) == expected


@pytest.mark.parametrize("host, expected", [
    ("203.0.113.45", True),  # the range used in examples counts as public
    ("8.8.8.8", True),
    ("10.0.0.5", False),
    ("192.168.1.1", False),
    ("127.0.0.1", False),
    ("paypal.com", False),  # not an IP address at all
])
def test_is_public_ip(host, expected):
    assert domains.is_public_ip(host) == expected


@pytest.mark.parametrize("domain, expected", [
    ("paypa1.com", "paypal"),
    ("netfl1x.com", "netflix"),  # "1" imitating "i": both sides are normalized
    ("micros0ft.com", "microsoft"),
    ("rnicrosoft.com", "microsoft"),  # "rn" imitating "m"
    ("paypa1-support.com", "paypal"),
    ("paypal.com", None),  # the real one
    ("netflix.com", None),
    ("google.co.il", None),  # the real name: no character was replaced
    ("google-analytics.com", None),  # the real name plus a word: a known limitation
    ("pineapple.com", None),
])
def test_imitated_brand(domain, expected):
    assert domains.imitated_brand(domain) == expected


@pytest.mark.parametrize("host, expected", [
    ("paypal.com.account-verify.xyz", "paypal"),
    ("paypa1.com.secure-login.top", "paypal"),
    ("gov.il.evil.com", "gov.il"),
    ("www.health.gov.il", None),
    ("mail.paypal.com", None),
])
def test_misplaced_brand(host, expected):
    assert domains.misplaced_brand(host) == expected


@pytest.mark.parametrize("text, expected", [
    ("PayPal Security", "paypal"),
    ("PayPa1 Security", "paypal"),
    ("PayPaI Security", "paypal"),  # capital I imitating l
    ("בנק לאומי", "בנק לאומי"),
    ("Pineapple Store", None),  # whole words only
    ("Dana Levi", None),
])
def test_brand_in_text(text, expected):
    assert domains.brand_in_text(text) == expected
