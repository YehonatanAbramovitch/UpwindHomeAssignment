"""Helpers for reading domain names.

Used by the link, sender and history checks, so they live here once.
"""

import ipaddress
import re   
from typing import Optional
from urllib.parse import urlsplit

from detector import config


def host_of(url: str) -> str:
    """Return the host name of a URL in lower case, or '' if it has none."""
    try:
        host = urlsplit(url.strip()).hostname or ""
    except ValueError:  # a malformed URL must not crash the scan
        return ""
    return host.rstrip(".")


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# Addresses that only work inside a local network or on the same computer.
# Every other address is treated as public. 
PRIVATE_NETWORKS = [
    ipaddress.ip_network(network)
    for network in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # private networks
        "127.0.0.0/8", "::1/128",  # this computer
        "169.254.0.0/16", "fe80::/10",  # link-local
        "fc00::/7",  # private IPv6
    )
]


def is_public_ip(host: str) -> bool:
    """True for an address on the internet, False for private ones like 10.0.0.5."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not any(address in network for network in PRIVATE_NETWORKS)


def registered_domain(host: str) -> str:
    """The part of a host name that someone registered.

    "login.leumi.co.il" -> "leumi.co.il", "paypal.com.evil.xyz" -> "evil.xyz".
    """
    if not host or is_ip_address(host):
        return host
    labels = host.split(".")
    size = 3 if ".".join(labels[-2:]) in config.TWO_PART_SUFFIXES else 2
    return ".".join(labels[-size:])


def subdomains(host: str) -> list[str]:
    """The parts in front of the registered domain, without "www"."""
    if not host or is_ip_address(host):
        return []
    size = len(registered_domain(host).split("."))
    return [label for label in host.split(".")[:-size] if label != "www"]


def normalize(text: str) -> str:
    """Replace lookalike characters, so that "paypa1" and "paypal" become equal.

    Always applied to both sides of a comparison (see config.LOOKALIKE_CHARACTERS).
    """
    text = text.lower()
    for fake, real in config.LOOKALIKE_CHARACTERS.items():
        text = text.replace(fake, real)
    return text


def contains_word(text: str, word: str) -> bool:
    """True if `word` appears in `text` as a whole word: "apple" is not in "pineapple"."""
    return re.search(rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])", text) is not None


def brand_owns(brand: str, domain: str) -> bool:
    """True if `domain` is one of the brand's real domains, or a subdomain of one."""
    return any(
        domain == real or domain.endswith("." + real)
        for real in config.KNOWN_BRANDS[brand]
    )


def domain_of_address(address: str) -> str:
    """"security@mail.paypal.com" -> "mail.paypal.com"."""
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def brand_in_text(text: str) -> Optional[str]:
    """The known brand named in free text, such as a display name.

    Lookalike characters are normalized first, so "PayPa1 Security" names paypal.
    """
    normalized = normalize(text)
    for brand in config.KNOWN_BRANDS:
        if contains_word(normalized, normalize(brand)):
            return brand
    return None


def brand_words() -> list[tuple[str, str]]:
    """Brand names as they can appear inside a domain: "israel post" -> "israelpost".

    Hebrew names are skipped, because they do not appear in domain names.
    """
    return [
        (brand, brand.replace(" ", ""))
        for brand in config.KNOWN_BRANDS
        if brand.isascii()
    ]


def imitated_brand(domain: str) -> Optional[str]:
    """The brand that a registered domain imitates with lookalike characters.

    "paypa1.com" and "paypa1-support.com" imitate paypal. "paypal.com" does not
    (it is the real one), and neither does "google.co.il": it has the brand's
    real name, so no character was replaced to fool the reader.
    """
    name = domain.split(".")[0]  # "paypa1-support.com" -> "paypa1-support"
    for brand, word in brand_words():
        if "." in word or brand_owns(brand, domain):
            continue
        if contains_word(normalize(name), normalize(word)) and not contains_word(name, word):
            return brand
    return None


def misplaced_brand(host: str) -> Optional[str]:
    """The brand that appears in front of a domain it does not own.

    "paypal.com.account-verify.xyz": the real domain is account-verify.xyz, and
    "paypal.com" in front of it is a subdomain that anyone can create.
    """
    domain = registered_domain(host)
    in_front = normalize(".".join(subdomains(host)))
    for brand, word in brand_words():
        if not brand_owns(brand, domain) and contains_word(in_front, normalize(word)):
            return brand
    return None
