"""Checks the links in an email."""

import re
from urllib.parse import urlsplit

from detector import config, domains
from detector.models import Finding, Link, ParsedEmail

INDICATOR = "Suspicious link"

# The order here is the order in which findings are shown.
DESCRIPTIONS = {
    "link_public_ip": "Link points to a public IP address instead of a domain name",
    "link_at_sign": "Link uses '@' to hide its real destination",
    "link_text_mismatch": "Link text shows one site, but the link goes to another",
    "link_lookalike_domain": "Link domain imitates a known brand",
    "link_brand_misplaced": "Brand name is placed in front of a domain it does not own",
    "link_unusual_tld": "Link domain ends with a commonly abused ending",
    "link_shortener": "Link uses a URL shortener that hides the destination",
    "link_long_structure": "Link has a long, convoluted structure",
    "link_no_encryption": "Link is not encrypted (http instead of https)",
}

# Link text that is itself a web address: "paypal.com", "https://www.paypal.com/login".
TEXT_ADDRESS_PATTERN = re.compile(r"^(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[:/?#]\S*)?$")


def check_links(email: ParsedEmail) -> list[Finding]:
    """Return one Finding per rule that at least one link breaks.

    Each rule counts once per email, however many links break it. All the
    links that broke it are listed as evidence.
    """
    evidence = {rule: [] for rule in DESCRIPTIONS}
    for link in email.links:
        for rule, detail in rules_broken_by(link):
            if detail not in evidence[rule]:
                evidence[rule].append(detail)

    return [
        Finding(INDICATOR, rule, DESCRIPTIONS[rule], config.RULE_POINTS[rule], details)
        for rule, details in evidence.items()
        if details
    ]


def rules_broken_by(link: Link) -> list[tuple[str, str]]:
    """Return (rule, evidence) for every rule that this one link breaks.

    Also used by the history check, to know which links were suspicious.
    """
    url = link.url
    host = domains.host_of(url)
    if not host:
        return []
    broken = []

    if domains.is_public_ip(host):
        broken.append(("link_public_ip", url))
        
    if "@" in urlsplit(url).netloc:
        broken.append(("link_at_sign", f"{url} (really goes to {host})"))

    shown = _address_in_text(link.text)
    if shown and domains.registered_domain(shown) != domains.registered_domain(host):
        broken.append(("link_text_mismatch", f'shows "{link.text}", goes to {url}'))

    # These rules are about domain names, so they do not apply to an IP address.
    if not domains.is_ip_address(host):
        domain = domains.registered_domain(host)

        brand = domains.imitated_brand(domain)
        if brand:
            broken.append(("link_lookalike_domain", f"{url} (imitates {brand})"))

        brand = domains.misplaced_brand(host)
        if brand:
            broken.append(("link_brand_misplaced", f"{url} (the real domain is {domain}, not {brand})"))

        if host.rsplit(".", 1)[-1] in config.UNUSUAL_TLDS:
            broken.append(("link_unusual_tld", url))

        if domain in config.URL_SHORTENERS or host.removeprefix("www.") in config.URL_SHORTENERS:
            broken.append(("link_shortener", url))

        if len(domains.subdomains(host)) > config.MAX_SUBDOMAINS:
            broken.append(("link_long_structure", url))

    if len(url) > config.MAX_URL_LENGTH:
        broken.append(("link_long_structure", url[:80] + "..."))

    if urlsplit(url).scheme == "http":
        broken.append(("link_no_encryption", url))

    return broken


def _address_in_text(text: str) -> str:
    """Return the host written in the link text, or '' if the text is not an address.

    "Click here" -> '', "paypal.com" -> "paypal.com", "report.pdf" -> '' (a file name).
    """
    match = TEXT_ADDRESS_PATTERN.match(text.strip().lower())
    if not match:
        return ""
    host = match.group(1)
    if host.rsplit(".", 1)[-1] in config.FILE_NAME_ENDINGS:
        return ""
    return host
