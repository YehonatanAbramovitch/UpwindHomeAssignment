"""Checks who the email claims to be from."""

import re

from detector import config, domains
from detector.models import Finding, ParsedEmail

INDICATOR = "Spoofed sender"

DESCRIPTIONS = {
    "sender_name_domain_mismatch": "Display name claims a known organization, but the domain is not theirs",
    "sender_lookalike_domain": "Sender domain imitates a known brand",
    "sender_name_is_other_address": "Display name is a different email address",
    "sender_auth_failed": "Sender authentication failed (SPF, DKIM or DMARC)",
    "sender_brand_before_at": "Brand name appears before the '@' of an unrelated domain",
    "sender_reply_to_other_domain": "Replies go to a different domain than the sender's",
    "sender_unusual_tld": "Sender domain ends with a commonly abused ending",
}

ADDRESS_PATTERN = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
AUTH_FAIL_PATTERN = re.compile(r"\b(spf|dkim|dmarc)=fail\b")


def check_sender(email: ParsedEmail) -> list[Finding]:
    """Return one Finding per sender rule that this email breaks."""
    address = email.sender_address
    host = domains.domain_of_address(address)
    domain = domains.registered_domain(host)
    broken = []  # (rule, evidence)

    # The authentication result does not depend on the address, so check it first.
    failed = sorted(set(AUTH_FAIL_PATTERN.findall(email.auth_results)))
    if failed:
        broken.append(("sender_auth_failed", ", ".join(f"{name}=fail" for name in failed)))

    if not host:  # no sender address: nothing else to compare
        return _findings(broken)

    # The display name is checked once, by the rule that fits its kind. A name
    # like "support@paypal.com" is an address that also names a brand; checking
    # it with both rules would count one fake name twice.
    shown = ADDRESS_PATTERN.search(email.sender_name)
    if shown:
        # The display name is an address. Domains are compared, not full
        # addresses: "support@paypal.com" on mail from no-reply@paypal.com is
        # the same organization.
        shown_domain = domains.registered_domain(domains.domain_of_address(shown.group(0)))
        if shown_domain != domain:
            broken.append(("sender_name_is_other_address",
                           f'name "{email.sender_name}", address {address}'))
    else:
        # The display name is free text: does it claim a brand that does not own the domain?
        brand = domains.brand_in_text(email.sender_name)
        if brand and not domains.brand_owns(brand, host):
            broken.append(("sender_name_domain_mismatch",
                           f'name "{email.sender_name}", address {address}'))

    brand = domains.imitated_brand(domain)
    if brand:
        broken.append(("sender_lookalike_domain", f"{address} (imitates {brand})"))

    local_part = domains.normalize(address.rsplit("@", 1)[0])
    for brand, word in domains.brand_words():
        if domains.contains_word(local_part, domains.normalize(word)) and not domains.brand_owns(brand, host):
            broken.append(("sender_brand_before_at", f"{address} (uses the name {brand})"))
            break

    reply_host = domains.domain_of_address(email.reply_to)
    if reply_host and domains.registered_domain(reply_host) != domain:
        broken.append(("sender_reply_to_other_domain", f"sent from {address}, replies go to {email.reply_to}"))

    if host.rsplit(".", 1)[-1] in config.UNUSUAL_TLDS:
        broken.append(("sender_unusual_tld", address))

    return _findings(broken)


def _findings(broken: list[tuple[str, str]]) -> list[Finding]:
    """Turn (rule, evidence) pairs into Findings, in the order of DESCRIPTIONS."""
    evidence = dict(broken)
    return [
        Finding(INDICATOR, rule, DESCRIPTIONS[rule], config.RULE_POINTS[rule], [evidence[rule]])
        for rule in DESCRIPTIONS
        if rule in evidence
    ]
