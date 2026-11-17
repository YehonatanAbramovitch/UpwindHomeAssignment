"""Checks the subject and body for suspicious wording.

Keyword matching does not understand context, 
so every category is worth the same LOW points (see config.RULE_POINTS).
"""

import re

from detector import config, domains
from detector.models import Finding, ParsedEmail

INDICATOR = "Suspicious wording"

DESCRIPTIONS = {
    "wording_time_pressure": "Creates time pressure",
    "wording_threat": "Threatens the reader",
    "wording_sensitive_info": "Asks for sensitive information",
    "wording_prize_or_refund": "Promises a prize or a refund",
    "wording_payment_demand": "Demands a payment",
    "wording_generic_greeting": "Uses a generic greeting instead of a name",
    "wording_install_or_permissions": "Asks to install something or grant permissions",
    "wording_shouting": "Shouting style (capital letters or '!!!')",
}

CAPITAL_WORD_PATTERN = re.compile(r"\b[A-Z]{2,}\b")  # one capital letter ("I") is not a word


def check_wording(email: ParsedEmail) -> list[Finding]:
    """Return one Finding per wording category found in the subject or body."""
    original = f"{email.subject}\n{email.body}"
    text = original.lower()
    findings = []

    for rule, phrases in config.WORDING_PHRASES.items():
        # Whole words in English: "you won" must not match "you wonder".
        found = [phrase for phrase in phrases if domains.contains_word(text, phrase)]
        if found:
            findings.append(_finding(rule, [f'"{phrase}"' for phrase in found]))

    shouting = _shouting_evidence(original)
    if shouting:
        findings.append(_finding("wording_shouting", shouting))

    return findings


def _shouting_evidence(text: str) -> list[str]:
    """Evidence of shouting, or [] if there is none.

    Shouting is at least SHOUTING_MIN_CAPITAL_WORDS different words written
    entirely in capital letters, or a run of SHOUTING_MIN_EXCLAMATION_RUN
    exclamation marks. One or two capital words are usually acronyms (PDF, NASA).
    """
    evidence = []
    capital_words = list(dict.fromkeys(CAPITAL_WORD_PATTERN.findall(text)))  # unique, in order
    if len(capital_words) >= config.SHOUTING_MIN_CAPITAL_WORDS:
        evidence.append("capital words: " + ", ".join(capital_words[:5]))
    if "!" * config.SHOUTING_MIN_EXCLAMATION_RUN in text:
        evidence.append("!" * config.SHOUTING_MIN_EXCLAMATION_RUN)
    return evidence


def _finding(rule: str, evidence: list[str]) -> Finding:
    return Finding(INDICATOR, rule, DESCRIPTIONS[rule], config.RULE_POINTS[rule], evidence)
