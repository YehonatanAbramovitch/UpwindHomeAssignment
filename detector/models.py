"""Data structures shared by every part of the detector, and how they are shown to a person."""

from dataclasses import asdict, dataclass, field

from detector import config


def printable(text: str) -> str:
    """Show hidden direction characters as codes, so a reader cannot be fooled by them.

    "invoice[hidden]fdp.exe" -> "invoice[U+202E]fdp.exe". The checks work on the
    real text; only what is shown to a person goes through this function.
    """
    for character in config.DIRECTION_OVERRIDE_CHARACTERS:
        text = text.replace(character, f"[U+{ord(character):04X}]")
    return text


@dataclass
class Link:
    """A link found in the email.

    `text` is the visible label of an HTML link. 
    It is empty for a bare URL that was simply written in the text.
    """

    url: str
    text: str = ""


@dataclass
class ParsedEmail:
    """The parts of an email that the checks look at."""

    sender_name: str = ""  # display name, free text chosen by the sender
    sender_address: str = ""
    reply_to: str = ""  # where a reply would be sent, if different
    subject: str = ""
    body: str = ""  # visible text only, without HTML tags
    links: list[Link] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)  # file names
    auth_results: str = ""  # the receiving server's SPF/DKIM/DMARC verdict, if present


@dataclass
class Finding:
    """One phishing indicator that a check detected."""

    indicator: str  # indicator family, for example "Suspicious link"
    rule: str  # rule id, matches a key in config.RULE_POINTS
    description: str  # explanation shown to the user
    points: int  # points this finding adds to the risk score
    evidence: list[str] = field(default_factory=list)  # what triggered it


@dataclass
class ScanResult:
    """The final answer for one scanned email."""

    sender: str
    subject: str
    body: str
    score: int
    verdict: str
    findings: list[Finding]
    # Shown to the user next to the content: every link and attached file,
    # also the ones that did not trigger any finding.
    links: list[Link] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
