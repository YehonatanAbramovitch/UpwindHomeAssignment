"""Checks the names of attached files.

Only the names are inspected. The files are never opened: 
scanning their content is the job of an antivirus.
"""

from detector import config
from detector.models import Finding, ParsedEmail, printable

INDICATOR = "Suspicious attachment"

DESCRIPTIONS = {
    "attachment_runs_code": "File runs code when opened",
    "attachment_disguised_name": "File name hides its real type",
    "attachment_macro": "Document that can contain macros",
    "attachment_html": "HTML file, which can hold a fake login page",
    "attachment_archive": "Archive or disk image, which hides its content from scanning",
}


def check_attachments(email: ParsedEmail) -> list[Finding]:
    """Return one Finding per attachment rule that at least one file breaks."""
    evidence = {rule: [] for rule in DESCRIPTIONS}
    for name in email.attachments:
        shown = printable(name)
        for rule in _broken_rules(name):
            if shown not in evidence[rule]:
                evidence[rule].append(shown)

    return [
        Finding(INDICATOR, rule, DESCRIPTIONS[rule], config.RULE_POINTS[rule], names)
        for rule, names in evidence.items()
        if names
    ]


def _broken_rules(name: str) -> list[str]:
    """Return every rule that this one file name breaks."""
    real_name = name.strip().lower()
    for character in config.DIRECTION_OVERRIDE_CHARACTERS:
        real_name = real_name.replace(character, "")
    parts = real_name.split(".")
    extension = parts[-1] if len(parts) > 1 else ""
    broken = []

    if extension in config.CODE_EXTENSIONS:
        broken.append("attachment_runs_code")
    if _is_disguised(name, parts, extension):
        broken.append("attachment_disguised_name")
    if extension in config.MACRO_EXTENSIONS:
        broken.append("attachment_macro")
    if extension in config.HTML_EXTENSIONS:
        broken.append("attachment_html")
    if extension in config.ARCHIVE_EXTENSIONS:
        broken.append("attachment_archive")

    return broken


def _is_disguised(name: str, parts: list[str], extension: str) -> bool:
    """True if the name is built to hide what the file really is."""
    # A hidden character that reverses the display order: "invoice[U+202E]fdp.exe"
    if any(character in name for character in config.DIRECTION_OVERRIDE_CHARACTERS):
        return True
    # Spaces that push the real extension out of view: "report.pdf      .exe".
    # Only when that extension runs code: "my   file.pdf" hides nothing dangerous.
    if extension in config.CODE_EXTENSIONS and " " * config.MIN_SPACE_RUN_IN_FILE_NAME in name:
        return True
    # Double extension: a harmless type right before a code type, "invoice.pdf.exe".
    # "version.2.exe" is not disguised: "2" is not a document type.
    return (
        len(parts) >= 3
        and extension in config.CODE_EXTENSIONS
        and parts[-2].strip() in config.DOCUMENT_EXTENSIONS
    )
