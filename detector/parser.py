"""Turns the raw text of an email into a ParsedEmail that the checks can inspect.

Works with a simple text file (a few header lines, an empty line, the body)
and with a full .eml file that has HTML parts and real attachments.
"""

import re
from email import message_from_bytes, policy
from email.utils import parseaddr
from html.parser import HTMLParser
from typing import Union

from detector.models import Link, ParsedEmail

URL_PATTERN = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
HTML_TAG_PATTERN = re.compile(r"<(a|html|body|div|p|br|table)\b", re.IGNORECASE)


def parse_email(raw: Union[bytes, str]) -> ParsedEmail:
    """Extract the sender, subject, body text, links and attachment names."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    message = message_from_bytes(raw, policy=policy.default)

    sender_name, sender_address = parseaddr(_header(message, "From"))
    _, reply_to = parseaddr(_header(message, "Reply-To"))

    text_parts = []
    links = []
    attachments = _listed_attachments(message)

    # An email can be made of several parts: plain text, HTML, attached files.
    for part in message.walk():
        if part.is_multipart():
            continue  # only a container for other parts
        filename = _filename(part)
        if filename:
            attachments.append(filename)
        elif part.get_content_type() in ("text/plain", "text/html"):
            text = _decode(part)
            if part.get_content_type() == "text/html" or HTML_TAG_PATTERN.search(text):
                text, html_links = _read_html(text)
                links.extend(html_links)
            text_parts.append(text)

    body = "\n".join(text_parts).strip()

    # Add URLs that are written in the text itself and are not HTML links.
    known_urls = {link.url for link in links}
    for url in _urls_in_text(body):
        if url not in known_urls:
            links.append(Link(url))
            known_urls.add(url)

    return ParsedEmail(
        sender_name=sender_name,
        sender_address=sender_address.lower(),
        reply_to=reply_to.lower(),
        subject=_header(message, "Subject"),
        body=body,
        links=links,
        attachments=attachments,
        auth_results=_header(message, "Authentication-Results").lower(),
    )


def _header(message, name: str) -> str:
    """Read a header as text. A malformed header must not crash the scan."""
    try:
        return str(message.get(name, "")).strip()
    except Exception:
        return ""


def _filename(part) -> str:
    """Return the file name of an attached part, or '' if it is not a file."""
    try:
        return part.get_filename() or ""
    except Exception:
        return ""


def _listed_attachments(message) -> list[str]:
    """Read attachment names from an 'Attachments: a.pdf, b.zip' header line.

    A plain text file cannot carry real files, so this simple line lets a
    text-only email still describe what was attached to it.
    """
    names = []
    for header in ("Attachment", "Attachments"):
        for name in _header(message, header).split(","):
            if name.strip():
                names.append(name.strip())
    return names


def _decode(part) -> str:
    """Return the text of one email part, whatever its declared encoding."""
    payload = part.get_payload(decode=True) or b""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:  # the email declares an encoding Python does not know
        return payload.decode("utf-8", errors="replace")


def _urls_in_text(text: str) -> list[str]:
    """Find URLs written in the text, without the punctuation that follows them."""
    return [url.rstrip(".,;:!?") for url in URL_PATTERN.findall(text)]


class _HtmlReader(HTMLParser):
    """Collects the visible text of an HTML body and every <a href> link in it."""

    def __init__(self):
        super().__init__()
        self.text_chunks = []
        self.links = []
        self._href = None  # href of the <a> tag we are inside, if any
        self._link_text = []
        self._hidden_depth = 0  # > 0 while inside <script> or <style>

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._hidden_depth += 1
        elif tag == "a":
            self._href = (dict(attrs).get("href") or "").strip()
            self._link_text = []

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._hidden_depth:
            self._hidden_depth -= 1
        elif tag == "a" and self._href is not None:
            if self._href.lower().startswith(("http://", "https://")):
                text = " ".join("".join(self._link_text).split())
                self.links.append(Link(self._href, text))
            self._href = None

    def handle_data(self, data):
        if self._hidden_depth:
            return
        self.text_chunks.append(data)
        if self._href is not None:
            self._link_text.append(data)


def _read_html(html: str) -> tuple[str, list[Link]]:
    """Return (visible text, links) of an HTML body."""
    reader = _HtmlReader()
    reader.feed(html)
    reader.close()
    text = " ".join(chunk.strip() for chunk in reader.text_chunks if chunk.strip())
    return text, reader.links