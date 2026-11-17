"""The web app: upload or paste an email, see the result, see the history.

Run locally:
    python -m flask --app web.app run
"""

import logging
import socket
from typing import Optional

from flask import Flask, render_template, request

from detector import config
from detector.analyzer import analyze
from detector.models import printable
from detector.scoring import LIKELY_LEGITIMATE, LIKELY_PHISHING, SUSPICIOUS
from web.storage import HistoryUnavailable, Storage

MAX_UPLOAD_MB = 35  # Gmail allows 25 MB of attachments, about 34 MB inside the email
ALLOWED_EXTENSIONS = (".eml", ".txt")
BODY_SHOWN_CHARACTERS = 20_000  # a huge email is cut on the page, but scanned in full

# The colour of each verdict on the page.
VERDICT_COLOURS = {LIKELY_LEGITIMATE: "green", SUSPICIOUS: "orange", LIKELY_PHISHING: "red"}

HISTORY_WARNING = (
    "History is unavailable right now. The scan ran without the history checks "
    "and was not saved."
)

log = logging.getLogger(__name__)


def create_app(database_url: Optional[str] = None) -> Flask:
    """Build the app. Tests pass their own database_url; otherwise DATABASE_URL is used."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    app = Flask(__name__)
    # Flask rejects a bigger request before reading it, so a huge upload cannot
    # fill the memory of the server.
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
    storage = Storage(database_url)
    served_by = socket.gethostname()

    # Every value from an email goes through printable() before it is shown.
    # Jinja escapes HTML on top of that, so "<script>" in an email is shown as
    # text and never runs, and links are plain text that cannot be clicked.
    app.jinja_env.filters["printable"] = printable

    @app.context_processor
    def page_values():
        return {"served_by": served_by, "max_upload_mb": MAX_UPLOAD_MB}

    @app.get("/")
    def scan_page():
        return render_template("scan.html")

    @app.post("/scan")
    def scan():
        raw, error = _read_email()
        if error:
            return render_template("scan.html", error=error), 400

        warning = None
        try:
            result = storage.scan(raw)
        except HistoryUnavailable:
            # The detector does not need the database: scan without history.
            result = analyze(raw)
            warning = HISTORY_WARNING

        log.info("scan score=%s verdict=%s findings=%d", result.score, result.verdict, len(result.findings))
        return render_template(
            "scan.html",
            result=result,
            warning=warning,
            colour=VERDICT_COLOURS[result.verdict],
            body=result.body[:BODY_SHOWN_CHARACTERS],
            body_cut=len(result.body) > BODY_SHOWN_CHARACTERS,
            points_detected=sum(finding.points for finding in result.findings),
            max_score=config.MAX_SCORE,
        )

    @app.get("/history")
    def history():
        try:
            rows = storage.recent()
        except HistoryUnavailable:
            return render_template("history.html", unavailable=True), 503
        return render_template("history.html", rows=rows, colours=VERDICT_COLOURS)

    @app.get("/health")
    def health():
        # Checks only that this server answers. It does not check the database
        # on purpose: if it did, a database outage would mark both servers as
        # unhealthy, and the load balancer would stop sending anyone to them.
        return "OK", 200

    @app.errorhandler(413)
    def too_large(_error):
        error = f"The file is too large (limit: {MAX_UPLOAD_MB} MB)."
        return render_template("scan.html", error=error), 413

    return app


def _read_email() -> tuple[bytes, Optional[str]]:
    """The email from the uploaded file or the paste box, or an error message."""
    upload = request.files.get("email_file")
    if upload and upload.filename:
        if not upload.filename.lower().endswith(ALLOWED_EXTENSIONS):
            return b"", "Please upload a .eml or .txt file."
        raw = upload.read()
    else:
        raw = request.form.get("email_text", "").encode("utf-8")

    if not raw.strip():
        return b"", "Please choose a file or paste the email content."
    return raw, None
