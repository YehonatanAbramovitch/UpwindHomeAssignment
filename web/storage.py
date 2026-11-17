"""Saves scans and reads the scan history.

The same code works with SQLite on a laptop and with PostgreSQL on AWS (RDS).
Only the connection string changes, and it comes from the DATABASE_URL
environment variable, so the database password is never written in the code.

This is the only file that talks to the database. 
Both the web app and `cli.py --history` use it.
"""

import json
import logging
import os
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional, Union

from sqlalchemy import (
    Column, DateTime, Integer, MetaData, String, Table, Text, create_engine, select,
)
from sqlalchemy.exc import SQLAlchemyError

from detector import config
from detector.analyzer import analyze
from detector.checks.history import domains_to_remember, sender_to_remember
from detector.models import ScanResult
from detector.parser import parse_email

log = logging.getLogger(__name__)

# Without DATABASE_URL, a local SQLite file in the current folder is used.
DEFAULT_DATABASE_URL = "sqlite:///history.db"

# How long to wait for the database before giving up, so a page never hangs
# while the database is down.
CONNECT_TIMEOUT_SECONDS = 3

metadata = MetaData()

# One row per scan. The email body is not stored: an email can hold personal
# details, and what is not stored cannot leak.
scans = Table(
    "scans",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("scanned_at", DateTime(timezone=True), nullable=False),
    Column("sender", String(500)),
    Column("subject", String(500)),
    Column("score", Integer, nullable=False),
    Column("verdict", String(50), nullable=False),
    Column("findings", Text),  # the findings as JSON, for showing them later
    # Filled only for a scan that scored PHISHING_THRESHOLD or more. The
    # history check of later scans reads these two columns.
    Column("remembered_sender", String(320)),
    Column("remembered_domains", Text),  # comma separated
)


class HistoryUnavailable(Exception):
    """The database cannot be reached. The scan itself can still run without it."""


class Storage:
    def __init__(self, database_url: Optional[str] = None):
        url = database_url or os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL)
        connect_args = {}
        if url.startswith("postgresql"):
            connect_args["connect_timeout"] = CONNECT_TIMEOUT_SECONDS
        # pool_pre_ping checks a connection before using it, 
        # so a database that restarted does not leave the app holding broken connections.
        self.engine = create_engine(url, pool_pre_ping=True, connect_args=connect_args)
        self._table_ready = False

    def scan(self, raw: Union[bytes, str]) -> ScanResult:
        """Scan an email with the history checks, and save the scan.

        Raises HistoryUnavailable if the database is down. 
        The caller then scans without history (detector.analyzer.analyze) and shows a warning.
        """
        flagged_senders, flagged_domains = self.flagged()
        result = analyze(raw, frozenset(flagged_senders), frozenset(flagged_domains))
        self.save(result, raw)
        return result

    def flagged(self) -> tuple[set[str], set[str]]:
        """The senders and link domains remembered from earlier phishing scans."""
        query = select(scans.c.remembered_sender, scans.c.remembered_domains).where(
            (scans.c.remembered_sender.is_not(None)) | (scans.c.remembered_domains.is_not(None))
        )
        senders, domains = set(), set()
        for sender, domain_list in self._run(lambda connection: connection.execute(query).all()):
            if sender:
                senders.add(sender)
            if domain_list:
                domains.update(domain_list.split(","))
        return senders, domains

    def save(self, result: ScanResult, raw: Union[bytes, str]) -> None:
        """Save one scan. What to remember is filled only for a phishing verdict."""
        remembered_sender, remembered_domains = None, None
        if result.score >= config.PHISHING_THRESHOLD:
            email = parse_email(raw)
            remembered_sender = sender_to_remember(email)
            remembered_domains = ",".join(sorted(domains_to_remember(email))) or None

        row = {
            "scanned_at": datetime.now(timezone.utc),
            "sender": result.sender[:500],
            "subject": result.subject[:500],
            "score": result.score,
            "verdict": result.verdict,
            "findings": json.dumps([asdict(finding) for finding in result.findings]),
            "remembered_sender": remembered_sender,
            "remembered_domains": remembered_domains,
        }
        self._run(lambda connection: connection.execute(scans.insert().values(**row)), write=True)

    def recent(self, limit: int = 100) -> list[dict]:
        """The latest scans, newest first, for the history page."""
        query = (
            select(scans.c.scanned_at, scans.c.sender, scans.c.subject, scans.c.score, scans.c.verdict)
            .order_by(scans.c.id.desc())
            .limit(limit)
        )
        rows = self._run(lambda connection: connection.execute(query).mappings().all())
        return [dict(row) for row in rows]

    def _run(self, action, write: bool = False):
        """Run one database action. Any database error becomes HistoryUnavailable."""
        try:
            self._create_table_once()
            if write:
                with self.engine.begin() as connection:  # commits at the end
                    return action(connection)
            with self.engine.connect() as connection:
                return action(connection)
        except SQLAlchemyError as error:
            log.error("Database unavailable: %s", error.__class__.__name__)
            raise HistoryUnavailable() from error

    def _create_table_once(self) -> None:
        """Create the table the first time it is needed, if it does not exist yet."""
        if not self._table_ready:
            metadata.create_all(self.engine, checkfirst=True)
            self._table_ready = True
