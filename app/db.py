"""SQLite connection management and schema.

The database path is read from ``LICENSE_CHECK_DB`` on every connect so tests
can redirect to a temporary file with ``monkeypatch.setenv``.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS projects (
    key          TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sboms (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project_key     TEXT NOT NULL REFERENCES projects(key),
    revision        INTEGER NOT NULL,
    format          TEXT NOT NULL,
    spec_version    TEXT,
    content_hash    TEXT NOT NULL,
    original_content TEXT NOT NULL,
    normalized_json TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    UNIQUE(project_key, revision),
    UNIQUE(project_key, content_hash)
);

CREATE TABLE IF NOT EXISTS rule_sets (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL,
    version_label    TEXT,
    content_hash     TEXT NOT NULL UNIQUE,
    licenses_json    TEXT NOT NULL,
    original_content TEXT,
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS verifications (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    project_key    TEXT NOT NULL,
    sbom_id        INTEGER NOT NULL REFERENCES sboms(id),
    rule_set_id    INTEGER NOT NULL REFERENCES rule_sets(id),
    releasable     INTEGER NOT NULL,
    strict_unknown INTEGER NOT NULL DEFAULT 0,
    report_json    TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

-- Latest per-branch incremental cache for a project lineage.
CREATE TABLE IF NOT EXISTS branch_cache (
    project_key       TEXT NOT NULL,
    branch_key        TEXT NOT NULL,
    signature         TEXT NOT NULL,
    license_keys_json TEXT NOT NULL,
    result_json       TEXT NOT NULL,
    sbom_id           INTEGER NOT NULL,
    rule_set_id       INTEGER NOT NULL,
    strict_unknown    INTEGER NOT NULL DEFAULT 0,
    updated_at        TEXT NOT NULL,
    PRIMARY KEY (project_key, branch_key)
);

-- Immutable published releases. Every row bundles result + exact inputs.
CREATE TABLE IF NOT EXISTS release_versions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project_key     TEXT NOT NULL,
    version_no      INTEGER NOT NULL,
    sbom_id         INTEGER NOT NULL REFERENCES sboms(id),
    rule_set_id     INTEGER NOT NULL REFERENCES rule_sets(id),
    verification_id INTEGER NOT NULL REFERENCES verifications(id),
    sbom_snapshot   TEXT NOT NULL,
    rules_snapshot  TEXT NOT NULL,
    result_snapshot TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    UNIQUE(project_key, version_no)
);

-- Every publish attempt, including policy rejections (operational failures
-- roll the whole transaction back and therefore leave no row).
CREATE TABLE IF NOT EXISTS publish_attempts (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    project_key           TEXT NOT NULL,
    outcome               TEXT NOT NULL,
    requested_sbom_id     INTEGER,
    requested_rule_set_id INTEGER,
    verification_id       INTEGER,
    current_version_no    INTEGER,
    detail                TEXT,
    created_at            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sboms_project ON sboms(project_key, revision);
CREATE INDEX IF NOT EXISTS idx_verifications_project ON verifications(project_key, id);
CREATE INDEX IF NOT EXISTS idx_releases_project ON release_versions(project_key, version_no);
"""


def db_path() -> str:
    return os.environ.get("LICENSE_CHECK_DB", "data/license_check.db")


def connect(path: str | None = None) -> sqlite3.Connection:
    """Open a configured connection. Caller closes the connection."""
    target = path or db_path()
    if target != ":memory:":
        Path(target).parent.mkdir(parents=True, exist_ok=True)
    # isolation_level=None -> explicit BEGIN/COMMIT transaction control.
    # check_same_thread=False is safe because each request gets its own
    # connection and a request's use is sequential (though AnyIO may migrate
    # sync dependency/endpoint steps between worker threads).
    conn = sqlite3.connect(
        target,
        isolation_level=None,
        timeout=30,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Explicit transaction that rolls back on any exception."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")
