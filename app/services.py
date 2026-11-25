"""Application services: import, verification, versioned publish/rollback."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import Any

from .cyclonedx import ParsedSBOM, parse_sbom
from .db import transaction
from .spdx import parse_rule_list
from .verifier import verify


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


class PolicyRejected(Exception):
    """New verification is not releasable; previous release stays current."""

    def __init__(self, report: dict[str, Any], current_version_no: int | None):
        self.report = report
        self.current_version_no = current_version_no
        super().__init__("Verification blocked publication")


class SimulatedPublishFailure(Exception):
    """Raised by the rollback demonstration switch inside the publish tx."""


class NotFound(LookupError):
    pass


class ConflictState(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Projects / import
# ---------------------------------------------------------------------------


def ensure_project(
    conn: sqlite3.Connection, project_key: str, display_name: str | None = None
) -> None:
    conn.execute(
        """
        INSERT INTO projects(key, display_name, created_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO NOTHING
        """,
        (project_key, display_name or project_key, now_iso()),
    )


def save_sbom(
    conn: sqlite3.Connection,
    project_key: str,
    content: bytes | str | dict[str, Any],
) -> dict[str, Any]:
    """Parse and store an SBOM. Identical content is idempotent."""
    if isinstance(content, dict):
        text = json.dumps(content, ensure_ascii=False)
    elif isinstance(content, bytes):
        text = content.decode("utf-8-sig", errors="replace")
    else:
        text = content

    parsed: ParsedSBOM = parse_sbom(text)
    normalized = parsed.normalized
    content_hash = parsed.content_hash

    with transaction(conn):
        ensure_project(conn, project_key)
        existing = conn.execute(
            "SELECT id, revision FROM sboms WHERE project_key = ? AND content_hash = ?",
            (project_key, content_hash),
        ).fetchone()
        if existing:
            return {
                "sbom_id": existing["id"],
                "revision": existing["revision"],
                "deduplicated": True,
                "component_count": len(normalized["components"]),
                "root_count": len(normalized["roots"]),
                "warnings": normalized["warnings"],
            }

        row = conn.execute(
            "SELECT COALESCE(MAX(revision), 0) + 1 AS next_rev FROM sboms WHERE project_key = ?",
            (project_key,),
        ).fetchone()
        revision = row["next_rev"]
        cursor = conn.execute(
            """
            INSERT INTO sboms (
                project_key, revision, format, spec_version, content_hash,
                original_content, normalized_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                project_key,
                revision,
                normalized["format"],
                normalized.get("spec_version"),
                content_hash,
                parsed.original_text,
                json.dumps(normalized, ensure_ascii=False),
                now_iso(),
            ),
        )
        sbom_id = cursor.lastrowid

    return {
        "sbom_id": sbom_id,
        "revision": revision,
        "deduplicated": False,
        "format": normalized["format"],
        "spec_version": normalized.get("spec_version"),
        "component_count": len(normalized["components"]),
        "root_count": len(normalized["roots"]),
        "warnings": normalized["warnings"],
    }


def save_rule_set(
    conn: sqlite3.Connection,
    content: bytes | str | list[str] | dict[str, Any],
    *,
    name: str = "restricted-spdx",
    version_label: str | None = None,
    content_type: str = "",
) -> dict[str, Any]:
    if isinstance(content, (list, dict)):
        entries = parse_rule_list(json.dumps(content), "application/json")
        original_text = json.dumps(content, ensure_ascii=False, indent=2)
    else:
        if isinstance(content, bytes):
            original_text = content.decode("utf-8-sig", errors="replace")
        else:
            original_text = content
        entries = parse_rule_list(original_text, content_type)

    from .cyclonedx import canonical_hash

    content_hash = canonical_hash(entries)

    with transaction(conn):
        existing = conn.execute(
            "SELECT id FROM rule_sets WHERE content_hash = ?", (content_hash,)
        ).fetchone()
        if existing:
            return {
                "rule_set_id": existing["id"],
                "deduplicated": True,
                "license_count": len(entries),
                "licenses": entries,
            }
        cursor = conn.execute(
            """
            INSERT INTO rule_sets (
                name, version_label, content_hash, licenses_json,
                original_content, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                version_label,
                content_hash,
                json.dumps(entries),
                original_text,
                now_iso(),
            ),
        )
        rule_set_id = cursor.lastrowid

    return {
        "rule_set_id": rule_set_id,
        "deduplicated": False,
        "license_count": len(entries),
        "licenses": entries,
    }


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def _resolve_sbom(
    conn: sqlite3.Connection,
    project_key: str,
    sbom_id: int | None,
    inline_sbom: dict[str, Any] | str | None,
) -> sqlite3.Row:
    if inline_sbom is not None:
        saved = save_sbom(conn, project_key, inline_sbom)
        sbom_id = saved["sbom_id"]
    if sbom_id is not None:
        row = conn.execute("SELECT * FROM sboms WHERE id = ?", (sbom_id,)).fetchone()
        if row is None:
            raise NotFound(f"sbom_id {sbom_id} not found")
        return row
    row = conn.execute(
        "SELECT * FROM sboms WHERE project_key = ? ORDER BY revision DESC LIMIT 1",
        (project_key,),
    ).fetchone()
    if row is None:
        raise NotFound(
            f"no SBOM imported for project {project_key!r}; import one first"
        )
    return row


def _resolve_rules(
    conn: sqlite3.Connection,
    rule_set_id: int | None,
    inline_licenses: list[str] | None,
    rule_name: str | None,
    rule_version: str | None,
) -> sqlite3.Row:
    if inline_licenses is not None:
        saved = save_rule_set(
            conn,
            inline_licenses,
            name=rule_name or "inline-restricted-spdx",
            version_label=rule_version,
        )
        rule_set_id = saved["rule_set_id"]
    if rule_set_id is not None:
        row = conn.execute(
            "SELECT * FROM rule_sets WHERE id = ?", (rule_set_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"rule_set_id {rule_set_id} not found")
        return row
    row = conn.execute(
        "SELECT * FROM rule_sets ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if row is None:
        raise NotFound("no restricted license rule set imported; import one first")
    return row


def _prepare(
    conn: sqlite3.Connection,
    req: Any,
) -> tuple[sqlite3.Row, sqlite3.Row, bool]:
    """Resolve inputs, persisting inline payloads. Returns (sbom, rules, strict)."""
    project_key = getattr(req, "project_key", "default") or "default"
    ensure_project(conn, project_key)
    sbom_row = _resolve_sbom(
        conn, project_key, getattr(req, "sbom_id", None), getattr(req, "sbom", None)
    )
    rules_row = _resolve_rules(
        conn,
        getattr(req, "rule_set_id", None),
        getattr(req, "licenses", None),
        getattr(req, "rule_name", None),
        getattr(req, "rule_version", None),
    )
    strict = bool(getattr(req, "strict_unknown", False))
    return sbom_row, rules_row, strict


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def create_verification(conn: sqlite3.Connection, req: Any) -> dict[str, Any]:
    project_key = getattr(req, "project_key", "default") or "default"
    sbom_row, rules_row, strict = _prepare(conn, req)
    normalized = json.loads(sbom_row["normalized_json"])
    entries = json.loads(rules_row["licenses_json"])

    with transaction(conn):
        report = verify(
            conn,
            project_key=project_key,
            sbom_id=sbom_row["id"],
            normalized=normalized,
            rule_set_id=rules_row["id"],
            rule_entries=entries,
            strict_unknown=strict,
        )
        cursor = conn.execute(
            """
            INSERT INTO verifications (
                project_key, sbom_id, rule_set_id, releasable,
                strict_unknown, report_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                project_key,
                sbom_row["id"],
                rules_row["id"],
                1 if report["releasable"] else 0,
                1 if strict else 0,
                json.dumps(report, ensure_ascii=False),
                now_iso(),
            ),
        )
        verification_id = cursor.lastrowid
    report["verification_id"] = verification_id
    return report


# ---------------------------------------------------------------------------
# Publish / rollback
# ---------------------------------------------------------------------------


def current_version_no(conn: sqlite3.Connection, project_key: str) -> int | None:
    row = conn.execute(
        "SELECT MAX(version_no) AS v FROM release_versions WHERE project_key = ?",
        (project_key,),
    ).fetchone()
    return row["v"] if row and row["v"] is not None else None


def publish_release(conn: sqlite3.Connection, req: Any) -> dict[str, Any]:
    project_key = getattr(req, "project_key", "default") or "default"
    sbom_row, rules_row, strict = _prepare(conn, req)
    normalized = json.loads(sbom_row["normalized_json"])
    entries = json.loads(rules_row["licenses_json"])
    simulate_failure = bool(getattr(req, "simulate_failure", False))

    with transaction(conn):
        report = verify(
            conn,
            project_key=project_key,
            sbom_id=sbom_row["id"],
            normalized=normalized,
            rule_set_id=rules_row["id"],
            rule_entries=entries,
            strict_unknown=strict,
        )
        verifier_cursor = conn.execute(
            """
            INSERT INTO verifications (
                project_key, sbom_id, rule_set_id, releasable,
                strict_unknown, report_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                project_key,
                sbom_row["id"],
                rules_row["id"],
                1 if report["releasable"] else 0,
                1 if strict else 0,
                json.dumps(report, ensure_ascii=False),
                now_iso(),
            ),
        )
        verification_id = verifier_cursor.lastrowid
        report["verification_id"] = verification_id

        if simulate_failure:
            # Everything done above is discarded by the transaction context.
            raise SimulatedPublishFailure(
                "simulated crash while publishing; transaction rolled back"
            )

        previous_version = current_version_no(conn, project_key)

        if not report["releasable"]:
            conn.execute(
                """
                INSERT INTO publish_attempts (
                    project_key, outcome, requested_sbom_id,
                    requested_rule_set_id, verification_id,
                    current_version_no, detail, created_at
                ) VALUES (?, 'policy_rejected', ?, ?, ?, ?, ?, ?)
                """,
                (
                    project_key,
                    sbom_row["id"],
                    rules_row["id"],
                    verification_id,
                    previous_version,
                    f"{report['summary']['violation_component_count']} violating "
                    "component(s)",
                    now_iso(),
                ),
            )
            rejected = True
        else:
            next_version = (previous_version or 0) + 1
            rules_snapshot = json.dumps(
                {
                    "rule_set_id": rules_row["id"],
                    "name": rules_row["name"],
                    "version_label": rules_row["version_label"],
                    "licenses": entries,
                },
                ensure_ascii=False,
            )
            conn.execute(
                """
                INSERT INTO release_versions (
                    project_key, version_no, sbom_id, rule_set_id,
                    verification_id, sbom_snapshot, rules_snapshot,
                    result_snapshot, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    project_key,
                    next_version,
                    sbom_row["id"],
                    rules_row["id"],
                    verification_id,
                    sbom_row["original_content"],
                    rules_snapshot,
                    json.dumps(report, ensure_ascii=False),
                    now_iso(),
                ),
            )
            conn.execute(
                """
                INSERT INTO publish_attempts (
                    project_key, outcome, requested_sbom_id,
                    requested_rule_set_id, verification_id,
                    current_version_no, detail, created_at
                ) VALUES (?, 'published', ?, ?, ?, ?, ?, ?)
                """,
                (
                    project_key,
                    sbom_row["id"],
                    rules_row["id"],
                    verification_id,
                    next_version,
                    f"published as version {next_version}",
                    now_iso(),
                ),
            )
            rejected = False

    if rejected:
        # Re-read current after commit for an accurate pointer.
        raise PolicyRejected(report, current_version_no(conn, project_key))

    bundle = get_release_bundle(conn, project_key, version_no=None)
    assert bundle is not None
    return bundle


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


def _bundle_from_row(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    sbom = conn.execute(
        "SELECT * FROM sboms WHERE id = ?", (row["sbom_id"],)
    ).fetchone()

    try:
        sbom_input: Any = json.loads(row["sbom_snapshot"])
    except (json.JSONDecodeError, TypeError):
        sbom_input = {"raw": row["sbom_snapshot"]}

    return {
        "release_id": row["id"],
        "project_key": row["project_key"],
        "version_no": row["version_no"],
        "published_at": row["created_at"],
        "input": {
            "sbom_id": row["sbom_id"],
            "sbom_revision": sbom["revision"] if sbom else None,
            "sbom": sbom_input,
            "rule_set_id": row["rule_set_id"],
            "rules": json.loads(row["rules_snapshot"]),
        },
        "verification": json.loads(row["result_snapshot"]),
    }


def get_release_bundle(
    conn: sqlite3.Connection, project_key: str, version_no: int | None
) -> dict[str, Any] | None:
    if version_no is None or version_no == 0:
        row = conn.execute(
            """
            SELECT * FROM release_versions
             WHERE project_key = ?
             ORDER BY version_no DESC LIMIT 1
            """,
            (project_key,),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM release_versions WHERE project_key = ? AND version_no = ?",
            (project_key, version_no),
        ).fetchone()
    if row is None:
        return None
    return _bundle_from_row(conn, row)


def list_release_versions(
    conn: sqlite3.Connection, project_key: str
) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT id, version_no, sbom_id, rule_set_id, verification_id, created_at
          FROM release_versions WHERE project_key = ?
         ORDER BY version_no DESC
        """,
        (project_key,),
    ).fetchall()
    return [dict(r) for r in rows]


def list_attempts(conn: sqlite3.Connection, project_key: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT id, outcome, requested_sbom_id, requested_rule_set_id,
               verification_id, current_version_no, detail, created_at
          FROM publish_attempts WHERE project_key = ?
         ORDER BY id DESC LIMIT 50
        """,
        (project_key,),
    ).fetchall()
    return [dict(r) for r in rows]


def reset_project(conn: sqlite3.Connection, project_key: str) -> None:
    """Delete all data of one demo project (used by one-click demos)."""
    with transaction(conn):
        for table, column in (
            ("release_versions", "project_key"),
            ("publish_attempts", "project_key"),
            ("verifications", "project_key"),
            ("branch_cache", "project_key"),
            ("sboms", "project_key"),
            ("projects", "key"),
        ):
            col = "key" if table == "projects" else column
            conn.execute(f"DELETE FROM {table} WHERE {col} = ?", (project_key,))
