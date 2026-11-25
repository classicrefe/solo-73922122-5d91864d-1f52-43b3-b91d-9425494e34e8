"""Shared helpers for engine-level tests."""

from __future__ import annotations

import json
from typing import Any

from app.services import save_rule_set, save_sbom
from app.verifier import verify as engine_verify

RESTRICTED = [
    "GPL-2.0-only",
    "GPL-3.0-only",
    "AGPL-3.0-only",
    "SSPL-1.0",
]


def verify_sbom(
    conn,
    sbom: dict[str, Any],
    *,
    project: str = "test-project",
    rules: list[str] | None = None,
    rule_id: int | None = None,
    sbom_id: int | None = None,
    strict: bool = False,
):
    rules = rules if rules is not None else RESTRICTED
    if sbom_id is None:
        sbom_id = save_sbom(conn, project, sbom)["sbom_id"]
    if rule_id is None:
        rule_id = save_rule_set(conn, rules)["rule_set_id"]

    row = conn.execute(
        "SELECT normalized_json FROM sboms WHERE id = ?", (sbom_id,)
    ).fetchone()
    normalized = json.loads(row["normalized_json"])
    return engine_verify(
        conn,
        project_key=project,
        sbom_id=sbom_id,
        normalized=normalized,
        rule_set_id=rule_id,
        rule_entries=rules,
        strict_unknown=strict,
    )


def continue_verify(conn, sbom_id, normalized, rule_id, rules, project="test-project", strict=False):
    return engine_verify(
        conn,
        project_key=project,
        sbom_id=sbom_id,
        normalized=normalized,
        rule_set_id=rule_id,
        rule_entries=rules,
        strict_unknown=strict,
    )
