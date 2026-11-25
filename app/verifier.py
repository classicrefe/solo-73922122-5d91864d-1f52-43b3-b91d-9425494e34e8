"""Verification engine: restriction checks, shortest paths, incremental cache.

Coverage
--------
* Every component in the CycloneDX document is checked (an unreachable but
  listed component must not be silently ignored): reachable violations get a
  shortest root-to-node path; unreachable ones get ``path = null`` with
  ``reachable = false``.

Incremental unit
----------------
The reachable graph is split into *branches* (one per direct child arc of the
root plus the root-self branch).  Each branch stores a content signature of
every component and edge reachable inside it (cycles safe).  Unreachable
components are cached as individual ``__orphan__::<ref>`` units.

On revision:

* identical signature + unaffected rules  -> cached unit result is reused;
* changed signature                        -> only that unit recomputes;
* rule revision                            -> only units containing a license
  whose restricted status flipped recompute.

The final report merges branch candidates and keeps exactly one globally
shortest path per violating bom-ref.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Callable
from datetime import UTC
from typing import Any

from .cyclonedx import canonical_hash
from .graph import Graph, diff_normalized
from .spdx import (
    RestrictionRules,
    evaluate_expression,
    flipped_match_keys,
    name_match_key,
    spdx_match_keys,
)

POLICY_UNRESOLVED_KEY = "policy:unresolved-license"
ORPHAN_PREFIX = "__orphan__::"


def orphan_key(ref: str) -> str:
    return f"{ORPHAN_PREFIX}{ref}"


# ---------------------------------------------------------------------------
# License evaluation
# ---------------------------------------------------------------------------


def _claim_display(claim: dict[str, str]) -> str:
    if claim["kind"] == "expression":
        return claim["value"]
    return claim["value"]


def collect_license_keys(comp: dict[str, Any], rules: RestrictionRules) -> list[str]:
    """Match keys that can affect evaluation of one component."""
    keys: set[str] = set()
    verdict = evaluate_component_licenses(comp, rules)
    if verdict["unresolved_licenses"]:
        keys.add(POLICY_UNRESOLVED_KEY)
    for claim in comp.get("licenses", []):
        kind = claim.get("kind")
        value = claim.get("value", "")
        if kind == "id":
            keys.update(spdx_match_keys(value))
        elif kind == "name":
            keys.add(name_match_key(value))
        elif kind == "expression":
            from .spdx import _tokenize  # internal tokenizer

            for token in _tokenize(value):
                if token in {"(", ")", "AND", "OR", "WITH"}:
                    continue
                keys.update(spdx_match_keys(token))
    return sorted(keys)


def evaluate_component_licenses(
    comp: dict[str, Any], rules: RestrictionRules
) -> dict[str, Any]:
    """Return violation license details and unresolved claims for a component."""
    bad: list[dict[str, Any]] = []
    unresolved: list[str] = []
    restricted_options: list[dict[str, Any]] = []

    for claim in comp.get("licenses", []):
        kind = claim.get("kind")
        value = claim.get("value", "")
        if kind == "id":
            matched = rules.match_spdx(value)
            if matched:
                bad.append(
                    {
                        "license": value,
                        "via": "spdx-id",
                        "matched_rule_ids": matched,
                    }
                )
        elif kind == "name":
            matched = rules.match_name(value)
            if matched:
                bad.append(
                    {
                        "license": value,
                        "via": "license-name",
                        "matched_rule_ids": matched,
                    }
                )
            else:
                unresolved.append(value)
        elif kind == "expression":
            verdict = evaluate_expression(value, rules)
            if verdict.parse_error:
                unresolved.append(
                    f"unparseable SPDX expression {value!r}: {verdict.parse_error}"
                )
            if verdict.violates:
                for item in verdict.bad_licenses:
                    bad.append(
                        {
                            "license": item["license"],
                            "via": "spdx-expression",
                            "exception": item.get("exception"),
                            "matched_rule_ids": item["matched_rule_ids"],
                            "expression": value,
                        }
                    )
            else:
                for item in verdict.mentioned_licenses:
                    restricted_options.append(
                        {
                            "expression": value,
                            "license": item["license"],
                            "note": "restricted alternative under OR; choice allowed",
                        }
                    )

    deduped: dict[tuple[str, str | None], dict[str, Any]] = {}
    for item in bad:
        key = (item["license"], item.get("expression"))
        deduped.setdefault(key, item)
    bad = list(deduped.values())

    violating_ids = sorted({item["license"] for item in bad})
    return {
        "violates": bool(bad),
        "license_details": bad,
        "violating_license_ids": violating_ids,
        "unresolved_licenses": sorted(set(unresolved)),
        "restricted_options": restricted_options,
        "declared_licenses": [_claim_display(c) for c in comp.get("licenses", [])],
    }


# ---------------------------------------------------------------------------
# Branch / orphan computation
# ---------------------------------------------------------------------------


def _component_brief(ref: str, comp: dict[str, Any] | None) -> dict[str, Any]:
    if not comp:
        return {"bom_ref": ref, "name": ref, "version": None, "missing": True}
    return {
        "bom_ref": ref,
        "name": comp.get("name", ref),
        "version": comp.get("version"),
        "purl": comp.get("purl"),
        "missing": bool(comp.get("missing")),
    }


def compute_branch_result(
    graph: Graph,
    branch: dict[str, str | None],
    rules: RestrictionRules,
) -> dict[str, Any]:
    key = branch["branch_key"]
    kind = branch["kind"]
    root_ref = branch["root_ref"]
    child_ref = branch["child_ref"]

    violations: list[dict[str, Any]] = []
    unresolved_entries: list[dict[str, Any]] = []

    if kind == "self":
        targets: dict[str, list[str]] = {root_ref: [root_ref]}
    else:
        assert child_ref is not None
        targets = graph.branch_paths(root_ref, child_ref)

    for ref in sorted(targets):
        comp = graph.nodes.get(ref)
        if comp is None:
            continue
        verdict = evaluate_component_licenses(comp, rules)
        if verdict["unresolved_licenses"]:
            unresolved_entries.append(
                {"bom_ref": ref, "licenses": verdict["unresolved_licenses"]}
            )
        if not verdict["violates"]:
            continue
        violations.append(
            {
                "ref": ref,
                "name": comp.get("name", ref),
                "version": comp.get("version"),
                "purl": comp.get("purl"),
                "relative_path": targets[ref],
                "declared_licenses": verdict["declared_licenses"],
                "violating_licenses": verdict["violating_license_ids"],
                "license_details": verdict["license_details"],
            }
        )

    return {
        "unit_kind": "branch",
        "branch_key": key,
        "kind": kind,
        "root_ref": root_ref,
        "child_ref": child_ref,
        "violations": violations,
        "unresolved": unresolved_entries,
    }


def compute_orphan_result(
    graph: Graph, ref: str, rules: RestrictionRules
) -> dict[str, Any]:
    comp = graph.nodes[ref]
    verdict = evaluate_component_licenses(comp, rules)
    violation = None
    if verdict["violates"]:
        violation = {
            "ref": ref,
            "name": comp.get("name", ref),
            "version": comp.get("version"),
            "purl": comp.get("purl"),
            "declared_licenses": verdict["declared_licenses"],
            "violating_licenses": verdict["violating_license_ids"],
            "license_details": verdict["license_details"],
        }
    return {
        "unit_kind": "orphan",
        "branch_key": orphan_key(ref),
        "ref": ref,
        "violations": [violation] if violation else [],
        "unresolved": [
            {"bom_ref": ref, "licenses": verdict["unresolved_licenses"]}
        ]
        if verdict["unresolved_licenses"]
        else [],
    }


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------


def _now() -> str:
    from datetime import datetime

    return datetime.now(UTC).isoformat()


def _load_rules_for(conn: sqlite3.Connection, rule_set_id: int) -> RestrictionRules:
    row = conn.execute(
        "SELECT licenses_json FROM rule_sets WHERE id = ?", (rule_set_id,)
    ).fetchone()
    if row is None:
        return RestrictionRules.compile([])
    return RestrictionRules.compile(json.loads(row["licenses_json"]))


def _upsert_cache(
    conn: sqlite3.Connection,
    project_key: str,
    unit_key: str,
    signature: str,
    license_keys: list[str],
    result: dict[str, Any],
    sbom_id: int,
    rule_set_id: int,
    strict_unknown: bool,
) -> None:
    conn.execute(
        """
        INSERT INTO branch_cache (
            project_key, branch_key, signature, license_keys_json,
            result_json, sbom_id, rule_set_id, strict_unknown, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(project_key, branch_key) DO UPDATE SET
            signature = excluded.signature,
            license_keys_json = excluded.license_keys_json,
            result_json = excluded.result_json,
            sbom_id = excluded.sbom_id,
            rule_set_id = excluded.rule_set_id,
            strict_unknown = excluded.strict_unknown,
            updated_at = excluded.updated_at
        """,
        (
            project_key,
            unit_key,
            signature,
            json.dumps(license_keys),
            json.dumps(result, ensure_ascii=False),
            sbom_id,
            rule_set_id,
            1 if strict_unknown else 0,
            _now(),
        ),
    )


def _impacted_refs(
    conn: sqlite3.Connection,
    old_row: sqlite3.Row,
    new_normalized: dict[str, Any],
    graph: Graph,
    branch: dict[str, str | None],
) -> list[str]:
    """Explain which SBOM touched refs drive a branch recomputation."""
    try:
        old_sbom = conn.execute(
            "SELECT normalized_json FROM sboms WHERE id = ?",
            (old_row["sbom_id"],),
        ).fetchone()
        if old_sbom is None:
            return []
        old_normalized = json.loads(old_sbom["normalized_json"])
        delta = diff_normalized(old_normalized, new_normalized)
        touched = set(delta["touched_refs"])
        if not touched:
            return []

        if branch["kind"] == "arc":
            new_closure = graph.branch_closure(
                branch["root_ref"], branch["child_ref"]  # type: ignore[arg-type]
            )
        else:
            new_closure = {branch["root_ref"]}

        old_graph = Graph.from_normalized(old_normalized)
        old_result = json.loads(old_row["result_json"])
        old_closure: set[str] = set()
        if old_result.get("kind") == "arc" and old_result.get("child_ref"):
            old_closure = old_graph.branch_closure(
                old_result["root_ref"], old_result["child_ref"]
            )
        elif old_result.get("root_ref"):
            old_closure = {old_result["root_ref"]}

        return sorted(touched & (new_closure | old_closure))
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------


def verify(
    conn: sqlite3.Connection,
    *,
    project_key: str,
    sbom_id: int,
    normalized: dict[str, Any],
    rule_set_id: int,
    rule_entries: list[str],
    strict_unknown: bool = False,
) -> dict[str, Any]:
    started = time.perf_counter()
    rules = RestrictionRules.compile(rule_entries)
    graph = Graph.from_normalized(normalized)

    old_rows = {
        row["branch_key"]: row
        for row in conn.execute(
            "SELECT * FROM branch_cache WHERE project_key = ?", (project_key,)
        ).fetchall()
    }

    branches = graph.branches()
    closures: dict[str, set[str]] = {}
    covered: set[str] = set()
    for branch in branches:
        if branch["kind"] == "self":
            closure = {branch["root_ref"]}
        else:
            closure = graph.branch_closure(
                branch["root_ref"], branch["child_ref"]  # type: ignore[arg-type]
            )
        closures[branch["branch_key"]] = closure
        covered |= closure

    orphan_refs = sorted(set(graph.nodes) - covered)

    recomputed: list[dict[str, Any]] = []
    reused: list[dict[str, Any]] = []
    branch_results: list[dict[str, Any]] = []
    orphan_results: list[dict[str, Any]] = []

    def resolve_unit(
        unit_key: str,
        signature: str,
        license_keys: list[str],
        compute_fn: Callable[[], dict[str, Any]],
        *,
        branch_for_impact: dict[str, str | None] | None = None,
    ) -> dict[str, Any]:
        old = old_rows.get(unit_key)
        if old is None:
            result = compute_fn()
            recomputed.append(
                {"branch_key": unit_key, "reason": "cold_cache",
                 "impacted_by_refs": []}
            )
            _upsert_cache(
                conn, project_key, unit_key, signature, license_keys, result,
                sbom_id, rule_set_id, strict_unknown,
            )
            return result

        if old["signature"] != signature:
            impacted: list[str] = []
            if branch_for_impact is not None:
                impacted = _impacted_refs(
                    conn, old, normalized, graph, branch_for_impact
                )
            result = compute_fn()
            recomputed.append(
                {
                    "branch_key": unit_key,
                    "reason": "sbom_revision_affected_branch",
                    "impacted_by_refs": impacted,
                }
            )
            _upsert_cache(
                conn, project_key, unit_key, signature, license_keys, result,
                sbom_id, rule_set_id, strict_unknown,
            )
            return result

        old_strict = bool(old["strict_unknown"])
        old_rule_id = old["rule_set_id"]
        old_keys = set(json.loads(old["license_keys_json"]))

        rule_recompute = False
        if old_rule_id != rule_set_id:
            old_rules = _load_rules_for(conn, old_rule_id)
            flipped = flipped_match_keys(old_rules, rules)
            if old_keys & flipped:
                rule_recompute = True

        strict_recompute = (
            old_strict != strict_unknown
            and POLICY_UNRESOLVED_KEY in old_keys
        )

        if rule_recompute or strict_recompute:
            result = compute_fn()
            reused_reason = (
                "rules_revision_affects_branch"
                if rule_recompute
                else "strict_unknown_policy_changed"
            )
            recomputed.append(
                {"branch_key": unit_key, "reason": reused_reason,
                 "impacted_by_refs": []}
            )
            _upsert_cache(
                conn, project_key, unit_key, signature, license_keys, result,
                sbom_id, rule_set_id, strict_unknown,
            )
            return result

        result = json.loads(old["result_json"])
        reused.append(
            {
                "branch_key": unit_key,
                "reason": "cache_hit"
                if old_rule_id == rule_set_id and old_strict == strict_unknown
                else "unaffected_by_rules_or_policy_revision",
            }
        )
        conn.execute(
            """
            UPDATE branch_cache
               SET sbom_id = ?, rule_set_id = ?, strict_unknown = ?,
                   signature = ?, license_keys_json = ?, updated_at = ?
             WHERE project_key = ? AND branch_key = ?
            """,
            (
                sbom_id, rule_set_id, 1 if strict_unknown else 0,
                signature, json.dumps(license_keys), _now(),
                project_key, unit_key,
            ),
        )
        return result

    # Reachable branches.
    for branch in branches:
        key = branch["branch_key"]
        closure = closures[key]
        signature = graph.branch_signature(closure)
        # Union component keys across the closure; evaluate each comp once.
        keys: set[str] = set()
        for ref in closure:
            comp = graph.nodes.get(ref)
            if comp:
                keys.update(collect_license_keys(comp, rules))
        result = resolve_unit(
            key,
            signature,
            sorted(keys),
            lambda b=branch: compute_branch_result(graph, b, rules),
            branch_for_impact=branch,
        )
        branch_results.append(result)

    # Unreachable listed components.
    for ref in orphan_refs:
        comp = graph.nodes[ref]
        signature = canonical_hash(comp)
        result = resolve_unit(
            orphan_key(ref),
            signature,
            collect_license_keys(comp, rules),
            lambda r=ref: compute_orphan_result(graph, r, rules),
        )
        orphan_results.append(result)

    current_keys = {b["branch_key"] for b in branches} | {
        orphan_key(r) for r in orphan_refs
    }
    removed_keys = sorted(set(old_rows) - current_keys)
    if removed_keys:
        conn.executemany(
            "DELETE FROM branch_cache WHERE project_key = ? AND branch_key = ?",
            [(project_key, key) for key in removed_keys],
        )

    report = _merge_results(
        graph=graph,
        normalized=normalized,
        branch_results=branch_results,
        orphan_results=orphan_results,
        recomputed=recomputed,
        reused=reused,
        removed_keys=removed_keys,
        had_cache=bool(old_rows),
        orphan_count=len(orphan_refs),
        project_key=project_key,
        sbom_id=sbom_id,
        rule_set_id=rule_set_id,
        rule_count=len(rule_entries),
        strict_unknown=strict_unknown,
    )
    report["computation_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return report


# ---------------------------------------------------------------------------
# Merge units -> one shortest path per violating component
# ---------------------------------------------------------------------------


def _merge_results(
    *,
    graph: Graph,
    normalized: dict[str, Any],
    branch_results: list[dict[str, Any]],
    orphan_results: list[dict[str, Any]],
    recomputed: list[dict[str, Any]],
    reused: list[dict[str, Any]],
    removed_keys: list[str],
    had_cache: bool,
    orphan_count: int,
    project_key: str,
    sbom_id: int,
    rule_set_id: int,
    rule_count: int,
    strict_unknown: bool,
) -> dict[str, Any]:
    best: dict[str, tuple[tuple, dict[str, Any]]] = {}
    unresolved_all: dict[str, dict[str, Any]] = {}

    for result in branch_results:
        current_root = result["root_ref"]
        current_key = result["branch_key"]
        for entry in result.get("unresolved", []):
            unresolved_all.setdefault(entry["bom_ref"], entry)

        for violation in result.get("violations", []):
            relative_path: list[str] = violation["relative_path"]
            if result["kind"] == "self":
                ref_path = [current_root]
            else:
                ref_path = [current_root] + relative_path

            length = len(ref_path) - 1
            sort_key = (length, tuple(ref_path), current_key)
            path_obj = {
                "root_bom_ref": current_root,
                "branch_key": current_key,
                "length_edges": length,
                "bom_refs": ref_path,
                "nodes": [
                    _component_brief(ref, graph.nodes.get(ref))
                    for ref in ref_path
                ],
            }
            payload = {
                key: value
                for key, value in violation.items()
                if key != "relative_path"
            }
            payload["reachable"] = True
            payload["path"] = path_obj

            ref = violation["ref"]
            incumbent = best.get(ref)
            if incumbent is None or sort_key < incumbent[0]:
                best[ref] = (sort_key, payload)

    # Orphans: full coverage, but no root-relative dependency path exists.
    for result in orphan_results:
        for entry in result.get("unresolved", []):
            unresolved_all.setdefault(entry["bom_ref"], entry)
        for violation in result.get("violations", []):
            ref = violation["ref"]
            if ref in best:
                continue  # a branch already found a path (should not happen)
            violation["reachable"] = False
            violation["path"] = None
            violation["path_note"] = (
                "component is listed in the SBOM but is not reachable from "
                "the dependency root(s)"
            )
            best[ref] = ((1 << 60, (ref,), result["branch_key"]), violation)

    violations = [
        payload
        for _, payload in sorted(
            best.values(),
            key=lambda item: (
                item[1].get("name") or "",
                item[1].get("version") or "",
                item[1]["ref"],
            ),
        )
    ]

    license_to_refs: dict[str, set[str]] = {}
    for violation in violations:
        for lic in violation["violating_licenses"]:
            license_to_refs.setdefault(lic, set()).add(violation["ref"])

    violating_licenses = [
        {
            "license": lic,
            "component_count": len(refs),
            "component_refs": sorted(refs),
        }
        for lic, refs in sorted(license_to_refs.items())
    ]
    violating_license_ids = sorted(license_to_refs)

    unresolved_components = sorted(unresolved_all.values(), key=lambda x: x["bom_ref"])
    policy_blocks: list[dict[str, Any]] = []
    if strict_unknown and unresolved_components:
        policy_blocks.append(
            {
                "code": "strict_unknown_licenses",
                "message": (
                    "strict_unknown is set and "
                    f"{len(unresolved_components)} component(s) have unresolved "
                    "license declarations"
                ),
                "component_refs": [u["bom_ref"] for u in unresolved_components],
            }
        )

    releasable = not violations and not policy_blocks

    if not had_cache:
        mode = "cold"
    elif not recomputed:
        mode = "cached"
    else:
        mode = "incremental"

    return {
        "project_key": project_key,
        "sbom_id": sbom_id,
        "rule_set_id": rule_set_id,
        "policy": {
            "strict_unknown": strict_unknown,
            "restricted_rule_count": rule_count,
        },
        "releasable": releasable,
        "summary": {
            "component_count": len(graph.nodes),
            "root_count": len(graph.roots),
            "branch_count": len(branch_results),
            "orphan_component_count": orphan_count,
            "violation_component_count": len(violations),
            "reachable_violation_count": sum(
                1 for v in violations if v.get("reachable")
            ),
            "unreachable_violation_count": sum(
                1 for v in violations if not v.get("reachable")
            ),
            "violation_license_count": len(violating_license_ids),
            "unresolved_component_count": len(unresolved_components),
            "recomputed_unit_count": len(recomputed),
            "reused_unit_count": len(reused),
        },
        "violations": violations,
        "violating_licenses": violating_licenses,
        "violating_license_ids": violating_license_ids,
        "unresolved_licenses": unresolved_components,
        "policy_blocks": policy_blocks,
        "warnings": normalized.get("warnings", []),
        "incremental": {
            "mode": mode,
            "recomputed_branches": recomputed,
            "reused_branches": reused,
            "removed_branch_keys": removed_keys,
        },
    }
