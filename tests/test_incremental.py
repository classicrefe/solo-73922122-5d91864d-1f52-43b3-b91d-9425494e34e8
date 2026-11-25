"""Incremental recomputation: only affected branches are recomputed."""

import json

from helpers import RESTRICTED

from app import verifier
from app.fixtures import incremental_v1_sbom, incremental_v2_sbom
from app.services import save_rule_set, save_sbom

WEB = "pkg:pypi/web-branch@1.0.0"
DATA = "pkg:pypi/data-branch@1.0.0"
STANDALONE = "pkg:pypi/standalone-branch@1.0.0"
ROOT_SELF = "__root_self__"


def _verify(conn, *, project, sbom_id, rule_id, rules):
    row = conn.execute(
        "SELECT normalized_json FROM sboms WHERE id = ?", (sbom_id,)
    ).fetchone()
    return verifier.verify(
        conn,
        project_key=project,
        sbom_id=sbom_id,
        normalized=json.loads(row["normalized_json"]),
        rule_set_id=rule_id,
        rule_entries=rules,
    )


def test_sbom_revision_recomputes_only_branches_containing_changed_node(
    conn, monkeypatch
):
    p = "inc-sbom"
    r1 = save_rule_set(conn, RESTRICTED)["rule_set_id"]
    s1 = save_sbom(conn, p, incremental_v1_sbom())["sbom_id"]
    first = _verify(conn, project=p, sbom_id=s1, rule_id=r1, rules=RESTRICTED)
    assert first["incremental"]["mode"] == "cold"
    assert {x["branch_key"] for x in first["incremental"]["recomputed_branches"]} == {
        ROOT_SELF, WEB, DATA, STANDALONE,
    }

    s2 = save_sbom(conn, p, incremental_v2_sbom())["sbom_id"]

    calls: list[str] = []
    original = verifier.compute_branch_result

    def spy(graph, branch, rules):
        calls.append(branch["branch_key"])
        return original(graph, branch, rules)

    monkeypatch.setattr(verifier, "compute_branch_result", spy)
    second = _verify(conn, project=p, sbom_id=s2, rule_id=r1, rules=RESTRICTED)

    recomputed = {
        x["branch_key"] for x in second["incremental"]["recomputed_branches"]
    }
    reused = {x["branch_key"] for x in second["incremental"]["reused_branches"]}
    assert recomputed == {ROOT_SELF, WEB, DATA}
    assert reused == {STANDALONE}
    assert calls == [ROOT_SELF, WEB, DATA] or set(calls) == {
        ROOT_SELF, WEB, DATA
    }
    assert STANDALONE not in calls

    # Impact explanation names the changed shared component refs.
    impacted = {
        x["branch_key"]: x["impacted_by_refs"]
        for x in second["incremental"]["recomputed_branches"]
    }
    web_impact = impacted[WEB]
    assert any("shared-core@2.0.0" in ref for ref in web_impact)

    # New AGPL violation is reported with a shortest path.
    refs = {v["ref"] for v in second["violations"]}
    assert "pkg:pypi/shared-core@2.0.0" in refs


def test_rule_revision_recomputes_only_branches_with_flipped_license(conn, monkeypatch):
    p = "inc-rules"
    r1 = save_rule_set(conn, RESTRICTED)["rule_set_id"]
    s1 = save_sbom(conn, p, incremental_v1_sbom())["sbom_id"]
    _verify(conn, project=p, sbom_id=s1, rule_id=r1, rules=RESTRICTED)
    s2 = save_sbom(conn, p, incremental_v2_sbom())["sbom_id"]
    _verify(conn, project=p, sbom_id=s2, rule_id=r1, rules=RESTRICTED)

    new_rules = RESTRICTED + ["BSD-3-Clause"]
    r2 = save_rule_set(conn, new_rules, version_label="v2")["rule_set_id"]

    calls: list[str] = []
    original = verifier.compute_branch_result

    def spy(graph, branch, rules):
        calls.append(branch["branch_key"])
        return original(graph, branch, rules)

    monkeypatch.setattr(verifier, "compute_branch_result", spy)
    third = _verify(conn, project=p, sbom_id=s2, rule_id=r2, rules=new_rules)

    recomputed = {
        x["branch_key"] for x in third["incremental"]["recomputed_branches"]
    }
    assert recomputed == {STANDALONE}
    assert calls == [STANDALONE]
    reused_reasons = {
        x["branch_key"]: x["reason"] for x in third["incremental"]["reused_branches"]
    }
    assert reused_reasons[WEB] == "unaffected_by_rules_or_policy_revision"

    violating = {v["ref"]: v for v in third["violations"]}
    assert "pkg:pypi/isolated-lib@1.0.0" in violating
    assert "pkg:pypi/shared-core@2.0.0" in violating


def test_unrelated_rule_addition_recomputes_nothing(conn):
    p = "inc-unrelated"
    r1 = save_rule_set(conn, RESTRICTED)["rule_set_id"]
    s1 = save_sbom(conn, p, incremental_v1_sbom())["sbom_id"]
    _verify(conn, project=p, sbom_id=s1, rule_id=r1, rules=RESTRICTED)

    new_rules = RESTRICTED + ["ZZ-NOT-A-USED-LICENSE-1.0"]
    r2 = save_rule_set(conn, new_rules)["rule_set_id"]
    report = _verify(conn, project=p, sbom_id=s1, rule_id=r2, rules=new_rules)
    assert report["incremental"]["mode"] == "cached"
    assert report["incremental"]["recomputed_branches"] == []
    assert all(
        x["reason"] == "unaffected_by_rules_or_policy_revision"
        for x in report["incremental"]["reused_branches"]
    )


def test_strict_unknown_flip_only_recomputes_branches_with_unresolved(conn):
    p = "inc-strict"
    doc = {
        "bomFormat": "CycloneDX",
        "metadata": {"component": {"bom-ref": "root", "name": "r", "version": "1"}},
        "components": [
            {"bom-ref": "root", "name": "r", "version": "1",
             "licenses": [{"license": {"id": "MIT"}}]},
            {"bom-ref": "branch-a", "name": "a", "version": "1",
             "licenses": [{"license": {"name": "Acme Proprietary EULA"}}]},
            {"bom-ref": "branch-b", "name": "b", "version": "1",
             "licenses": [{"license": {"id": "MIT"}}]},
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["branch-a", "branch-b"]},
            {"ref": "branch-a", "dependsOn": []},
            {"ref": "branch-b", "dependsOn": []},
        ],
    }
    sid = save_sbom(conn, p, doc)["sbom_id"]
    rid = save_rule_set(conn, RESTRICTED)["rule_set_id"]

    normal = verifier.verify(
        conn, project_key=p, sbom_id=sid,
        normalized=json.loads(conn.execute(
            "SELECT normalized_json FROM sboms WHERE id=?", (sid,)
        ).fetchone()[0]),
        rule_set_id=rid, rule_entries=RESTRICTED, strict_unknown=False,
    )
    assert normal["releasable"] is True
    assert normal["summary"]["unresolved_component_count"] == 1

    strict = verifier.verify(
        conn, project_key=p, sbom_id=sid,
        normalized=json.loads(conn.execute(
            "SELECT normalized_json FROM sboms WHERE id=?", (sid,)
        ).fetchone()[0]),
        rule_set_id=rid, rule_entries=RESTRICTED, strict_unknown=True,
    )
    assert strict["releasable"] is False
    recomputed = {x["branch_key"] for x in strict["incremental"]["recomputed_branches"]}
    assert recomputed == {"branch-a"}
