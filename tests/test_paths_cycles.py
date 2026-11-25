"""Correctness: separate versions, shortest paths, cycles, random graphs."""

import random
from collections import deque

from helpers import RESTRICTED, verify_sbom

from app.fixtures import cycle_sbom, version_conflict_sbom


def _refs_of_license(report, license_id):
    return {
        v["ref"]
        for v in report["violations"]
        if license_id in v["violating_licenses"]
    }


def test_same_package_versions_checked_separately(conn):
    report = verify_sbom(conn, version_conflict_sbom())
    assert report["releasable"] is False
    assert report["summary"]["violation_component_count"] == 1

    violation = report["violations"][0]
    assert violation["name"] == "logging-lib"
    assert violation["version"] == "2.1.0"
    assert violation["violating_licenses"] == ["AGPL-3.0-only"]

    refs = violation["path"]["bom_refs"]
    assert refs == [
        "pkg:maven/com.acme/shop@2.4.0",
        "pkg:maven/org.example/metrics-agent@2.0.0",
        "pkg:maven/org.example/logging-lib@2.1.0",
    ]
    assert violation["path"]["length_edges"] == 2

    # The permissive 1.4.2 version exists as a component and is not violating.
    sbom_row = conn.execute("SELECT normalized_json FROM sboms WHERE id=1").fetchone()
    import json

    components = json.loads(sbom_row[0])["components"]
    old = components["pkg:maven/org.example/logging-lib@1.4.2"]
    assert old["version"] == "1.4.2"
    assert all(v["version"] != "1.4.2" for v in report["violations"])


def test_cycles_no_duplicate_no_missing_and_shortest(conn):
    report = verify_sbom(conn, cycle_sbom())
    assert report["releasable"] is False

    by_ref = {v["ref"]: v for v in report["violations"]}
    reports_ref = "pkg:npm/compliance-reports@0.9.0"
    vault_ref = "pkg:npm/token-vault@2.2.0"
    assert set(by_ref) == {reports_ref, vault_ref}

    # Each violating component appears exactly once.
    assert len(report["violations"]) == len(by_ref)

    vault_path = by_ref[vault_ref]["path"]["bom_refs"]
    assert vault_path == [
        "pkg:npm/order-service@1.0.0",
        "pkg:npm/auth-gateway@4.0.0",
        vault_ref,
    ]
    assert len(vault_path) == len(set(vault_path))  # no repeated node

    reports_path = by_ref[reports_ref]["path"]["bom_refs"]
    # Shortest route is root -> pricing -> rule-core -> reports (3 edges),
    # not the longer route through policy-store.
    assert reports_path == [
        "pkg:npm/order-service@1.0.0",
        "pkg:npm/pricing-engine@3.2.1",
        "pkg:npm/rule-core@2.0.0",
        reports_ref,
    ]
    assert len(reports_path) - 1 == by_ref[reports_ref]["path"]["length_edges"]
    assert len(reports_path) == len(set(reports_path))

    # Aggregated licenses are unique and reference the components.
    agg = {x["license"]: x for x in report["violating_licenses"]}
    assert set(agg) == {"AGPL-3.0-only", "GPL-3.0-only"}
    assert agg["AGPL-3.0-only"]["component_refs"] == [vault_ref]


def test_second_run_is_fully_cached_and_stable(conn):
    sbom = cycle_sbom()
    first = verify_sbom(conn, sbom, project="stable")
    second = verify_sbom(conn, sbom, project="stable")
    assert second["incremental"]["mode"] == "cached"
    assert second["incremental"]["recomputed_branches"] == []
    assert [v["ref"] for v in first["violations"]] == [
        v["ref"] for v in second["violations"]
    ]
    assert [v["path"]["bom_refs"] for v in first["violations"]] == [
        v["path"]["bom_refs"] for v in second["violations"]
    ]


def test_unreachable_listed_component_is_still_reported_without_path(conn):
    import json

    from app.services import save_rule_set, save_sbom
    from app.verifier import verify

    doc = {
        "bomFormat": "CycloneDX",
        "metadata": {"component": {"bom-ref": "root", "name": "r", "version": "1"}},
        "components": [
            {"bom-ref": "root", "name": "r", "version": "1"},
            {"bom-ref": "reachable", "name": "a", "version": "1",
             "licenses": [{"license": {"id": "MIT"}}]},
            {"bom-ref": "orphan-bad", "name": "hidden", "version": "9",
             "licenses": [{"license": {"id": "SSPL-1.0"}}]},
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["reachable"]},
            {"ref": "reachable", "dependsOn": []},
        ],
    }
    sid = save_sbom(conn, "orphan", doc)["sbom_id"]
    rid = save_rule_set(conn, RESTRICTED)["rule_set_id"]
    norm = json.loads(conn.execute(
        "SELECT normalized_json FROM sboms WHERE id=?", (sid,)
    ).fetchone()[0])
    report = verify(
        conn, project_key="orphan", sbom_id=sid, normalized=norm,
        rule_set_id=rid, rule_entries=RESTRICTED,
    )
    assert [v["ref"] for v in report["violations"]] == ["orphan-bad"]
    v = report["violations"][0]
    assert v["reachable"] is False
    assert v["path"] is None
    assert report["summary"]["unreachable_violation_count"] == 1


# ---------------------------------------------------------------------------
# Seeded random graph fuzz: compare against independent BFS oracle
# ---------------------------------------------------------------------------


def _oracle_distances(adj, root, node_ids):
    dist = {root: 0}
    q = deque([root])
    while q:
        u = q.popleft()
        for w in adj.get(u, []):
            if w not in dist:
                dist[w] = dist[u] + 1
                q.append(w)
    return dist


def test_random_graphs_shortest_path_and_coverage_oracle(conn):
    rng = random.Random(20261125)
    for seed in range(40):
        rng.seed(seed)
        n = rng.randint(3, 14)
        node_ids = [f"n{i}" for i in range(n)]
        root = "n0"
        adj = {x: [] for x in node_ids}
        for i in range(1, n):
            # ensure mostly connected, then random extra edges (cycles likely)
            parent = f"n{rng.randint(0, i - 1)}"
            adj[parent].append(f"n{i}")
        for _ in range(rng.randint(0, n * 2)):
            u = rng.choice(node_ids)
            v = rng.choice(node_ids)
            if v not in adj[u]:
                adj[u].append(v)

        restricted_nodes = set(rng.sample(node_ids, rng.randint(1, n // 2 + 1)))
        components = {}
        for x in node_ids:
            lic = "R-LIC" if x in restricted_nodes else "MIT"
            components[x] = {
                "bom_ref": x, "name": x, "version": "1", "type": "library",
                "purl": None, "supplier": None, "missing": False,
                "licenses": [{"kind": "id", "value": lic}],
            }
        normalized = {
            "format": "test", "spec_version": None, "roots": [root],
            "components": components, "edges": adj, "warnings": [],
        }
        # Call engine directly with synthetic normalized graph.
        from app.verifier import verify

        report = verify(
            conn, project_key=f"fuzz-{seed}", sbom_id=10_000 + seed,
            normalized=normalized, rule_set_id=999,
            rule_entries=["R-LIC"],
        )

        dist = _oracle_distances(adj, root, node_ids)
        violating = {v["ref"]: v for v in report["violations"]}

        # Full coverage: every restricted node reported exactly once.
        assert set(violating) == restricted_nodes, seed
        assert len(report["violations"]) == len(restricted_nodes)

        for ref, v in violating.items():
            if ref in dist:
                assert v["reachable"] is True
                refs = v["path"]["bom_refs"]
                assert refs[0] == root and refs[-1] == ref
                assert len(refs) == len(set(refs))
                assert len(refs) - 1 == dist[ref] == v["path"]["length_edges"]
                for a, b in zip(refs, refs[1:]):
                    assert b in adj[a]
            else:
                assert v["reachable"] is False and v["path"] is None

        # Second run cached and identical.
        again = verify(
            conn, project_key=f"fuzz-{seed}", sbom_id=10_000 + seed,
            normalized=normalized, rule_set_id=999,
            rule_entries=["R-LIC"],
        )
        assert again["incremental"]["mode"] == "cached", seed
        assert [v["path"] for v in again["violations"]] == [
            v["path"] for v in report["violations"]
        ]
