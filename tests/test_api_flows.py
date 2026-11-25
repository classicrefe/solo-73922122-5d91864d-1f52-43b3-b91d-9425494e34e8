"""End-to-end API tests: imports, verification, publish versioning/rollback."""

from app.fixtures import (
    RESTRICTED_LICENSES,
    cycle_sbom,
    rollback_v1_sbom,
    rollback_v2_sbom,
    version_conflict_sbom,
)


def test_health_and_root(client):
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/").json()["docs"] == "/docs"


def test_import_sbom_and_rules_then_verify_by_id(client):
    r = client.post(
        "/api/sboms?project_key=shop", json=version_conflict_sbom()
    )
    assert r.status_code == 200, r.text
    sbom_id = r.json()["sbom_id"]

    r = client.post("/api/rules", json={"licenses": RESTRICTED_LICENSES})
    assert r.status_code == 200
    rule_id = r.json()["rule_set_id"]

    r = client.post(
        "/api/verifications",
        json={
            "project_key": "shop",
            "sbom_id": sbom_id,
            "rule_set_id": rule_id,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["releasable"] is False
    assert body["violations"][0]["name"] == "logging-lib"
    assert body["violations"][0]["version"] == "2.1.0"
    assert body["incremental"]["mode"] == "cold"


def test_inline_verification_is_self_contained(client):
    r = client.post(
        "/api/verifications",
        json={
            "project_key": "inline-demo",
            "sbom": cycle_sbom(),
            "licenses": RESTRICTED_LICENSES,
        },
    )
    assert r.status_code == 200, r.text
    refs = {v["ref"] for v in r.json()["violations"]}
    assert len(refs) == 2


def test_invalid_sbom_returns_422_and_nothing_imported(client):
    r = client.post("/api/sboms?project_key=bad", content=b"{not json",
                    headers={"content-type": "application/json"})
    assert r.status_code == 422
    listed = client.get("/api/sboms?project_key=bad").json()
    assert listed == []


def test_publish_happy_then_policy_rejection_and_failure_rollback(client):
    key = "release-flow"

    # v1 clean publishes.
    r = client.post(
        "/api/releases",
        json={
            "project_key": key,
            "sbom": rollback_v1_sbom(),
            "licenses": RESTRICTED_LICENSES,
        },
    )
    assert r.status_code == 200, r.text
    bundle = r.json()
    assert bundle["version_no"] == 1
    assert bundle["verification"]["releasable"] is True
    # Inputs are bundled with the result.
    assert bundle["input"]["sbom"]["bomFormat"] == "CycloneDX"
    assert bundle["input"]["rules"]["licenses"] == RESTRICTED_LICENSES

    current = client.get(f"/api/releases/current?project_key={key}").json()
    assert current["version_no"] == 1

    # v2 violating -> 409 and current stays v1.
    r = client.post(
        "/api/releases",
        json={
            "project_key": key,
            "sbom": rollback_v2_sbom(),
            "licenses": RESTRICTED_LICENSES,
        },
    )
    assert r.status_code == 409
    assert r.json()["current_version_no"] == 1
    assert r.json()["verification"]["releasable"] is False

    current = client.get(f"/api/releases/current?project_key={key}").json()
    assert current["version_no"] == 1
    # The retained bundle is still the v1 input snapshot.
    assert current["input"]["sbom"]["metadata"]["component"]["version"] == "1.0.0"

    versions = client.get(f"/api/releases?project_key={key}").json()
    assert [v["version_no"] for v in versions] == [1]

    attempts = client.get(f"/api/attempts?project_key={key}").json()
    outcomes = [a["outcome"] for a in attempts]
    assert outcomes == ["policy_rejected", "published"]

    # Simulated crash -> 500, transaction rolled back, still v1.
    r = client.post(
        "/api/releases",
        json={
            "project_key": key,
            "sbom": rollback_v1_sbom(),
            "licenses": RESTRICTED_LICENSES,
            "simulate_failure": True,
        },
    )
    assert r.status_code == 500
    assert r.json()["rolled_back"] is True
    assert r.json()["current_version_no"] == 1

    current = client.get(f"/api/releases/current?project_key={key}").json()
    assert current["version_no"] == 1
    versions = client.get(f"/api/releases?project_key={key}").json()
    assert [v["version_no"] for v in versions] == [1]
    # Rolled-back attempt left no 'failed' row beyond the two committed ones.
    attempts = client.get(f"/api/attempts?project_key={key}").json()
    assert len(attempts) == 2


def test_multiple_published_versions_are_retained(client):
    key = "multi-version"
    for i in range(2):
        sbom = rollback_v1_sbom()  # identical content dedupes, but publish still versions
        r = client.post(
            "/api/releases",
            json={"project_key": key, "sbom": sbom,
                  "licenses": RESTRICTED_LICENSES},
        )
        # Second publish references identical sbom/rules but creates release v2.
        assert r.status_code == 200, r.text
    versions = client.get(f"/api/releases?project_key={key}").json()
    assert [v["version_no"] for v in versions] == [2, 1]
    v1 = client.get(f"/api/releases/1?project_key={key}")
    assert v1.status_code == 200 and v1.json()["version_no"] == 1


def test_current_release_404_for_unknown_project(client):
    r = client.get("/api/releases/current?project_key=nope")
    assert r.status_code == 404


def test_demo_endpoints(client):
    r = client.post("/api/demo/version-conflict")
    assert r.status_code == 200, r.text
    assert r.json()["verification"]["summary"]["violation_component_count"] == 1

    r = client.post("/api/demo/cycle")
    assert r.status_code == 200
    assert len(r.json()["verification"]["violations"]) == 2

    r = client.post("/api/demo/incremental")
    assert r.status_code == 200
    steps = r.json()["steps"]
    assert steps[0]["verification"]["incremental"]["mode"] == "cold"
    assert steps[1]["verification"]["summary"]["recomputed_unit_count"] == 3
    assert steps[2]["verification"]["summary"]["recomputed_unit_count"] == 1

    r = client.post("/api/demo/rollback")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["current_version_no_after"] == 1
    assert data["policy_rejection"]["http_status"] == 409
    assert data["simulated_failure"]["rolled_back"] is True
    assert [v["version_no"] for v in data["published_versions"]] == [1]
