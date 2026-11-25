#!/usr/bin/env python3
"""End-to-end smoke test against a running License Release Gate API.

Usage:
    python scripts/smoke_test.py [BASE_URL]

Stdlib only. Exits non-zero if any key operation behaves incorrectly.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
PASS = "✅"
FAIL = "❌"
failures: list[str] = []


def call(method: str, path: str, body=None, expected: int | None = None):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status = resp.status
            payload = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        status = exc.code
        payload = json.loads(exc.read().decode())
    if expected is not None and status != expected:
        failures.append(f"{method} {path}: expected {expected}, got {status}: {payload}")
        print(f"{FAIL} {method} {path} -> {status} (expected {expected})")
    return status, payload


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"{PASS} {name}")
    else:
        failures.append(name)
        print(f"{FAIL} {name} {detail}")


# 1. Meta + docs/openapi -----------------------------------------------------
status, health = call("GET", "/health", expected=200)
check("health ok", health.get("status") == "ok")
with urllib.request.urlopen(BASE + "/docs", timeout=10) as r:
    check("/docs available", r.status == 200 and b"swagger" in r.read().lower())
status, spec = call("GET", "/openapi.json", expected=200)
check("openapi lists demo endpoints",
      "/api/demo/version-conflict" in spec["paths"]
      and "/api/demo/cycle" in spec["paths"]
      and "/api/demo/rollback" in spec["paths"])

# 2. Structured import + id-based verification ------------------------------
_, rules = call("POST", "/api/rules", {
    "name": "smoke-rules", "version_label": "t",
    "licenses": ["GPL-3.0-only", "AGPL-3.0-only", "SSPL-1.0"],
}, 200)
rid = rules["rule_set_id"]

sbom = json.load(open("examples/sbom-version-conflict.json", encoding="utf-8"))
_, imported = call("POST", "/api/sboms?project_key=smoke-shop", sbom, 200)
sid = imported["sbom_id"]
check("sbom import reports 5 components", imported["component_count"] == 5)

_, verdict = call("POST", "/api/verifications", {
    "project_key": "smoke-shop", "sbom_id": sid, "rule_set_id": rid,
}, 200)
check("version conflict -> not releasable", verdict["releasable"] is False)
v0 = verdict["violations"][0]
check("only AGPL 2.1.0 violates",
      v0["name"] == "logging-lib" and v0["version"] == "2.1.0"
      and v0["violating_licenses"] == ["AGPL-3.0-only"])
check("shortest path has 2 edges", v0["path"]["length_edges"] == 2)

# Same verification again -> persisted incremental cache hit.
_, verdict2 = call("POST", "/api/verifications", {
    "project_key": "smoke-shop", "sbom_id": sid, "rule_set_id": rid,
}, 200)
check("repeat verification fully cached",
      verdict2["incremental"]["mode"] == "cached")

# 3. Raw rule-list import (JSON array file shape) ----------------------------
raw_rules = json.load(open("examples/restricted-spdx.json", encoding="utf-8"))
_, raw_import = call("POST", "/api/rules", {
    "name": "smoke-raw", "licenses": raw_rules,
}, 200)
check("rule list import idempotent/ok", "rule_set_id" in raw_import)

# 4. Publish / reject / simulated failure / rollback -------------------------
key = "smoke-release"
clean = json.load(open("examples/sbom-rollback-v1-clean.json", encoding="utf-8"))
bad = json.load(open("examples/sbom-rollback-v2-violating.json", encoding="utf-8"))

_, pub1 = call("POST", "/api/releases", {
    "project_key": key, "sbom": clean, "licenses": raw_rules,
}, 200)
check("clean release published as v1", pub1["version_no"] == 1
      and pub1["verification"]["releasable"] is True)
check("release bundles current SBOM input",
      pub1["input"]["sbom"]["metadata"]["component"]["version"] == "1.0.0")

status, rejected = call("POST", "/api/releases", {
    "project_key": key, "sbom": bad, "licenses": raw_rules,
}, 409)
check("violating release rejected with current_version_no=1",
      status == 409 and rejected["current_version_no"] == 1)

status, crashed = call("POST", "/api/releases", {
    "project_key": key, "sbom": clean, "licenses": raw_rules,
    "simulate_failure": True,
}, 500)
check("simulated failure reports rollback",
      status == 500 and crashed["rolled_back"] is True
      and crashed["current_version_no"] == 1)

_, current = call("GET", f"/api/releases/current?project_key={key}", expected=200)
check("current release still v1 with original input",
      current["version_no"] == 1
      and current["input"]["sbom"]["metadata"]["component"]["version"] == "1.0.0")
_, versions = call("GET", f"/api/releases?project_key={key}", expected=200)
check("exactly one published version retained",
      [v["version_no"] for v in versions] == [1])

# 5. Cycle demo invariants over HTTP ----------------------------------------
_, cycle_demo = call("POST", "/api/demo/cycle", expected=200)
cverdict = cycle_demo["verification"]
violations = cverdict["violations"]
check("cycle demo reports exactly 2 violations", len(violations) == 2)
for v in violations:
    refs = v["path"]["bom_refs"]
    check(f"path to {v['name']} is simple/non-repeating",
          len(refs) == len(set(refs)) and v["path"]["length_edges"] == len(refs) - 1)

# 6. Incremental demo counts -------------------------------------------------
_, inc = call("POST", "/api/demo/incremental", expected=200)
steps = inc["steps"]
check("incremental step1 cold", steps[0]["verification"]["incremental"]["mode"] == "cold")
check("incremental step2 recomputes 3 units",
      steps[1]["verification"]["summary"]["recomputed_unit_count"] == 3)
check("incremental step3 recomputes 1 unit",
      steps[2]["verification"]["summary"]["recomputed_unit_count"] == 1)

print()
if failures:
    print(f"{len(failures)} CHECK(S) FAILED")
    sys.exit(1)
print("ALL SMOKE CHECKS PASSED")
