"""Canonical demo/fixture inputs shared by one-click demos and tests."""

from __future__ import annotations

from typing import Any

RESTRICTED_LICENSES: list[str] = [
    "GPL-2.0-only",
    "GPL-3.0-only",
    "AGPL-3.0-only",
    "LGPL-3.0-only",
    "SSPL-1.0",
]


def _component(
    ref: str,
    name: str,
    version: str,
    licenses: list[Any],
    *,
    cdx_type: str = "library",
) -> dict[str, Any]:
    lic_entries = []
    for lic in licenses:
        if isinstance(lic, dict):
            lic_entries.append(lic)
        elif isinstance(lic, str) and (" OR " in lic or " AND " in lic):
            lic_entries.append({"expression": lic})
        else:
            lic_entries.append({"license": {"id": lic}})
    return {
        "type": cdx_type,
        "bom-ref": ref,
        "name": name,
        "version": version,
        "licenses": lic_entries,
    }


def _sbom(
    *,
    root_ref: str,
    root_name: str,
    root_version: str,
    components: list[dict[str, Any]],
    deps: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": _component(
                root_ref, root_name, root_version, ["Apache-2.0"],
                cdx_type="application",
            )
        },
        "components": components,
        "dependencies": deps,
    }


# ---------------------------------------------------------------------------
# 1) Version conflict: same package name, two coexisting versions
# ---------------------------------------------------------------------------


def version_conflict_sbom() -> dict[str, Any]:
    refs = {
        "root": "pkg:maven/com.acme/shop@2.4.0",
        "web": "pkg:maven/org.example/web-framework@5.1.0",
        "metrics": "pkg:maven/org.example/metrics-agent@2.0.0",
        "log_old": "pkg:maven/org.example/logging-lib@1.4.2",
        "log_new": "pkg:maven/org.example/logging-lib@2.1.0",
    }
    components = [
        _component(refs["web"], "web-framework", "5.1.0", ["MIT"]),
        _component(refs["metrics"], "metrics-agent", "2.0.0", ["Apache-2.0"]),
        _component(refs["log_old"], "logging-lib", "1.4.2", ["Apache-2.0"]),
        _component(refs["log_new"], "logging-lib", "2.1.0", ["AGPL-3.0-only"]),
    ]
    deps = [
        {"ref": refs["root"], "dependsOn": [refs["web"], refs["metrics"]]},
        {"ref": refs["web"], "dependsOn": [refs["log_old"]]},
        {"ref": refs["metrics"], "dependsOn": [refs["log_new"]]},
        {"ref": refs["log_old"], "dependsOn": []},
        {"ref": refs["log_new"], "dependsOn": []},
    ]
    return _sbom(
        root_ref=refs["root"], root_name="acme-shop", root_version="2.4.0",
        components=components, deps=deps,
    )


# ---------------------------------------------------------------------------
# 2) Circular dependencies with violations inside cycles
# ---------------------------------------------------------------------------


def cycle_sbom() -> dict[str, Any]:
    r = {
        "root": "pkg:npm/order-service@1.0.0",
        "pricing": "pkg:npm/pricing-engine@3.2.1",
        "rulecore": "pkg:npm/rule-core@2.0.0",
        "policystore": "pkg:npm/policy-store@1.2.0",
        "reports": "pkg:npm/compliance-reports@0.9.0",
        "auth": "pkg:npm/auth-gateway@4.0.0",
        "vault": "pkg:npm/token-vault@2.2.0",
        "metrics": "pkg:npm/metrics-collector@1.0.0",
    }
    components = [
        _component(r["pricing"], "pricing-engine", "3.2.1", ["Apache-2.0"]),
        _component(r["rulecore"], "rule-core", "2.0.0", ["MIT"]),
        _component(r["policystore"], "policy-store", "1.2.0", ["BSD-3-Clause"]),
        _component(r["reports"], "compliance-reports", "0.9.0", ["GPL-3.0-only"]),
        _component(r["auth"], "auth-gateway", "4.0.0", ["Apache-2.0"]),
        _component(r["vault"], "token-vault", "2.2.0", ["AGPL-3.0-only"]),
        _component(r["metrics"], "metrics-collector", "1.0.0", ["MIT"]),
    ]
    deps = [
        {"ref": r["root"], "dependsOn": [r["pricing"], r["auth"], r["metrics"]]},
        # cycle rule-core <-> policy-store; reports reachable via two routes
        {"ref": r["pricing"], "dependsOn": [r["rulecore"]]},
        {"ref": r["rulecore"], "dependsOn": [r["policystore"], r["reports"]]},
        {"ref": r["policystore"], "dependsOn": [r["rulecore"], r["reports"]]},
        {"ref": r["reports"], "dependsOn": []},
        # cycle auth-gateway <-> token-vault (violating node in the cycle)
        {"ref": r["auth"], "dependsOn": [r["vault"]]},
        {"ref": r["vault"], "dependsOn": [r["auth"]]},
        # self-loop
        {"ref": r["metrics"], "dependsOn": [r["metrics"]]},
    ]
    return _sbom(
        root_ref=r["root"], root_name="order-service", root_version="1.0.0",
        components=components, deps=deps,
    )


# ---------------------------------------------------------------------------
# 3) Publish rollback: clean v1, policy-breaking v2
# ---------------------------------------------------------------------------


def rollback_v1_sbom() -> dict[str, Any]:
    root = "pkg:golang/acme.io/release-console@1.0.0"
    safe = "pkg:golang/github.com/acme/safe-lib@1.0.0"
    return _sbom(
        root_ref=root, root_name="release-console", root_version="1.0.0",
        components=[_component(safe, "safe-lib", "1.0.0", ["Apache-2.0"])],
        deps=[
            {"ref": root, "dependsOn": [safe]},
            {"ref": safe, "dependsOn": []},
        ],
    )


def rollback_v2_sbom() -> dict[str, Any]:
    root = "pkg:golang/acme.io/release-console@2.0.0"
    safe = "pkg:golang/github.com/acme/safe-lib@1.0.0"
    copyleft = "pkg:golang/github.com/ext/copyleft-lib@3.0.0"
    return _sbom(
        root_ref=root, root_name="release-console", root_version="2.0.0",
        components=[
            _component(safe, "safe-lib", "1.0.0", ["Apache-2.0"]),
            _component(copyleft, "copyleft-lib", "3.0.0", ["GPL-3.0-only"]),
        ],
        deps=[
            {"ref": root, "dependsOn": [safe, copyleft]},
            {"ref": safe, "dependsOn": []},
            {"ref": copyleft, "dependsOn": []},
        ],
    )


# ---------------------------------------------------------------------------
# 4) Incremental recomputation: shared dependency across two branches
# ---------------------------------------------------------------------------


def incremental_v1_sbom() -> dict[str, Any]:
    r = {
        "root": "pkg:pypi/build-app@1.0.0",
        "web": "pkg:pypi/web-branch@1.0.0",
        "data": "pkg:pypi/data-branch@1.0.0",
        "standalone": "pkg:pypi/standalone-branch@1.0.0",
        "shared": "pkg:pypi/shared-core@1.0.0",
        "isolated": "pkg:pypi/isolated-lib@1.0.0",
    }
    components = [
        _component(r["web"], "web-branch", "1.0.0", ["MIT"]),
        _component(r["data"], "data-branch", "1.0.0", ["MIT"]),
        _component(r["standalone"], "standalone-branch", "1.0.0", ["MIT"]),
        _component(r["shared"], "shared-core", "1.0.0", ["MIT"]),
        _component(r["isolated"], "isolated-lib", "1.0.0", ["BSD-3-Clause"]),
    ]
    deps = [
        {"ref": r["root"], "dependsOn": [r["web"], r["data"], r["standalone"]]},
        {"ref": r["web"], "dependsOn": [r["shared"]]},
        {"ref": r["data"], "dependsOn": [r["shared"]]},
        {"ref": r["standalone"], "dependsOn": [r["isolated"]]},
        {"ref": r["shared"], "dependsOn": []},
        {"ref": r["isolated"], "dependsOn": []},
    ]
    return _sbom(
        root_ref=r["root"], root_name="build-app", root_version="1.0.0",
        components=components, deps=deps,
    )


def incremental_v2_sbom() -> dict[str, Any]:
    """shared-core bumps to 2.0.0 and becomes AGPL; branches otherwise same."""
    base = incremental_v1_sbom()
    old_root = "pkg:pypi/build-app@1.0.0"
    new_root = "pkg:pypi/build-app@1.1.0"
    old_shared = "pkg:pypi/shared-core@1.0.0"
    new_shared = "pkg:pypi/shared-core@2.0.0"
    base["metadata"]["component"]["version"] = "1.1.0"
    base["metadata"]["component"]["bom-ref"] = new_root
    base["metadata"]["component"]["name"] = "build-app"
    for comp in base["components"]:
        if comp["bom-ref"] == old_shared:
            comp["bom-ref"] = new_shared
            comp["version"] = "2.0.0"
            comp["licenses"] = [{"license": {"id": "AGPL-3.0-only"}}]
    new_deps = []
    for dep in base["dependencies"]:
        if dep["ref"] == old_root:
            dep["ref"] = new_root
        if dep["ref"] == old_shared:
            dep["ref"] = new_shared
        dep["dependsOn"] = [
            new_shared if d == old_shared else d for d in dep["dependsOn"]
        ]
        new_deps.append(dep)
    base["dependencies"] = new_deps
    return base
