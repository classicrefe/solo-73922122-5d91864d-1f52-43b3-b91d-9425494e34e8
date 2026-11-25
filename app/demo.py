"""One-click scenarios surfaced as POST /api/demo/* in /docs."""

from __future__ import annotations

from typing import Any

from . import fixtures
from .db import connect, init_db
from .schemas import PublishRequest, VerificationRequest
from .services import (
    PolicyRejected,
    SimulatedPublishFailure,
    create_verification,
    current_version_no,
    get_release_bundle,
    list_attempts,
    list_release_versions,
    publish_release,
    reset_project,
    save_rule_set,
    save_sbom,
)

RULES = fixtures.RESTRICTED_LICENSES


def _conn():
    conn = connect()
    init_db(conn)
    return conn


def _ids(conn, project_key: str, sbom: dict[str, Any]) -> tuple[int, int]:
    sbom_info = save_sbom(conn, project_key, sbom)
    rules_info = save_rule_set(
        conn, RULES, name="demo-restricted-spdx", version_label="demo-v1"
    )
    return sbom_info["sbom_id"], rules_info["rule_set_id"]


def run_version_conflict() -> dict[str, Any]:
    key = "demo-version-conflict"
    conn = _conn()
    try:
        reset_project(conn, key)
        sbom_id, rule_id = _ids(conn, key, fixtures.version_conflict_sbom())
        report = create_verification(
            conn,
            VerificationRequest(
                project_key=key, sbom_id=sbom_id, rule_set_id=rule_id
            ),
        )
        return {
            "scenario": "version-conflict",
            "title": "版本冲突：同一包名 logging-lib 的 1.4.2 与 2.1.0 同时在图中",
            "expectation": (
                "两个版本作为不同 bom-ref 分别核查；仅 2.1.0(AGPL-3.0-only) 违规，"
                "并给出一条最短路径；1.4.2(Apache-2.0) 放行。"
            ),
            "project_key": key,
            "verification": report,
        }
    finally:
        conn.close()


def run_cycle() -> dict[str, Any]:
    key = "demo-cycle"
    conn = _conn()
    try:
        reset_project(conn, key)
        sbom_id, rule_id = _ids(conn, key, fixtures.cycle_sbom())
        report = create_verification(
            conn,
            VerificationRequest(
                project_key=key, sbom_id=sbom_id, rule_set_id=rule_id
            ),
        )
        return {
            "scenario": "circular-dependencies",
            "title": "循环依赖：rule-core↔policy-store、auth-gateway↔token-vault 与自环",
            "expectation": (
                "每个违规组件只出现一次、只给一条不含重复节点的最短简单路径；"
                "环内违规 token-vault 不漏报；compliance-reports 取最短直达路径。"
            ),
            "project_key": key,
            "verification": report,
        }
    finally:
        conn.close()


def run_incremental() -> dict[str, Any]:
    key = "demo-incremental"
    conn = _conn()
    try:
        reset_project(conn, key)
        s1, r1 = _ids(conn, key, fixtures.incremental_v1_sbom())
        first = create_verification(
            conn,
            VerificationRequest(project_key=key, sbom_id=s1, rule_set_id=r1),
        )

        s2_info = save_sbom(conn, key, fixtures.incremental_v2_sbom())
        s2 = s2_info["sbom_id"]
        second = create_verification(
            conn,
            VerificationRequest(project_key=key, sbom_id=s2, rule_set_id=r1),
        )

        r2_info = save_rule_set(
            conn,
            RULES + ["BSD-3-Clause"],
            name="demo-restricted-spdx",
            version_label="demo-v2-add-bsd3",
        )
        r2 = r2_info["rule_set_id"]
        third = create_verification(
            conn,
            VerificationRequest(project_key=key, sbom_id=s2, rule_set_id=r2),
        )

        return {
            "scenario": "incremental-recompute",
            "title": "增量重算：SBOM 修订与规则修订都只重算受影响分支",
            "expectation": (
                "首次 cold 全量；shared-core 变 AGPL 后仅 web/data 两个包含它的"
                "分支及 root-self 重算，standalone 命中缓存；规则新增 BSD-3-Clause "
                "后仅 standalone 分支重算，其余复用。"
            ),
            "project_key": key,
            "steps": [
                {"step": 1, "name": "SBOM v1 首次核查", "verification": first},
                {
                    "step": 2,
                    "name": "SBOM v2：shared-core 升级并改为 AGPL",
                    "verification": second,
                },
                {
                    "step": 3,
                    "name": "规则 v2：新增限制 BSD-3-Clause",
                    "verification": third,
                },
            ],
        }
    finally:
        conn.close()


def run_rollback() -> dict[str, Any]:
    key = "demo-rollback"
    conn = _conn()
    story: list[dict[str, Any]] = []
    try:
        reset_project(conn, key)
        rule_id = save_rule_set(
            conn, RULES, name="demo-restricted-spdx", version_label="demo-v1"
        )["rule_set_id"]
        s1 = save_sbom(conn, key, fixtures.rollback_v1_sbom())["sbom_id"]
        s2 = save_sbom(conn, key, fixtures.rollback_v2_sbom())["sbom_id"]

        # Step 1: publish clean v1.
        bundle_v1 = publish_release(
            conn,
            PublishRequest(project_key=key, sbom_id=s1, rule_set_id=rule_id),
        )
        story.append(
            {
                "step": 1,
                "action": "导入干净 SBOM v1 并发布",
                "result": f"current version = {bundle_v1['version_no']}",
            }
        )

        # Step 2: policy violation blocks v2.
        rejected_report = None
        current_on_reject = None
        try:
            publish_release(
                conn,
                PublishRequest(project_key=key, sbom_id=s2, rule_set_id=rule_id),
            )
        except PolicyRejected as exc:
            rejected_report = exc.report
            current_on_reject = exc.current_version_no
            story.append(
                {
                    "step": 2,
                    "action": "导入含 GPL-3.0-only 的 SBOM v2 并尝试发布",
                    "result": "409 policy_rejected；当前版本保持 "
                    f"v{current_on_reject}",
                }
            )

        # Step 3: simulated operational failure -> transaction rollback.
        failure_error = None
        try:
            publish_release(
                conn,
                PublishRequest(
                    project_key=key,
                    sbom_id=s1,
                    rule_set_id=rule_id,
                    simulate_failure=True,
                ),
            )
        except SimulatedPublishFailure as exc:
            failure_error = str(exc)
            story.append(
                {
                    "step": 3,
                    "action": "带 simulate_failure=true 再次尝试发布",
                    "result": "500 且事务回滚，核查/缓存/版本写入全部撤销",
                }
            )

        current = get_release_bundle(conn, key, None)
        versions = list_release_versions(conn, key)
        attempts = list_attempts(conn, key)
        story.append(
            {
                "step": 4,
                "action": "读取当前发布版本与历史",
                "result": (
                    f"current=v{current['version_no'] if current else None}；"
                    f"published versions={[v['version_no'] for v in versions]}；"
                    f"attempts={[a['outcome'] for a in attempts]}"
                ),
            }
        )

        return {
            "scenario": "publish-failure-rollback",
            "title": "失败回滚：策略拦截与事务故障都保留上一版 v1",
            "expectation": (
                "v2 因许可证违规被拒绝（记录 policy_rejected）；模拟故障的事务"
                "整体回滚（不留 failed 残留）；current 始终是包含输入快照与核查"
                "结果的 v1。"
            ),
            "project_key": key,
            "story": story,
            "policy_rejection": {
                "http_status": 409,
                "current_version_no": current_on_reject,
                "releasable": rejected_report["releasable"]
                if rejected_report
                else None,
                "violating_license_ids": rejected_report["violating_license_ids"]
                if rejected_report
                else None,
                "violations": rejected_report["violations"]
                if rejected_report
                else None,
            },
            "simulated_failure": {
                "http_status": 500,
                "error": failure_error,
                "rolled_back": True,
            },
            "current_release": current,
            "published_versions": versions,
            "publish_attempts": attempts,
            "current_version_no_after": current_version_no(conn, key),
        }
    finally:
        conn.close()
