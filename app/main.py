"""FastAPI application: CycloneDX license-release verification API.

Open ``/docs`` for Swagger UI: the ``🎬 演示场景`` group contains one-click
scenarios for version conflicts, circular dependencies, incremental
recomputation and publish rollback.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, File, Form, Query, Request, UploadFile
from fastapi.responses import JSONResponse

from . import demo, fixtures
from .cyclonedx import SBOMParseError
from .db import connect, db_path, init_db
from .schemas import PublishRequest, RuleSetRequest, VerificationRequest
from .services import (
    NotFound,
    PolicyRejected,
    SimulatedPublishFailure,
    create_verification,
    current_version_no,
    get_release_bundle,
    list_attempts,
    list_release_versions,
    publish_release,
    save_rule_set,
    save_sbom,
)

DESCRIPTION = """
发布许可证核查服务（FastAPI + SQLite）。

## 它能做什么

1. **导入 CycloneDX SBOM**（JSON / XML）与**受限 SPDX 许可证清单**。
2. 解析依赖图，按 **bom-ref** 区分组件 —— 同一包的不同版本分别核查。
3. 返回：
   - `releasable`：是否可发布；
   - `violating_licenses`：违规许可证及组件；
   - `violations[].path`：每个违规组件**一条最短依赖路径**。
4. 循环依赖通过 visited/BFS 处理：路径不重复、违规不漏报。
5. **增量核查**：SBOM 或规则修订后，只重算签名/规则匹配键受影响的依赖分支，
   响应的 `incremental` 字段列出 `recomputed_branches` 与 `reused_branches`。
6. **发布版本化**：`POST /api/releases` 把核查结果与当时的 SBOM、规则输入
   快照一起发布为不可变版本；策略不通过或发布事务失败时，当前版本仍是上一版。

## 在 /docs 三分钟演示三个关键场景

调用下面 `🎬 演示场景（一键运行）` 分组中的接口即可，无需准备数据：

- `POST /api/demo/version-conflict` —— 同名包两个版本，仅受限版本被判违规。
- `POST /api/demo/cycle` —— 两组循环依赖 + 自环，验证路径唯一、无重复、无漏报。
- `POST /api/demo/rollback` —— v1 发布成功；v2 策略违规被拒；模拟事务故障后
  当前版本仍为 v1，输入快照与核查结果随 v1 一起保留。
- `POST /api/demo/incremental` —— SBOM 修订与规则修订各自只重算受影响分支。

也可以直接在 `POST /api/verifications` / `POST /api/releases` 的
**Request body → Examples** 下拉框选择预填示例试跑。

## 推荐调用顺序

`POST /api/sboms` → `POST /api/rules` → `POST /api/verifications` →
`POST /api/releases` → `GET /api/releases/current`。
"""

@asynccontextmanager
async def lifespan(app: FastAPI):
    conn = connect()
    try:
        init_db(conn)
    finally:
        conn.close()
    yield


app = FastAPI(
    title="License Release Gate API",
    description=DESCRIPTION,
    version="1.0.0",
    lifespan=lifespan,
    openapi_tags=[
        {
            "name": "🎬 演示场景（一键运行）",
            "description": "版本冲突 / 循环依赖 / 失败回滚 / 增量重算",
        },
        {"name": "imports", "description": "导入 CycloneDX SBOM 与 SPDX 规则清单"},
        {"name": "verifications", "description": "许可证核查与增量结果"},
        {"name": "releases", "description": "版本化发布、当前版本与回滚保留"},
        {"name": "meta", "description": "健康检查"},
    ],
)


def get_db():
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


@app.exception_handler(SBOMParseError)
async def sbom_parse_error_handler(request: Request, exc: SBOMParseError):
    return JSONResponse(status_code=422, content={"error": "invalid_sbom", "detail": str(exc)})


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(status_code=422, content={"error": "invalid_input", "detail": str(exc)})


@app.exception_handler(NotFound)
async def not_found_handler(request: Request, exc: NotFound):
    return JSONResponse(status_code=404, content={"error": "not_found", "detail": str(exc)})


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok", "database": db_path()}


@app.get("/", tags=["meta"])
def root() -> dict[str, Any]:
    return {
        "service": "license-release-gate",
        "docs": "/docs",
        "demos": {
            "version_conflict": "/api/demo/version-conflict",
            "circular_dependencies": "/api/demo/cycle",
            "failure_rollback": "/api/demo/rollback",
            "incremental_recompute": "/api/demo/incremental",
        },
        "endpoints": [
            "/api/sboms",
            "/api/rules",
            "/api/verifications",
            "/api/releases",
            "/api/releases/current",
        ],
    }


# ---------------------------------------------------------------------------
# Demo scenarios
# ---------------------------------------------------------------------------


@app.post(
    "/api/demo/version-conflict",
    tags=["🎬 演示场景（一键运行）"],
    summary="演示①：版本冲突（同包不同版本分别核查）",
)
def demo_version_conflict() -> dict[str, Any]:
    return demo.run_version_conflict()


@app.post(
    "/api/demo/cycle",
    tags=["🎬 演示场景（一键运行）"],
    summary="演示②：循环依赖（路径不重复、违规不漏报）",
)
def demo_cycle() -> dict[str, Any]:
    return demo.run_cycle()


@app.post(
    "/api/demo/rollback",
    tags=["🎬 演示场景（一键运行）"],
    summary="演示③：失败回滚（策略拒绝 + 事务故障均保留上一版）",
)
def demo_rollback() -> dict[str, Any]:
    return demo.run_rollback()


@app.post(
    "/api/demo/incremental",
    tags=["🎬 演示场景（一键运行）"],
    summary="演示④：增量重算（SBOM/规则修订只重算受影响分支）",
)
def demo_incremental() -> dict[str, Any]:
    return demo.run_incremental()


# ---------------------------------------------------------------------------
# Import: SBOM
# ---------------------------------------------------------------------------

_SBOM_EXAMPLES = {
    "版本冲突 SBOM": {
        "summary": "同名包 logging-lib 1.4.2 / 2.1.0 共存",
        "value": fixtures.version_conflict_sbom(),
    },
    "循环依赖 SBOM": {
        "summary": "两组循环 + 自环，含环内违规组件",
        "value": fixtures.cycle_sbom(),
    },
    "干净 SBOM v1": {"value": fixtures.rollback_v1_sbom()},
    "违规 SBOM v2": {"value": fixtures.rollback_v2_sbom()},
}


@app.post(
    "/api/sboms",
    tags=["imports"],
    summary="导入 CycloneDX SBOM（JSON 或 XML 原始正文）",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {"examples": _SBOM_EXAMPLES},
                "application/xml": {"schema": {"type": "string"}},
                "text/xml": {"schema": {"type": "string"}},
            },
        }
    },
)
async def import_sbom_raw(
    request: Request,
    project_key: str = Query(default="default", description="项目标识"),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    body = await request.body()
    return save_sbom(conn, project_key, body)


@app.post(
    "/api/sboms/upload",
    tags=["imports"],
    summary="以文件上传方式导入 CycloneDX SBOM",
)
async def import_sbom_upload(
    file: UploadFile = File(..., description=".json 或 .xml CycloneDX SBOM"),
    project_key: str = Form(default="default"),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    body = await file.read()
    return save_sbom(conn, project_key, body)


@app.get("/api/sboms", tags=["imports"], summary="列出项目的 SBOM 修订")
def list_sboms(
    project_key: str = Query(default="default"),
    conn: sqlite3.Connection = Depends(get_db),
):
    rows = conn.execute(
        """
        SELECT id, project_key, revision, format, spec_version,
               content_hash, created_at
          FROM sboms WHERE project_key = ? ORDER BY revision DESC
        """,
        (project_key,),
    ).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/sboms/{sbom_id}", tags=["imports"], summary="查看已解析的 SBOM（含图模型）")
def get_sbom(sbom_id: int, conn: sqlite3.Connection = Depends(get_db)):
    row = conn.execute("SELECT * FROM sboms WHERE id = ?", (sbom_id,)).fetchone()
    if row is None:
        raise NotFound(f"sbom_id {sbom_id} not found")
    return {
        "sbom_id": row["id"],
        "project_key": row["project_key"],
        "revision": row["revision"],
        "format": row["format"],
        "spec_version": row["spec_version"],
        "created_at": row["created_at"],
        "normalized": json.loads(row["normalized_json"]),
    }


# ---------------------------------------------------------------------------
# Import: rules
# ---------------------------------------------------------------------------


@app.post("/api/rules", tags=["imports"], summary="导入受限 SPDX 清单（结构化 JSON）")
def import_rules(
    payload: RuleSetRequest, conn: sqlite3.Connection = Depends(get_db)
):
    return save_rule_set(
        conn,
        payload.licenses,
        name=payload.name,
        version_label=payload.version_label,
    )


@app.post(
    "/api/rules/import",
    tags=["imports"],
    summary="导入原始清单（JSON 数组 / SPDX License List 文档 / 每行一个 ID 的文本）",
)
async def import_rules_raw(
    request: Request,
    name: str = Query(default="restricted-spdx"),
    version_label: str | None = Query(default=None),
    conn: sqlite3.Connection = Depends(get_db),
):
    body = await request.body()
    return save_rule_set(
        conn,
        body,
        name=name,
        version_label=version_label,
        content_type=request.headers.get("content-type", ""),
    )


@app.get("/api/rules", tags=["imports"], summary="列出规则集")
def list_rules(conn: sqlite3.Connection = Depends(get_db)):
    rows = conn.execute(
        "SELECT id, name, version_label, content_hash, created_at FROM rule_sets ORDER BY id DESC"
    ).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/rules/{rule_set_id}", tags=["imports"], summary="查看规则集内容")
def get_rule(rule_set_id: int, conn: sqlite3.Connection = Depends(get_db)):
    row = conn.execute(
        "SELECT * FROM rule_sets WHERE id = ?", (rule_set_id,)
    ).fetchone()
    if row is None:
        raise NotFound(f"rule_set_id {rule_set_id} not found")
    return {
        "rule_set_id": row["id"],
        "name": row["name"],
        "version_label": row["version_label"],
        "created_at": row["created_at"],
        "licenses": json.loads(row["licenses_json"]),
    }


# ---------------------------------------------------------------------------
# Verification examples
# ---------------------------------------------------------------------------

_VERIFY_EXAMPLES = {
    "① 版本冲突（内联，可直接 Execute）": {
        "summary": "同名包两个版本，仅 AGPL 版本违规",
        "value": {
            "project_key": "try-version-conflict",
            "sbom": fixtures.version_conflict_sbom(),
            "licenses": fixtures.RESTRICTED_LICENSES,
        },
    },
    "② 循环依赖（内联，可直接 Execute）": {
        "summary": "循环 + 自环，路径唯一且不漏报",
        "value": {
            "project_key": "try-cycle",
            "sbom": fixtures.cycle_sbom(),
            "licenses": fixtures.RESTRICTED_LICENSES,
        },
    },
    "③ 增量-SBOM修订v1": {
        "summary": "先核查 incremental v1（cold 全量）",
        "value": {
            "project_key": "try-incremental",
            "sbom": fixtures.incremental_v1_sbom(),
            "licenses": fixtures.RESTRICTED_LICENSES,
        },
    },
    "③ 增量-SBOM修订v2": {
        "summary": "同 project 再提交 v2，仅受影响分支重算",
        "value": {
            "project_key": "try-incremental",
            "sbom": fixtures.incremental_v2_sbom(),
            "licenses": fixtures.RESTRICTED_LICENSES,
        },
    },
}


_VERIFY_OPENAPI_EXTRA = {
    "requestBody": {
        "required": True,
        "content": {
            "application/json": {
                "schema": {"$ref": "#/components/schemas/VerificationRequest"},
                "examples": _VERIFY_EXAMPLES,
            }
        },
    }
}


@app.post(
    "/api/verifications",
    tags=["verifications"],
    summary="执行核查（支持内联 SBOM/规则；自动增量）",
    openapi_extra=_VERIFY_OPENAPI_EXTRA,
)
def post_verification(
    payload: VerificationRequest,
    conn: sqlite3.Connection = Depends(get_db),
):
    return create_verification(conn, payload)


# ---------------------------------------------------------------------------
# Releases
# ---------------------------------------------------------------------------

_PUBLISH_EXAMPLES = {
    "发布干净 v1": {
        "summary": "可发布 -> 生成 release version 1",
        "value": {
            "project_key": "try-rollback",
            "sbom": fixtures.rollback_v1_sbom(),
            "licenses": fixtures.RESTRICTED_LICENSES,
        },
    },
    "策略违规（保留上一版）": {
        "summary": "先执行上例得到 v1，再执行此例 -> 409，current 仍为 v1",
        "value": {
            "project_key": "try-rollback",
            "sbom": fixtures.rollback_v2_sbom(),
            "licenses": fixtures.RESTRICTED_LICENSES,
        },
    },
    "模拟发布故障（事务回滚）": {
        "summary": "simulate_failure=true -> 500，所有写入回滚，current 不变",
        "value": {
            "project_key": "try-rollback",
            "sbom": fixtures.rollback_v1_sbom(),
            "licenses": fixtures.RESTRICTED_LICENSES,
            "simulate_failure": True,
        },
    },
}

_PUBLISH_OPENAPI_EXTRA = {
    "requestBody": {
        "required": True,
        "content": {
            "application/json": {
                "schema": {"$ref": "#/components/schemas/PublishRequest"},
                "examples": _PUBLISH_EXAMPLES,
            }
        },
    }
}


@app.post(
    "/api/releases",
    tags=["releases"],
    summary="核查并发布新版本（结果+输入快照；失败保留上一版）",
    openapi_extra=_PUBLISH_OPENAPI_EXTRA,
    responses={
        200: {"description": "已发布，返回包含输入与核查结果的完整版本包"},
        409: {"description": "核查未通过，拒绝发布；当前版本保持不变"},
        500: {"description": "simulate_failure 演示：事务已回滚，上一版保留"},
    },
)
def post_release(
    payload: PublishRequest,
    conn: sqlite3.Connection = Depends(get_db),
):
    project_key = payload.project_key or "default"
    try:
        return publish_release(conn, payload)
    except PolicyRejected as exc:
        return JSONResponse(
            status_code=409,
            content={
                "error": "policy_rejected",
                "detail": "Verification is not releasable; previous release retained",
                "current_version_no": exc.current_version_no,
                "verification": exc.report,
            },
        )
    except SimulatedPublishFailure as exc:
        return JSONResponse(
            status_code=500,
            content={
                "error": "simulated_publish_failure",
                "detail": str(exc),
                "rolled_back": True,
                "current_version_no": current_version_no(conn, project_key),
            },
        )


@app.get(
    "/api/releases/current",
    tags=["releases"],
    summary="获取当前发布版本（含 SBOM+规则输入快照与核查结果）",
)
def get_current_release(
    project_key: str = Query(default="default"),
    conn: sqlite3.Connection = Depends(get_db),
):
    bundle = get_release_bundle(conn, project_key, None)
    if bundle is None:
        raise NotFound(f"no published release for project {project_key!r}")
    return bundle


@app.get("/api/releases", tags=["releases"], summary="列出已发布版本")
def get_releases(
    project_key: str = Query(default="default"),
    conn: sqlite3.Connection = Depends(get_db),
):
    return list_release_versions(conn, project_key)


@app.get(
    "/api/releases/{version_no}",
    tags=["releases"],
    summary="获取指定发布版本包",
)
def get_release(
    version_no: int,
    project_key: str = Query(default="default"),
    conn: sqlite3.Connection = Depends(get_db),
):
    bundle = get_release_bundle(conn, project_key, version_no)
    if bundle is None:
        raise NotFound(
            f"release v{version_no} for project {project_key!r} not found"
        )
    return bundle


@app.get("/api/attempts", tags=["releases"], summary="查看发布尝试记录（含策略拒绝）")
def get_attempts(
    project_key: str = Query(default="default"),
    conn: sqlite3.Connection = Depends(get_db),
):
    return list_attempts(conn, project_key)
