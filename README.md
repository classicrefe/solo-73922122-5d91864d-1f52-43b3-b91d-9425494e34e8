# License Release Gate

用 **FastAPI + SQLite** 实现的发布许可证核查服务：导入 **CycloneDX SBOM**
与**受限 SPDX 许可证清单**，解析依赖图，回答发布工程师的三个问题：

1. 这次构建产物**是否可发布**（`releasable`）；
2. 哪些**许可证违规**、分别涉及哪些组件；
3. 每个违规组件的**一条最短依赖路径**。

并支持：同包不同版本分别核查、循环依赖安全遍历、SBOM/规则修订后的
**分支级增量重算**、核查结果与输入快照一起**版本化发布**、失败时**保留上一版**。

---

## 1. 快速开始

### Docker Compose（推荐）

```bash
docker compose up --build
# API + Swagger 文档：
#   http://localhost:8000/docs
```

SQLite 数据库保存在命名卷 `license-gate-data` 的 `/data/license_check.db`。

在容器镜像内运行自测：

```bash
docker compose --profile test run --rm tests
```

### 本地虚拟环境

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
LICENSE_CHECK_DB=data/license_check.db \
  .venv/bin/uvicorn app.main:app --reload --port 8000
```

运行测试与冒烟脚本：

```bash
.venv/bin/python -m pytest -q
.venv/bin/python scripts/smoke_test.py http://127.0.0.1:8000
```

---

## 2. 在 `/docs` 演示三个规定场景

打开 <http://localhost:8000/docs>：

### 🎬 一键演示（无需准备数据）

`🎬 演示场景（一键运行）` 分组下，对每个接口点 **Try it out → Execute**：

| 接口 | 场景 | 预期 |
| --- | --- | --- |
| `POST /api/demo/version-conflict` | **版本冲突** | `logging-lib@1.4.2`(Apache-2.0) 与 `@2.1.0`(AGPL) 同时存在；两个 bom-ref 分别核查，仅 2.1.0 违规并给出路径 |
| `POST /api/demo/cycle` | **循环依赖** | `rule-core↔policy-store`、`auth-gateway↔token-vault` 与一个自环；2 个违规组件各出现一次，路径无重复节点，环内 `token-vault` 不漏报 |
| `POST /api/demo/rollback` | **失败回滚** | v1 发布成功 → v2 含 GPL 被 `409` 拒绝 → `simulate_failure=true` 触发 `500` 且事务回滚；当前版本始终是包含输入快照与核查结果的 v1 |
| `POST /api/demo/incremental` | **增量重算**（附加） | cold 全量 → SBOM 修订只重算 3 个受影响单元 → 规则新增 BSD-3 后只重算 1 个分支 |

### 请求体示例下拉

`POST /api/verifications` 与 `POST /api/releases` 的 **Request body →
Examples** 内置了“版本冲突 / 循环依赖 / 增量 v1/v2 / 发布干净版 / 策略违规 /
模拟故障”等预填 JSON，可直接 Execute（内联 SBOM 与许可证清单会先自动导入）。

---

## 3. 典型调用流程（curl + 仓库内示例）

```bash
# 1) 导入受限 SPDX 清单（JSON 数组、SPDX License List 文档或每行一个 ID 的文本均可）
curl -X POST "http://localhost:8000/api/rules" \
  -H 'Content-Type: application/json' \
  -d '{"name":"release-restricted","version_label":"2026.11",
       "licenses":["GPL-3.0-only","AGPL-3.0-only","SSPL-1.0"]}'

# 或导入原始文件
curl -X POST "http://localhost:8000/api/rules/import?name=restricted" \
  -H 'Content-Type: text/plain' \
  --data-binary @examples/restricted-spdx.txt

# 2) 导入 CycloneDX SBOM（JSON / XML 原始正文，或 /api/sboms/upload 表单文件）
curl -X POST "http://localhost:8000/api/sboms?project_key=shop" \
  -H 'Content-Type: application/json' \
  --data-binary @examples/sbom-version-conflict.json

# 3) 核查（不传 sbom_id/rule_set_id 时使用项目最新 SBOM 与最新规则集）
curl -X POST http://localhost:8000/api/verifications \
  -H 'Content-Type: application/json' \
  -d '{"project_key":"shop"}'

# 4) 核查并发布；违规返回 409，当前发布版本不变
curl -X POST http://localhost:8000/api/releases \
  -H 'Content-Type: application/json' \
  -d '{"project_key":"shop"}'

# 5) 读取当前发布版本（含 SBOM+规则输入快照与核查结果）
curl "http://localhost:8000/api/releases/current?project_key=shop"
```

`examples/` 目录提供：

- `sbom-version-conflict.json` —— 同包两版本；
- `sbom-cycle.json` —— 循环依赖 + 自环；
- `sbom-rollback-v1-clean.json` / `sbom-rollback-v2-violating.json` —— 回滚；
- `sbom-incremental-v1.json` / `v2.json` —— 共享依赖变更；
- `sbom-minimal.xml` —— CycloneDX XML 示例；
- `restricted-spdx.json` / `.txt` —— 受限清单。

---

## 4. 核查响应结构（节选）

```jsonc
{
  "releasable": false,
  "summary": {
    "component_count": 8,
    "violation_component_count": 2,
    "recomputed_unit_count": 4,
    "reused_unit_count": 0
  },
  "violating_license_ids": ["AGPL-3.0-only", "GPL-3.0-only"],
  "violating_licenses": [
    {"license": "AGPL-3.0-only", "component_count": 1,
     "component_refs": ["pkg:npm/token-vault@2.2.0"]}
  ],
  "violations": [
    {
      "ref": "pkg:npm/token-vault@2.2.0",
      "name": "token-vault", "version": "2.2.0",
      "violating_licenses": ["AGPL-3.0-only"],
      "reachable": true,
      "path": {
        "length_edges": 2,
        "branch_key": "pkg:npm/auth-gateway@4.0.0",
        "bom_refs": ["...order-service@1.0.0", "...auth-gateway@4.0.0", "...token-vault@2.2.0"],
        "nodes": [ {"bom_ref": "...", "name": "order-service", "version": "1.0.0"} ]
      }
    }
  ],
  "incremental": {
    "mode": "cold | incremental | cached",
    "recomputed_branches": [{"branch_key": "...", "reason": "...", "impacted_by_refs": []}],
    "reused_branches": [{"branch_key": "...", "reason": "cache_hit | unaffected_by_rules_or_policy_revision"}]
  }
}
```

SBOM 中列出但从根不可达的组件仍会被核查，返回 `"reachable": false,
"path": null`，避免漏报。

---

## 5. 关键设计

### 5.1 身份与版本

节点身份是唯一的 CycloneDX `bom-ref`。`logging-lib@1.4.2` 与
`logging-lib@2.1.0` 是两个节点、两条路径、两个核查结论。重复但冲突的
`bom-ref`（同一 `components` 数组内）返回 `422`；`metadata.component` 与
`components` 中同 ref 的常见写法会合并许可证并给出 warning。

### 5.2 最短路径与循环依赖

- 以根的每个直接依赖弧划分**依赖分支**，分支内做 BFS；BFS 首次访问即最短。
- visited/parent map 使循环必然终止，父链深度严格递减，因此还原出的路径
  **不含重复节点**。
- 合并各分支候选时按 `(边数, 路径, branch_key)` 取唯一最优，保证每个违规
  bom-ref **恰好一条全局最短路径**；并列时结果确定。
- 测试用 40 个随机有环图对照独立 BFS oracle，校验覆盖率、路径最短性与简单性。

### 5.3 SPDX 匹配与表达式

- 精确 SPDX ID 匹配；对 GPL/LGPL/AGPL 的弃用裸 ID 与 `-only` /
  `-or-later` / `+` 做保守族匹配（规则 `GPL-3.0-only` 也覆盖
  `GPL-3.0-or-later`）。
- 支持 `AND` / `OR` / `WITH` / 括号。`OR` 按双许可选择语义：只有所有备选
  都受限才判违规；`AND` 任一受限即违规。
- 非 SPDX 的自由文本许可证名称进入 `unresolved_licenses`；
  `strict_unknown=true` 时这些组件也会阻止发布。

### 5.4 增量重算

每个项目（`project_key`）在 SQLite `branch_cache` 中保存各分支单元的：

- 分支可达闭包内全部组件载荷 + 边的规范哈希 `signature`；
- 能影响结论的 SPDX/名称匹配键集合；
- 上次核查结果。

判定：

- 无缓存 → `cold` 全量；
- SBOM 修订导致 `signature` 变化 → **仅该分支重算**，并通过前后 SBOM
  diff 给出 `impacted_by_refs`；共享依赖变更会精确波及所有包含它的分支；
- 规则修订 → 计算新旧规则匹配键的对称差，**仅许可证键与翻转集合相交的
  分支重算**，其余直接复用旧结论并改盖新 rule_set 戳；
- `strict_unknown` 翻转时仅重算含未解析许可证的分支；
- 不可达组件以 `__orphan__::<bom-ref>` 为独立缓存单元。

### 5.5 发布与回滚

`release_versions` 保存不可变版本包：精确的 SBOM 原始正文、规则清单快照与
完整核查报告。

- 核查通过：同一事务内写核查记录 + release 版本，版本号递增并成为 current；
- 核查不通过：提交一条 `policy_rejected` 尝试记录，但**不写新版本**，
  `409` 响应带回完整报告与 `current_version_no`；
- `simulate_failure=true`：在写库之后、提交之前抛错，整个事务
  `ROLLBACK`（核查、缓存、版本均不留残），接口返回 `500` 与回滚后的当前版本；
- 所有历史版本保留，`GET /api/releases/{version_no}` 可取回任意一版。

---

## 6. 目录结构

```
app/
  main.py         # FastAPI 路由、OpenAPI /docs 示例、异常处理
  config via env  # LICENSE_CHECK_DB（默认 data/license_check.db）
  db.py           # sqlite 连接、schema、显式事务
  cyclonedx.py    # CycloneDX JSON/XML 解析与规范化
  spdx.py         # 规则清单导入、SPDX 匹配与表达式求值
  graph.py        # 图、分支闭包/签名、BFS、SBOM diff
  verifier.py     # 增量决策、许可证判定、路径合并
  services.py     # 导入/核查/发布/回滚用例与仓储 SQL
  demo.py         # 四个一键演示场景
  fixtures.py     # 演示/测试共用固件
  schemas.py      # 请求模型
tests/            # 30 个 pytest 用例（含随机图 oracle）
scripts/smoke_test.py
examples/
Dockerfile
docker-compose.yml
```

---

## 7. 完成情况说明

### 已实现

- CycloneDX JSON + XML 导入、校验、悬空引用占位与 warning、幂等去重；
- 受限 SPDX 清单多格式导入；SPDX 表达式与族匹配；
- 依赖图解析、多根支持、最短路径、循环/自环安全、每组件一条路径；
- 同包不同版本按 bom-ref 分别核查；不可达组件兜底核查；
- 分支级增量缓存（SBOM 修订、规则修订、strict 策略修订），响应明示
  重算/复用单元及原因；
- 核查结果 + SBOM/规则输入快照的不可变发布版本；策略拒绝与事务故障两条
  回滚路径；发布尝试审计；
- `/docs` 中文说明、请求示例与四个一键演示接口；
- Dockerfile + docker-compose（api 卷持久化、healthcheck、tests profile）；
- pytest 套件与零依赖冒烟脚本。

### 已验证（本环境实际执行）

- `.venv/bin/python -m pytest -q`：**30 passed**；
- 真实 uvicorn 进程 + HTTP 冒烟脚本：**21 项全部通过**；
- 版本冲突 / 循环 / 增量 / 回滚四个演示接口实测输出符合预期；
- 第二个服务进程打开同一 SQLite 文件：发布版本可读、增量缓存为 `cached`，
  证明重启/跨进程持久化；
- XML 上传、纯文本规则导入实测通过；
- `docker-compose.yml` 通过 YAML 解析校验。

### 未完成 / 受限项

- 当前环境**没有 Docker CLI/守护进程，也无 root**，因此**镜像 build 与
  `docker compose up` 未在本机实跑验证**；Dockerfile 基于标准
  `python:3.11-slim`，依赖已固定在 `requirements.txt`，compose 配置仅做了
  语法校验。
- `/docs` 的 Swagger JS/CSS 走 jsDelivr CDN（FastAPI 默认）；离线浏览器需
  自行托管静态资源，API 与 `/openapi.json` 本身不依赖 CDN。
- SPDX 匹配未内置完整 SPDX ID 合法性词表，因此“无法识别的 ID”不做合法性
  报错，只对自由文本许可证名称提供 unresolved/strict 处理。
- 未实现 CycloneDX 之外的 SBOM 标准（SPDX SBOM）与 XML 之外的签名校验。
