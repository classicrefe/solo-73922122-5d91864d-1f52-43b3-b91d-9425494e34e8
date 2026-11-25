"""Pydantic request models (response payloads are documented via examples)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class RuleSetRequest(BaseModel):
    name: str = Field(default="restricted-spdx", description="规则清单名称")
    version_label: str | None = Field(
        default=None, description="规则版本标签，例如 2026-11-01"
    )
    licenses: list[str] = Field(
        ..., description="受限 SPDX 标识符数组", min_length=1
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "name": "release-restricted",
                "version_label": "2026.11",
                "licenses": ["GPL-3.0-only", "AGPL-3.0-only", "SSPL-1.0"],
            }
        }
    }


class _VerificationFields(BaseModel):
    project_key: str = Field(
        default="default", description="产品/项目标识，SBOM 修订与增量缓存按此隔离"
    )
    sbom_id: int | None = Field(
        default=None, description="已导入 SBOM 的 ID；留空则使用该项目最新修订"
    )
    rule_set_id: int | None = Field(
        default=None, description="已导入规则集 ID；留空则使用最新规则集"
    )
    strict_unknown: bool = Field(
        default=False,
        description="为 true 时，无法解析为 SPDX 的许可证声明也会阻止发布",
    )
    sbom: dict[str, Any] | None = Field(
        default=None,
        description="内联 CycloneDX JSON；提供时会先导入，便于在 /docs 直接试跑",
    )
    licenses: list[str] | None = Field(
        default=None, description="内联受限 SPDX 清单；提供时会先导入"
    )
    rule_name: str | None = None
    rule_version: str | None = None


class VerificationRequest(_VerificationFields):
    pass


class PublishRequest(_VerificationFields):
    simulate_failure: bool = Field(
        default=False,
        description=(
            "演示用：在同一事务内、提交前抛出故障，验证全部写入回滚且上一版保留"
        ),
    )
