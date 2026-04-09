"""Request models for the ASR HTTP extension."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


SourceType = Literal[
    "text",
    "html",
    "markdown",
    "pdf_text",
    "retrieval",
    "tool_args",
    "tool_output",
]

ModeType = Literal["enforce", "warn", "shadow"]


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str = Field(..., min_length=1)
    source_type: SourceType = "text"
    source_ref: str | None = None


class DecideRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_name: str = Field(
        ...,
        min_length=1,
        validation_alias=AliasChoices("tool_name", "tool"),
        serialization_alias="tool_name",
    )
    args: dict[str, Any] = Field(default_factory=dict)
    capabilities: list[str] = Field(default_factory=list)
    policy: dict[str, Any] | None = None
    policy_preset: str | None = None
    mode: ModeType | None = None
    pii_profiles: list[str] | None = None


class RedactRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_name: str = Field(
        default="tool_result",
        min_length=1,
        validation_alias=AliasChoices("tool_name", "tool"),
        serialization_alias="tool_name",
    )
    result: Any = Field(
        ...,
        validation_alias=AliasChoices("result", "text"),
        serialization_alias="result",
    )
    policy: dict[str, Any] | None = None
    policy_preset: str | None = None
    mode: ModeType | None = None
    pii_profiles: list[str] | None = None
