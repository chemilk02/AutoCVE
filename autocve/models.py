"""DB 스키마. 설명은 docs/02-architecture.md §7을 따른다.

PostgreSQL에서는 jsonb를, 테스트용 SQLite에서는 JSON을 쓰도록 타입 변형을 둔다.
"""

from datetime import date, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

JsonType = JSON().with_variant(JSONB(), "postgresql")
IdType = BigInteger().with_variant(Integer(), "sqlite")


class Provider(StrEnum):
    ANTHROPIC = "anthropic"
    TYPESAFE = "typesafe"
    OPENROUTER = "openrouter"


JEV_PROVIDERS = (Provider.TYPESAFE, Provider.OPENROUTER)


class JevProvider(StrEnum):
    NONE = "none"
    TYPESAFE = Provider.TYPESAFE.value
    OPENROUTER = Provider.OPENROUTER.value


class CredentialStatus(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    UNVERIFIED = "unverified"  # 네트워크 오류 등으로 검증하지 못함


class FindingStatus(StrEnum):
    NEW = "new"
    TRIAGED = "triaged"
    ANALYZING = "analyzing"
    ANALYZED = "analyzed"
    NOTIFIED = "notified"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"
    UNANALYZED = "unanalyzed"  # 예산 소진
    ANALYSIS_REFUSED = "analysis_refused"


class Verdict(StrEnum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNCERTAIN = "uncertain"


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JsonType, list[Any]: JsonType}


def created_at_column() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now())


class Workspace(Base):
    __tablename__ = "workspaces"

    id: Mapped[int] = mapped_column(IdType, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    monthly_budget_usd: Mapped[Decimal | None] = mapped_column(Numeric(10, 2))
    model_settings: Mapped[dict[str, Any]] = mapped_column(default=dict)
    jev_provider: Mapped[str] = mapped_column(String(16), default=JevProvider.NONE)
    jev_model: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = created_at_column()

    credentials: Mapped[list["ApiCredential"]] = relationship(
        back_populates="workspace", cascade="all, delete-orphan"
    )


class ApiCredential(Base):
    __tablename__ = "api_credentials"
    __table_args__ = (UniqueConstraint("workspace_id", "provider"),)

    id: Mapped[int] = mapped_column(IdType, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String(16))
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    key_id: Mapped[str] = mapped_column(String(16))  # 마스터 키 교체 시 구분용
    last4: Mapped[str] = mapped_column(String(4))
    status: Mapped[str] = mapped_column(String(16))
    status_message: Mapped[str | None] = mapped_column(String(255))
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    workspace: Mapped[Workspace] = relationship(back_populates="credentials")


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("workspace_id", "repo_url"),)

    id: Mapped[int] = mapped_column(IdType, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(200))
    repo_url: Mapped[str] = mapped_column(String(500))
    default_branch: Mapped[str | None] = mapped_column(String(200))
    # internet: prod 인터넷 노출, internal: prod 내부, dev: 개발 전용
    exposure: Mapped[str] = mapped_column(String(16), default="internet")
    scan_schedule: Mapped[str] = mapped_column(String(32), default="daily")
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_column()


class Component(Base):
    __tablename__ = "components"
    __table_args__ = (
        UniqueConstraint("project_id", "purl", "manifest_path"),
        Index("ix_components_ecosystem_name", "ecosystem", "name"),
    )

    id: Mapped[int] = mapped_column(IdType, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    purl: Mapped[str] = mapped_column(String(512))
    ecosystem: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(100))
    direct: Mapped[bool] = mapped_column(Boolean)
    scope: Mapped[str] = mapped_column(String(8))  # prod | dev
    manifest_path: Mapped[str] = mapped_column(String(500))


class CodeFile(Base):
    __tablename__ = "code_files"
    __table_args__ = (UniqueConstraint("project_id", "path"),)

    id: Mapped[int] = mapped_column(IdType, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    path: Mapped[str] = mapped_column(String(1000))
    sha256: Mapped[str] = mapped_column(String(64))
    imports: Mapped[list[Any]] = mapped_column(default=list)
    is_test: Mapped[bool] = mapped_column(Boolean, default=False)


class Advisory(Base):
    __tablename__ = "advisories"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # OSV id
    aliases: Mapped[list[Any]] = mapped_column(default=list)
    modified: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    withdrawn: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    summary: Mapped[str | None] = mapped_column(Text)
    details: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[list[Any]] = mapped_column(default=list)
    affected: Mapped[list[Any]] = mapped_column(default=list)
    references: Mapped[list[Any]] = mapped_column(default=list)


class AdvisoryPackage(Base):
    """취약점 → 패키지 역인덱스. 새 취약점이 들어오면 (ecosystem, name)으로 컴포넌트를 찾는다."""

    __tablename__ = "advisory_packages"
    __table_args__ = (Index("ix_advisory_packages_ecosystem_name", "ecosystem", "name"),)

    advisory_id: Mapped[str] = mapped_column(
        ForeignKey("advisories.id", ondelete="CASCADE"), primary_key=True
    )
    ecosystem: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), primary_key=True)


class ExploitSignal(Base):
    __tablename__ = "exploit_signals"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    epss: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    epss_date: Mapped[date | None] = mapped_column(Date)
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_date_added: Mapped[date | None] = mapped_column(Date)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AdvisoryProfile(Base):
    __tablename__ = "advisory_profiles"
    __table_args__ = (
        UniqueConstraint("workspace_id", "advisory_id", "advisory_modified", "prompt_version"),
    )

    id: Mapped[int] = mapped_column(IdType, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"))
    advisory_id: Mapped[str] = mapped_column(ForeignKey("advisories.id", ondelete="CASCADE"))
    advisory_modified: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    prompt_version: Mapped[str] = mapped_column(String(32))
    profile: Mapped[dict[str, Any]] = mapped_column(default=dict)
    incomplete: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = created_at_column()


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("component_id", "advisory_id"),)

    id: Mapped[int] = mapped_column(IdType, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    component_id: Mapped[int] = mapped_column(ForeignKey("components.id", ondelete="CASCADE"))
    advisory_id: Mapped[str] = mapped_column(ForeignKey("advisories.id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(String(24), default=FindingStatus.NEW)
    verdict: Mapped[str | None] = mapped_column(String(24))
    risk_score: Mapped[float | None] = mapped_column(Float)
    grade: Mapped[str | None] = mapped_column(String(16))
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class TriageResult(Base):
    __tablename__ = "triage_results"

    id: Mapped[int] = mapped_column(IdType, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String(16))  # typesafe | openrouter | rules
    model_version: Mapped[str | None] = mapped_column(String(64))
    exposure_probs: Mapped[dict[str, Any]] = mapped_column(default=dict)
    route_probs: Mapped[dict[str, Any]] = mapped_column(default=dict)
    confidence: Mapped[float | None] = mapped_column(Float)
    action: Mapped[str] = mapped_column(String(24))
    degraded: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = created_at_column()


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(IdType, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    model: Mapped[str] = mapped_column(String(64))
    verdict: Mapped[str] = mapped_column(String(24))
    confidence: Mapped[float | None] = mapped_column(Float)
    rationale: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[list[Any]] = mapped_column(default=list)
    cache_key: Mapped[str] = mapped_column(String(128), index=True)
    created_at: Mapped[datetime] = created_at_column()


class LlmUsage(Base):
    __tablename__ = "llm_usage"
    __table_args__ = (Index("ix_llm_usage_workspace_created", "workspace_id", "created_at"),)

    id: Mapped[int] = mapped_column(IdType, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String(16))
    model: Mapped[str] = mapped_column(String(64))
    stage: Mapped[str] = mapped_column(String(16))  # profile | jev | haiku | sonnet | opus
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))
    batch: Mapped[bool] = mapped_column(Boolean, default=False)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cache_creation_input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cache_read_input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[Decimal] = mapped_column(Numeric(12, 6), default=Decimal(0))
    created_at: Mapped[datetime] = created_at_column()


class Feedback(Base):
    __tablename__ = "feedback"

    id: Mapped[int] = mapped_column(IdType, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    user_verdict: Mapped[str] = mapped_column(String(24))
    reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = created_at_column()
