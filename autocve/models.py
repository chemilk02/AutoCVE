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
    GITHUB = "github"  # 비공개 저장소 clone용 PAT
    SLACK = "slack"  # Slack Incoming Webhook URL (URL 자체가 비밀이다)


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
    # 알림 설정: email_to(list), immediate_grade("critical"|"high"), digest(bool)
    notification_settings: Mapped[dict[str, Any]] = mapped_column(default=dict)
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
    last_commit: Mapped[str | None] = mapped_column(String(64))
    last_scan_error: Mapped[str | None] = mapped_column(String(500))
    # 끄면 JEV 판별 요청에 코드 스니펫을 넣지 않고 메타데이터만 보낸다 (§10)
    jev_snippets: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = created_at_column()


class Component(Base):
    """lockfile 안의 설치 위치(locator) 단위로 유지한다.

    버전이 바뀌어도 같은 행을 갱신하므로, 업그레이드로 해소된 Finding을 추적할 수 있다.
    """

    __tablename__ = "components"
    __table_args__ = (
        UniqueConstraint("project_id", "manifest_path", "locator"),
        Index("ix_components_ecosystem_name", "ecosystem", "name"),
    )

    id: Mapped[int] = mapped_column(IdType, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    # npm: package-lock의 경로 키(node_modules/a/node_modules/b), Python: 정규화된 패키지 이름
    locator: Mapped[str] = mapped_column(String(1000))
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
    # GHSA의 심각도 등급(severity: LOW/MODERATE/HIGH/CRITICAL) 등 DB별 부가 정보
    database_specific: Mapped[dict[str, Any]] = mapped_column(default=dict)


class AdvisoryPackage(Base):
    """취약점 → 패키지 역인덱스. 새 취약점이 들어오면 (ecosystem, name)으로 컴포넌트를 찾는다."""

    __tablename__ = "advisory_packages"
    __table_args__ = (Index("ix_advisory_packages_ecosystem_name", "ecosystem", "name"),)

    advisory_id: Mapped[str] = mapped_column(
        ForeignKey("advisories.id", ondelete="CASCADE"), primary_key=True
    )
    ecosystem: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), primary_key=True)


class FeedCursor(Base):
    """피드별 마지막 수집 위치. OSV는 생태계마다 modified 타임스탬프를 저장한다."""

    __tablename__ = "feed_cursors"

    source: Mapped[str] = mapped_column(String(64), primary_key=True)  # 예: osv:npm, epss, kev
    cursor: Mapped[str | None] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


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
    # 점수를 구성한 요소 값 (§6). 화면에서 등급의 이유를 보여주는 데 쓴다.
    risk_factors: Mapped[dict[str, Any]] = mapped_column(default=dict)
    # 마지막으로 알린 시각과 그때의 등급. 등급이 올라가면 다시 알린다.
    notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    notified_grade: Mapped[str | None] = mapped_column(String(16))
    created_at: Mapped[datetime] = created_at_column()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class TriageResult(Base):
    __tablename__ = "triage_results"

    id: Mapped[int] = mapped_column(IdType, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String(16))  # typesafe | openrouter | rules | cache
    model_version: Mapped[str | None] = mapped_column(String(64))
    exposure_probs: Mapped[dict[str, Any]] = mapped_column(default=dict)
    route_probs: Mapped[dict[str, Any]] = mapped_column(default=dict)
    confidence: Mapped[float | None] = mapped_column(Float)
    action: Mapped[str] = mapped_column(String(24))
    # action이 analyze일 때 분석할 모델 등급 (haiku | sonnet | opus)
    route: Mapped[str | None] = mapped_column(String(16))
    reasons: Mapped[list[Any]] = mapped_column(default=list)
    evidence: Mapped[dict[str, Any]] = mapped_column(default=dict)
    audit: Mapped[bool] = mapped_column(Boolean, default=False)
    degraded: Mapped[bool] = mapped_column(Boolean, default=False)
    # 같은 입력이면 판별을 다시 하지 않도록 쓰는 키 (§4.1)
    cache_key: Mapped[str | None] = mapped_column(String(64), index=True)
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


class AnalysisBatch(Base):
    """Batch API로 보낸 경량 분석 묶음. 결과는 워커가 주기적으로 확인해 반영한다."""

    __tablename__ = "analysis_batches"

    id: Mapped[int] = mapped_column(IdType, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"))
    batch_id: Mapped[str] = mapped_column(String(100), unique=True)
    model: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="in_progress")  # in_progress | ended
    # custom_id → finding_id, 분석 캐시 키
    requests: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = created_at_column()
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


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


class FeedbackAction(StrEnum):
    CONFIRM = "confirm"  # 영향 있음 확인 (수용)
    NOT_AFFECTED = "not_affected"  # 해당 없음 (사유 필수)
    FIXED = "fixed"  # 수정 완료
    REOPEN = "reopen"


class Feedback(Base):
    """사용자 처리 기록. 판정과 다르면 JEV 임계값 보정과 평가(M5)에 쓴다."""

    __tablename__ = "feedback"

    id: Mapped[int] = mapped_column(IdType, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    user_verdict: Mapped[str] = mapped_column(String(24))  # FeedbackAction
    reason: Mapped[str | None] = mapped_column(Text)
    # 처리 시점의 시스템 판정. 사용자가 판정을 뒤집었는지 계산할 때 쓴다.
    system_verdict: Mapped[str | None] = mapped_column(String(24))
    created_at: Mapped[datetime] = created_at_column()


class NotificationLog(Base):
    __tablename__ = "notification_log"

    id: Mapped[int] = mapped_column(IdType, primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"))
    channel: Mapped[str] = mapped_column(String(16))  # slack | email
    kind: Mapped[str] = mapped_column(String(16))  # immediate | digest | test
    finding_ids: Mapped[list[Any]] = mapped_column(default=list)
    ok: Mapped[bool] = mapped_column(Boolean)
    error: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = created_at_column()
