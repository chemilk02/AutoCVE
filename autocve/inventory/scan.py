"""프로젝트 스캔: clone → lockfile 파싱 → 컴포넌트 갱신 → 코드 인덱스 갱신.

컴포넌트와 코드 파일은 지우고 다시 넣지 않고 차이만 반영한다.
Finding이 컴포넌트를 참조하므로, 다시 넣으면 기존 판정 이력이 사라지기 때문이다.
"""

import logging
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from autocve.ecosystems import purl
from autocve.inventory import repo
from autocve.inventory.code_index import IndexedFile, index_repository
from autocve.inventory.parsers import Dependency, ParseError, find_manifests, parse_manifest
from autocve.models import CodeFile, Component, Project

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    commit: str | None = None
    changed_components: list[Component] = field(default_factory=list)
    removed_components: int = 0
    total_components: int = 0
    indexed_files: int = 0
    manifest_errors: list[str] = field(default_factory=list)


def collect_dependencies(root: Path) -> tuple[dict[tuple[str, str], Dependency], list[str]]:
    deps: dict[tuple[str, str], Dependency] = {}
    errors = []
    for manifest in find_manifests(root):
        rel = manifest.relative_to(root).as_posix()
        try:
            parsed = parse_manifest(root, manifest)
        except ParseError as e:
            errors.append(f"{rel}: {e}")
            continue
        for dep in parsed:
            deps[(rel, dep.locator)] = dep
    return deps, errors


def sync_components(
    session: Session, project: Project, deps: dict[tuple[str, str], Dependency]
) -> tuple[list[Component], int]:
    existing = {
        (c.manifest_path, c.locator): c
        for c in session.scalars(select(Component).where(Component.project_id == project.id))
    }
    changed: list[Component] = []
    for (manifest, locator), dep in deps.items():
        component = existing.pop((manifest, locator), None)
        values = {
            "ecosystem": dep.ecosystem,
            "name": dep.name,
            "version": dep.version,
            "purl": purl(dep.ecosystem, dep.name, dep.version),
            "direct": dep.direct,
            "scope": dep.scope,
        }
        if component is None:
            component = Component(
                project_id=project.id, manifest_path=manifest, locator=locator, **values
            )
            session.add(component)
            changed.append(component)
        elif any(getattr(component, k) != v for k, v in values.items()):
            for key, value in values.items():
                setattr(component, key, value)
            changed.append(component)
    for gone in existing.values():
        session.delete(gone)
    session.flush()
    return changed, len(existing)


def sync_code_files(session: Session, project: Project, files: list[IndexedFile]) -> None:
    existing = {
        f.path: f
        for f in session.scalars(select(CodeFile).where(CodeFile.project_id == project.id))
    }
    for indexed in files:
        row = existing.pop(indexed.path, None)
        if row is None:
            session.add(
                CodeFile(
                    project_id=project.id,
                    path=indexed.path,
                    sha256=indexed.sha256,
                    imports=indexed.imports,
                    is_test=indexed.is_test,
                )
            )
        elif row.sha256 != indexed.sha256 or row.is_test != indexed.is_test:
            row.sha256 = indexed.sha256
            row.imports = indexed.imports
            row.is_test = indexed.is_test
    for gone in existing.values():
        session.delete(gone)


def scan_checkout(session: Session, project: Project, root: Path, commit: str | None) -> ScanResult:
    deps, errors = collect_dependencies(root)
    changed, removed = sync_components(session, project, deps)
    files = index_repository(root)
    sync_code_files(session, project, files)
    project.last_commit = commit
    project.last_scanned_at = datetime.now(UTC)
    project.last_scan_error = "; ".join(errors)[:500] if errors else None
    session.commit()
    return ScanResult(
        commit=commit,
        changed_components=changed,
        removed_components=removed,
        total_components=len(deps),
        indexed_files=len(files),
        manifest_errors=errors,
    )


@contextmanager
def checked_out(
    session: Session,
    project: Project,
    *,
    token: str | None = None,
    workdir: str | None = None,
    allow_local: bool = False,
) -> Iterator[tuple[Path, str]]:
    """저장소를 임시 디렉터리에 clone해 (경로, 커밋)을 넘기고, 블록이 끝나면 코드를 지운다."""
    tmp = Path(tempfile.mkdtemp(prefix="autocve-scan-", dir=workdir))
    try:
        root = tmp / "repo"
        try:
            commit = repo.clone(
                project.repo_url,
                root,
                branch=project.default_branch,
                token=token,
                allow_local=allow_local,
            )
        except repo.RepoError as e:
            project.last_scan_error = str(e)[:500]
            session.commit()
            raise
        yield root, commit
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def log_scan(project: Project, result: ScanResult) -> None:
    logger.info(
        "프로젝트 %s 스캔: 컴포넌트 %d개(변경 %d, 삭제 %d), 코드 파일 %d개",
        project.id,
        result.total_components,
        len(result.changed_components),
        result.removed_components,
        result.indexed_files,
    )
