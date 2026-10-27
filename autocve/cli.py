"""운영용 CLI. 워커를 기다리지 않고 수집·스캔을 바로 돌릴 때 쓴다.

python -m autocve.cli sync-feeds [--ecosystem npm]
python -m autocve.cli sync-exploits
python -m autocve.cli add-project NAME URL [--branch main] [--exposure internet]
python -m autocve.cli scan PROJECT_ID
python -m autocve.cli findings PROJECT_ID
"""

import argparse
import json
import logging
import sys

from sqlalchemy import select

from autocve import pipeline
from autocve.config import get_settings
from autocve.credentials.service import get_or_create_default_workspace
from autocve.db import make_engine, make_session_factory
from autocve.ecosystems import SUPPORTED
from autocve.inventory.repo import RepoError, validate_repo_url
from autocve.matcher.matcher import match_components
from autocve.models import Advisory, Component, Finding, Project
from autocve.security.keyvault import KeyVault
from autocve.security.redaction import install_log_redaction

EXPOSURES = ("internet", "internal", "dev")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="autocve")
    sub = parser.add_subparsers(dest="command", required=True)
    feeds = sub.add_parser("sync-feeds", help="OSV 수집 후 매칭")
    feeds.add_argument("--ecosystem", choices=SUPPORTED, action="append")
    sub.add_parser("sync-exploits", help="EPSS, KEV 갱신")
    add = sub.add_parser("add-project", help="저장소 등록")
    add.add_argument("name")
    add.add_argument("url")
    add.add_argument("--branch")
    add.add_argument("--exposure", choices=EXPOSURES, default="internet")
    scan = sub.add_parser("scan", help="저장소 스캔 → 매칭 → 판별")
    scan.add_argument("project_id", type=int)
    sub.add_parser("collect-batches", help="끝난 Batch API 분석 결과 반영")
    notify = sub.add_parser("notify", help="즉시 알림 보내기 (--digest: 일일 요약)")
    notify.add_argument("--digest", action="store_true")
    triage = sub.add_parser("triage", help="판별·분석 대기 Finding 처리 (저장소를 다시 clone)")
    triage.add_argument("project_id", type=int)
    sub.add_parser("rematch", help="모든 컴포넌트를 취약점 DB와 다시 대조")
    findings = sub.add_parser("findings", help="후보 Finding 목록")
    findings.add_argument("project_id", type=int)
    args = parser.parse_args(argv)

    settings = get_settings()
    logging.basicConfig(level=settings.log_level, format="%(levelname)s %(name)s: %(message)s")
    install_log_redaction()
    factory = make_session_factory(make_engine(settings.database_url))

    with factory() as session:
        if args.command == "sync-feeds":
            with pipeline.http_client() as http:
                summary = pipeline.sync_feeds(
                    session, http, settings, tuple(args.ecosystem or SUPPORTED)
                )
            print(json.dumps(summary.__dict__, ensure_ascii=False))
        elif args.command == "sync-exploits":
            with pipeline.http_client() as http:
                print(json.dumps(pipeline.sync_exploit_signals(session, http, settings)))
        elif args.command == "add-project":
            try:
                url = validate_repo_url(args.url)
            except RepoError as e:
                print(e, file=sys.stderr)
                return 2
            workspace = get_or_create_default_workspace(session)
            project = Project(
                workspace_id=workspace.id,
                name=args.name,
                repo_url=url,
                default_branch=args.branch,
                exposure=args.exposure,
            )
            session.add(project)
            session.commit()
            print(project.id)
        elif args.command == "scan":
            project = session.get(Project, args.project_id)
            if project is None:
                print("프로젝트가 없습니다", file=sys.stderr)
                return 1
            vault = KeyVault.from_b64(settings.master_key.get_secret_value())
            try:
                with pipeline.http_client() as http:
                    summary = pipeline.scan_and_match(session, project, vault, settings, http=http)
            except RepoError as e:
                print(e, file=sys.stderr)
                return 1
            print(json.dumps(summary.__dict__, ensure_ascii=False))
        elif args.command == "triage":
            project = session.get(Project, args.project_id)
            if project is None:
                print("프로젝트가 없습니다", file=sys.stderr)
                return 1
            vault = KeyVault.from_b64(settings.master_key.get_secret_value())
            try:
                with pipeline.http_client() as http:
                    result = pipeline.triage_project(session, project, vault, settings, http=http)
            except RepoError as e:
                print(e, file=sys.stderr)
                return 1
            print(json.dumps(result, ensure_ascii=False))
        elif args.command == "collect-batches":
            vault = KeyVault.from_b64(settings.master_key.get_secret_value())
            print(json.dumps(pipeline.collect_analysis_batches(session, vault), default=str))
        elif args.command == "notify":
            vault = KeyVault.from_b64(settings.master_key.get_secret_value())
            print(json.dumps(pipeline.notify_all(session, vault, settings, digest=args.digest)))
        elif args.command == "rematch":
            result = match_components(session, session.scalars(select(Component)).all())
            print(json.dumps({"created": len(result.created), "resolved": len(result.resolved)}))
        elif args.command == "findings":
            rows = session.execute(
                select(Finding, Component, Advisory)
                .join(Component, Component.id == Finding.component_id)
                .join(Advisory, Advisory.id == Finding.advisory_id)
                .where(Finding.project_id == args.project_id)
                .order_by(Component.name, Advisory.id)
            )
            for finding, component, advisory in rows:
                print(
                    f"{finding.status:10} {advisory.id:22} {component.name}@{component.version}"
                    f" [{component.scope}{', direct' if component.direct else ''}]"
                    f" {advisory.summary or ''}"
                )
    return 0


if __name__ == "__main__":
    sys.exit(main())
