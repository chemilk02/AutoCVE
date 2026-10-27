# AutoCVE

공개 취약점 DB(OSV, EPSS, CISA KEV)를 주기적으로 수집합니다. 새 취약점이 연결된 저장소에 실제로 영향을 주는지 판별하고, 근거와 위험도를 알려주는 서비스입니다.

- **판별 우선**: 저비용 판별 모델 JEV가 먼저 위험 여부와 분석 모델(없음/Haiku/Sonnet/Opus)을 정합니다. Claude는 근거가 필요한 경우에만 호출합니다.
- **BYOK**: 사용자 본인의 Anthropic API 키(필수)와 JEV 키(선택)를 사용합니다. JEV는 TypeSafe에 직접 호출하거나 OpenRouter를 거쳐 호출할 수 있습니다.

## 문서

- [MVP 범위](docs/01-mvp-scope.md)
- [아키텍처](docs/02-architecture.md)

## 상태

- M0(기반) 완료: 저장소 골격, DB 스키마, Docker Compose, API 키 저장소
- M1(데이터) 완료: OSV/EPSS/KEV 수집, 저장소 스캔(lockfile, 코드 import 인덱스), 버전 범위 매칭으로 후보 생성
- M2(판별) 완료: 취약점 프로파일(Haiku, 취약점당 1회), 증거 수집, JEV 판별·라우팅(TypeSafe/OpenRouter), 규칙 기반 대체, 라우팅 정책, 사용량·예산 기록

- M3(분석·점수) 완료: Haiku 경량 분석, Sonnet/Opus 도구 기반 심층 분석, 불확실 시 한 단계 상향, 거부 대비 fallback, Batch API, 자동 종결 감사 피드백, 위험도 산정

- M4(알림·UI) 완료: Slack/이메일 즉시 알림과 일일 요약, Finding 상세와 처리(수용·해당 없음·수정 완료), 사용량 대시보드

평가 도구(정답 셋 기반 정확도·비용 측정)는 M5에서 들어갑니다.

## 실행 (Docker Compose)

1. 마스터 키를 만들어 `.env`에 넣습니다. 이 키로 API 키를 암호화하므로 잃어버리면 저장된 키를 복호화할 수 없습니다.

   ```bash
   cp .env.example .env
   python3 -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
   # 출력값을 .env의 AUTOCVE_MASTER_KEY= 뒤에 붙여 넣습니다.
   ```

2. 필요하면 `.env`의 `AUTOCVE_ADMIN_PASSWORD`를 설정합니다. 설정하면 웹 UI에 HTTP Basic 인증(사용자 이름 `admin`)이 걸립니다.

3. 실행합니다. 앱 컨테이너가 시작할 때 DB 마이그레이션을 자동으로 적용합니다.

   ```bash
   docker compose up -d --build
   ```

4. http://127.0.0.1:8000 에 접속해 API 키를 등록합니다.
   - **Anthropic** (필수): `GET /v1/models`로 검증합니다. 토큰을 쓰지 않습니다.
   - **JEV** (선택): TypeSafe 키 또는 OpenRouter 키 중 하나를 넣고, 사용할 제공자를 고릅니다. OpenRouter는 키 정보 조회로 검증하고, TypeSafe는 최소 판별 요청 1회로 검증합니다.

   - **GitHub** (선택): 비공개 저장소를 clone할 때만 씁니다. github.com 저장소에만 전송합니다.

   거부된 키는 저장하지 않습니다. 네트워크 문제로 검증하지 못한 키는 "검증 못 함" 상태로 저장되며, 나중에 재검증할 수 있습니다.

5. **프로젝트**에서 저장소(https URL)를 등록하면 바로 스캔하고 후보 취약점을 위험도 순으로 보여줍니다.
6. **알림**에서 Slack Incoming Webhook이나 이메일 받는 사람을 등록합니다. 이메일은 SMTP 환경변수(`AUTOCVE_SMTP_HOST`, `AUTOCVE_SMTP_PORT`, `AUTOCVE_SMTP_USERNAME`, `AUTOCVE_SMTP_PASSWORD`, `AUTOCVE_SMTP_FROM`)가 있어야 보냅니다. 알림 속 링크 주소는 `AUTOCVE_PUBLIC_URL`로 정합니다.

## 수집과 스캔

워커가 다음 일정으로 돌립니다 (UTC).

| 작업 | 주기 | 내용 |
|------|------|------|
| `sync_feeds` | 매시 7분, 워커 시작 시 | OSV npm/PyPI 수집 → 바뀐 취약점만 다시 매칭 |
| `sync_exploits` | 매일 06:17, 워커 시작 시 | EPSS, CISA KEV 갱신 |
| `scan_all_projects` | 매일 03:23 | 모든 프로젝트 재스캔 → 바뀐 컴포넌트만 다시 매칭 → 판별 |
| `triage_project` | 피드 수집 후 | 새 취약점으로 Finding이 생긴 프로젝트를 다시 clone해 판별·분석 |
| `collect_batches` | 10분마다 | Batch API로 보낸 경량 분석 결과 반영 |
| `send_digest` | 매일 00:07 | Medium·Low 등급 일일 요약 알림 |

High 이상(설정으로 Critical만 가능)은 스캔·판별·분석·EPSS/KEV 갱신이 끝날 때마다 바로 알립니다. 이미 알린 취약점은 등급이 올라갈 때만 다시 알립니다.

- 처음 실행하면 OSV 전체 덤프를 적재합니다. npm은 약 23만 건(219MB)이며 수 분 걸립니다. 이후에는 변경분만 받습니다.
- 같은 취약점이 여러 DB에 있으면(GHSA, PYSEC 등 별칭) Finding은 하나만 만듭니다.
- 업그레이드로 영향 범위를 벗어나면 미처리 Finding은 `resolved`가 됩니다.
- clone한 코드는 스캔이 끝나면 지우고, import 목록과 파일 해시만 남깁니다.

워커를 기다리지 않고 직접 돌릴 때는 CLI를 씁니다.

```bash
python -m autocve.cli sync-feeds [--ecosystem npm]
python -m autocve.cli sync-exploits
python -m autocve.cli add-project NAME https://github.com/owner/repo [--branch main] [--exposure internet]
python -m autocve.cli scan PROJECT_ID      # 스캔 → 매칭 → 판별
python -m autocve.cli triage PROJECT_ID    # 판별·분석 (저장소를 다시 clone)
python -m autocve.cli collect-batches      # Batch API 결과 반영
python -m autocve.cli notify [--digest]    # 즉시 알림 / 일일 요약
python -m autocve.cli findings PROJECT_ID
python -m autocve.cli rematch
```

## 개발

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check .
```

로컬 PostgreSQL에 마이그레이션 적용:

```bash
export AUTOCVE_DATABASE_URL=postgresql+psycopg://autocve:autocve@localhost:5432/autocve
alembic upgrade head
```

모델을 바꾼 뒤에는 `alembic revision --autogenerate -m "<설명>"`으로 마이그레이션을 만듭니다.

## 구조

```
autocve/
  api/            # FastAPI 앱, 접근 제어(Basic 인증, 출처 검사), 설정·프로젝트 화면
  collector/      # OSV(전체 적재 + 증분), EPSS, KEV 수집
  credentials/    # 제공자별 키 검증, 키 저장/재검증/삭제 서비스
  inventory/      # 저장소 clone, lockfile 파서, 코드 import 인덱스, 스캔
  matcher/        # OSV 버전 범위 판정(SemVer, PEP 440), 후보 Finding 생성
  analysis/       # 취약점 프로파일, 경량·심층 분석, Batch API, 감사 피드백
  triage/         # 증거 수집, JEV/규칙 판별, 라우팅 정책, 판별 실행
  llm/            # Claude 호출 게이트웨이(예산, 사용량), 단가표
  scoring/        # CVSS v3 점수 계산, 위험도 산정
  security/       # keyvault.py(AES-256-GCM 암호화), redaction.py(로그 키 마스킹)
  notify/         # 알림 채널(Slack, 이메일), 메시지, 대상 선정
  web/            # 템플릿, CSS
  feedback.py     # 사용자 처리(수용·해당 없음·수정 완료·다시 열기)
  usage.py        # 사용량 대시보드 통계
  models.py       # DB 스키마 (docs/02-architecture.md §7)
  pipeline.py     # 수집 → 매칭, 스캔 → 매칭 작업 단위
  worker.py       # arq 워커 (cron 일정)
  cli.py          # 운영용 CLI
migrations/       # Alembic
tests/
```
