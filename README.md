# AutoCVE

공개 취약점 DB(OSV, EPSS, CISA KEV)를 주기적으로 수집합니다. 새 취약점이 연결된 저장소에 실제로 영향을 주는지 판별하고, 근거와 위험도를 알려주는 서비스입니다.

- **판별 우선**: 저비용 판별 모델 JEV가 먼저 위험 여부와 분석 모델(없음/Haiku/Sonnet/Opus)을 정합니다. Claude는 근거가 필요한 경우에만 호출합니다.
- **BYOK**: 사용자 본인의 Anthropic API 키(필수)와 JEV 키(선택)를 사용합니다. JEV는 TypeSafe에 직접 호출하거나 OpenRouter를 거쳐 호출할 수 있습니다.

## 문서

- [MVP 범위](docs/01-mvp-scope.md)
- [아키텍처](docs/02-architecture.md)
- [평가](docs/03-evaluation.md)

## 상태

- M0(기반) 완료: 저장소 골격, DB 스키마, Docker Compose, API 키 저장소
- M1(데이터) 완료: OSV/EPSS/KEV 수집, 저장소 스캔(lockfile, 코드 import 인덱스), 버전 범위 매칭으로 후보 생성
- M2(판별) 완료: 취약점 프로파일(Haiku, 취약점당 1회), 증거 수집, JEV 판별·라우팅(TypeSafe/OpenRouter), 규칙 기반 대체, 라우팅 정책, 사용량·예산 기록

- M3(분석·점수) 완료: Haiku 경량 분석, Sonnet/Opus 도구 기반 심층 분석, 불확실 시 한 단계 상향, 거부 대비 fallback, Batch API, 자동 종결 감사 피드백, 위험도 산정

- M4(알림·UI) 완료: Slack/이메일 즉시 알림과 일일 요약, Finding 상세와 처리(수용·해당 없음·수정 완료), 사용량 대시보드
- M5(평가) 완료: 성공 지표 리포트, 정답 셋(사용자 처리 기록·JSON), 정확도·놓친 비율, 자동 종결 임계값 보정, 캐스케이드 vs Opus 단일 비교 실험
- 실행·배포: `.env`로 모든 설정 관리(키·알림·예산은 화면에서 잠금), `run.sh` 실행, `build.sh` 배포 번들

## 실행

Docker와 Docker Compose 플러그인이 필요합니다. 설정은 모두 `.env`에서 읽습니다 ([.env.example](.env.example)에 전체 항목과 설명이 있습니다).

```bash
./run.sh up
```

처음 실행하면 다음을 처리합니다.

1. `.env.example`을 `.env`로 복사합니다 (권한 600).
2. 마스터 키(`AUTOCVE_MASTER_KEY`)와 DB 비밀번호를 만들어 넣습니다. 마스터 키로 API 키를 암호화하므로, 잃어버리면 저장된 키를 복호화할 수 없습니다. **`.env`를 안전한 곳에 백업하세요.**
3. 이미지를 빌드하고 컨테이너를 띄웁니다. 앱이 시작할 때 DB 마이그레이션을 자동으로 적용합니다.
4. 앱이 정상 상태가 될 때까지 기다린 뒤 주소를 알려줍니다 (기본 http://127.0.0.1:8000).

| 명령 | 내용 |
|------|------|
| `./run.sh up` | `.env` 준비 → 빌드 → 실행 → 상태 확인 |
| `./run.sh down` | 중지 (데이터 유지) |
| `./run.sh restart` | `.env`를 바꾼 뒤 새 설정으로 앱·워커 재시작 |
| `./run.sh logs [app\|worker]` | 로그 |
| `./run.sh status` | 컨테이너 상태 |
| `./run.sh cli <명령>` | 운영 CLI (아래 [수집과 스캔](#수집과-스캔)) |
| `./run.sh backup` | DB를 `backups/`에 덤프 |
| `./run.sh dev` | Docker 없이 로컬 실행 (PostgreSQL, Redis, `.venv` 필요) |

### 설정 (.env)

| 항목 | 변수 | 비워 두면 |
|------|------|-----------|
| 웹 UI 비밀번호 (HTTP Basic, 사용자 `admin`) | `AUTOCVE_ADMIN_PASSWORD` | 인증 없음 |
| 접속 주소·포트 | `AUTOCVE_BIND`, `AUTOCVE_PORT` | `127.0.0.1:8000` (같은 PC에서만) |
| Anthropic 키 (필수) | `AUTOCVE_ANTHROPIC_API_KEY` | 웹 화면에서 입력 |
| JEV 제공자 | `AUTOCVE_JEV_PROVIDER` (`none`/`typesafe`/`openrouter`) | 웹 화면에서 선택 |
| JEV 키 | `AUTOCVE_TYPESAFE_API_KEY`, `AUTOCVE_OPENROUTER_API_KEY` | 웹 화면에서 입력 |
| GitHub 토큰 (비공개 저장소) | `AUTOCVE_GITHUB_TOKEN` | 웹 화면에서 입력 |
| 월 예산 (USD) | `AUTOCVE_MONTHLY_BUDGET_USD` | 웹 화면에서 설정 |
| 알림 기준·일일 요약 | `AUTOCVE_NOTIFY_IMMEDIATE_GRADE`, `AUTOCVE_NOTIFY_DIGEST` | 웹 화면에서 설정 |
| Slack Webhook | `AUTOCVE_SLACK_WEBHOOK_URL` | 웹 화면에서 입력 |
| 이메일 받는 사람·SMTP | `AUTOCVE_NOTIFY_EMAIL_TO`, `AUTOCVE_SMTP_*` | 이메일 안 보냄 |
| 알림 속 링크 주소 | `AUTOCVE_PUBLIC_URL` | `http://127.0.0.1:8000` |

- API 키, JEV 제공자, 예산, 알림 항목은 시작할 때 DB에 반영됩니다. 그 항목은 웹 화면에서 잠기고 "`.env`로 관리" 표시가 나옵니다.
- `.env`의 키는 형식만 확인하고 "검증 못 함" 상태로 저장합니다. 웹 화면의 **재검증**으로 실제 호출을 확인할 수 있습니다. 값이 그대로면 다시 저장하지 않으므로 재검증 결과가 유지됩니다.
- `.env`에서 키를 지우고 다시 시작하면 그 키는 DB에서도 지워집니다. 웹 화면에서 입력한 키는 건드리지 않습니다.
- 외부에 열 때는 `AUTOCVE_BIND=0.0.0.0`과 `AUTOCVE_ADMIN_PASSWORD`를 함께 설정하고, HTTPS 리버스 프록시(Caddy, nginx 등) 뒤에 두세요.

### 사용

1. **설정 > API 키**에서 키를 확인하거나 입력합니다 (`.env`에 넣었다면 생략).
   - **Anthropic** (필수): `GET /v1/models`로 검증합니다. 토큰을 쓰지 않습니다.
   - **JEV** (선택): TypeSafe 키 또는 OpenRouter 키 중 하나를 넣고, 사용할 제공자를 고릅니다. OpenRouter는 키 정보 조회로 검증하고, TypeSafe는 최소 판별 요청 1회로 검증합니다.
   - **GitHub** (선택): 비공개 저장소를 clone할 때만 씁니다. github.com 저장소에만 전송합니다.

   거부된 키는 저장하지 않습니다. 네트워크 문제로 검증하지 못한 키는 "검증 못 함" 상태로 저장되며, 나중에 재검증할 수 있습니다.
2. **프로젝트**에서 저장소(https URL)를 등록하면 바로 스캔하고 후보 취약점을 위험도 순으로 보여줍니다.
3. **알림**에서 Slack Webhook이나 이메일 받는 사람을 등록합니다 (`.env`에 넣었다면 생략).

### 배포 번들

```bash
./build.sh               # ruff, pytest → 이미지 빌드 → dist/autocve-<버전>.tar.gz
./build.sh --skip-tests  # 검사 생략
./build.sh --offline     # postgres, redis 이미지도 포함 (인터넷 없는 서버용)
./build.sh --image-only  # 이미지만 빌드
```

번들에는 이미지 파일, 이미지 기반 `docker-compose.yml`, `.env.example`, `run.sh`, 설치 안내가 들어 있습니다. 서버에는 Docker만 있으면 되고 소스는 필요 없습니다.

```bash
scp dist/autocve-<버전>.tar.gz server:
ssh server 'tar xzf autocve-<버전>.tar.gz && cd autocve-<버전> && ./run.sh up'
```

업그레이드할 때는 새 번들을 풀고 이전 폴더의 `.env`를 복사한 뒤 `./run.sh up`을 실행합니다. Compose 프로젝트 이름이 `autocve`로 고정되어 있어 같은 DB 볼륨을 그대로 씁니다.

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

워커를 기다리지 않고 직접 돌릴 때는 CLI를 씁니다. Docker로 실행 중이면 `python -m autocve.cli` 대신 `./run.sh cli`를 씁니다.

```bash
python -m autocve.cli sync-feeds [--ecosystem npm]
python -m autocve.cli sync-exploits
python -m autocve.cli add-project NAME https://github.com/owner/repo [--branch main] [--exposure internet]
python -m autocve.cli scan PROJECT_ID      # 스캔 → 매칭 → 판별
python -m autocve.cli triage PROJECT_ID    # 판별·분석 (저장소를 다시 clone)
python -m autocve.cli collect-batches      # Batch API 결과 반영
python -m autocve.cli notify [--digest]    # 즉시 알림 / 일일 요약
python -m autocve.cli eval report          # 평가 리포트 (docs/03-evaluation.md)
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

로컬에서 실행 (`.env`의 `AUTOCVE_DATABASE_URL`, `AUTOCVE_REDIS_URL`을 씁니다. 마이그레이션 → 워커 → 웹 순서로 띄웁니다):

```bash
./run.sh dev
```

테스트는 `.env`와 `AUTOCVE_*` 환경변수를 읽지 않습니다.

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
  evaluation/     # 성공 지표, 정답 셋, 정확도, 임계값 보정, 비교 실험
  models.py       # DB 스키마 (docs/02-architecture.md §7)
  pipeline.py     # 수집 → 매칭, 스캔 → 매칭 작업 단위
  worker.py       # arq 워커 (cron 일정)
  cli.py          # 운영용 CLI
  envsync.py      # .env 설정을 DB에 반영 (시작 시)
migrations/       # Alembic
run.sh            # 실행 (up/down/restart/logs/cli/backup/dev)
build.sh          # 배포 번들 생성
tests/
```
