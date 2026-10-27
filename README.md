# AutoCVE

공개 취약점 DB(OSV, EPSS, CISA KEV)를 주기적으로 수집합니다. 새 취약점이 연결된 저장소에 실제로 영향을 주는지 판별하고, 근거와 위험도를 알려주는 서비스입니다.

- **판별 우선**: 저비용 판별 모델 JEV가 먼저 위험 여부와 분석 모델(없음/Haiku/Sonnet/Opus)을 정합니다. Claude는 근거가 필요한 경우에만 호출합니다.
- **BYOK**: 사용자 본인의 Anthropic API 키(필수)와 JEV 키(선택)를 사용합니다. JEV는 TypeSafe에 직접 호출하거나 OpenRouter를 거쳐 호출할 수 있습니다.

## 목차

- [사용 설명서](#사용-설명서)
  1. [준비물](#1-준비물)
  2. [설치와 첫 실행](#2-설치와-첫-실행)
  3. [설정 (.env)](#3-설정-env)
  4. [API 키 등록](#4-api-키-등록)
  5. [저장소 등록과 스캔](#5-저장소-등록과-스캔)
  6. [결과 읽기](#6-결과-읽기)
  7. [취약점 처리](#7-취약점-처리)
  8. [알림](#8-알림)
  9. [비용 관리와 사용량](#9-비용-관리와-사용량)
  10. [평가](#10-평가)
  11. [자동으로 돌아가는 작업](#11-자동으로-돌아가는-작업)
  12. [CLI](#12-cli)
  13. [운영: 백업, 업그레이드, 외부 공개](#13-운영-백업-업그레이드-외부-공개)
  14. [배포 번들 만들기](#14-배포-번들-만들기)
  15. [문제 해결](#15-문제-해결)
- [개발](#개발)
- [구조](#구조)
- 설계 문서: [MVP 범위](docs/01-mvp-scope.md) · [아키텍처](docs/02-architecture.md) · [평가](docs/03-evaluation.md)

---

# 사용 설명서

## 1. 준비물

| 항목 | 필수 | 설명 |
|------|------|------|
| Docker, Docker Compose 플러그인 | 필수 | `docker compose version`으로 확인 |
| Anthropic API 키 | 필수 | 취약점 요약과 Claude 분석에 사용 ([console.anthropic.com](https://console.anthropic.com)) |
| JEV 키 (TypeSafe 또는 OpenRouter) | 선택 | 없으면 규칙 기반으로 판별합니다. 있으면 Claude 호출이 줄어듭니다. |
| GitHub 토큰 | 선택 | 비공개 저장소를 스캔할 때만 필요 |
| Slack Webhook 또는 SMTP 서버 | 선택 | 알림을 받을 때 필요 |

지원하는 저장소: https로 clone할 수 있는 git 저장소. 다음 의존성 파일을 읽습니다.

| 생태계 | 파일 |
|--------|------|
| npm | `package-lock.json` (v1~v3) |
| PyPI | `poetry.lock`, `requirements*.txt`, `requirements/*.txt` |

`requirements.txt`는 `name==1.2.3`처럼 버전이 고정된 줄만 읽습니다. 범위로 지정한 줄(`>=`, `~=`)은 실제 설치 버전을 알 수 없어 건너뜁니다. `pip-compile` 출력을 쓰면 직접·간접 의존성까지 구분합니다.

## 2. 설치와 첫 실행

```bash
git clone https://github.com/chemilk02/AutoCVE.git
cd AutoCVE
./run.sh up
```

처음 실행하면 `run.sh`가 다음을 처리합니다.

1. `.env.example`을 `.env`로 복사합니다 (권한 600).
2. 마스터 키(`AUTOCVE_MASTER_KEY`)와 DB 비밀번호를 만들어 넣습니다.
3. 이미지를 빌드하고 DB, Redis, 웹 앱, 워커를 띄웁니다. 앱이 시작할 때 DB 마이그레이션을 자동으로 적용합니다.
4. 앱이 정상 상태가 될 때까지 기다린 뒤 주소를 알려줍니다 (기본 http://127.0.0.1:8000).

> **`.env`를 안전한 곳에 백업하세요.** 마스터 키로 API 키를 암호화합니다. 마스터 키를 잃어버리면 저장된 키를 복호화할 수 없어 키를 다시 입력해야 합니다.

첫 실행 직후 워커가 OSV 전체 덤프를 적재합니다. npm은 약 23만 건이며 수 분 걸립니다. 진행 상황은 `./run.sh logs worker`로 봅니다. 적재 중에도 저장소를 등록할 수 있고, 적재가 끝나면 자동으로 다시 대조합니다.

### run.sh 명령

| 명령 | 내용 |
|------|------|
| `./run.sh up` | `.env` 준비 → 빌드 → 실행 → 상태 확인 |
| `./run.sh down` | 중지 (데이터 유지) |
| `./run.sh restart` | `.env`를 바꾼 뒤 새 설정으로 앱·워커 재시작 |
| `./run.sh logs [app\|worker]` | 로그 보기 (Ctrl+C로 종료) |
| `./run.sh status` | 컨테이너 상태 |
| `./run.sh cli <명령>` | 운영 CLI ([12. CLI](#12-cli)) |
| `./run.sh backup` | DB를 `backups/`에 백업 |
| `./run.sh dev` | Docker 없이 로컬 실행 ([개발](#개발)) |

## 3. 설정 (.env)

설정은 모두 `.env`에서 읽습니다. [.env.example](.env.example)에 전체 항목과 설명이 있습니다. `.env`를 고친 뒤에는 `./run.sh restart`로 반영합니다.

| 항목 | 변수 | 비워 두면 |
|------|------|-----------|
| 웹 UI 비밀번호 (HTTP Basic, 사용자 `admin`) | `AUTOCVE_ADMIN_PASSWORD` | 인증 없음 |
| 접속 주소·포트 | `AUTOCVE_BIND`, `AUTOCVE_PORT` | `127.0.0.1:8000` (같은 PC에서만) |
| 알림 속 링크 주소 | `AUTOCVE_PUBLIC_URL` | `http://127.0.0.1:8000` |
| Anthropic 키 | `AUTOCVE_ANTHROPIC_API_KEY` | 웹 화면에서 입력 |
| JEV 제공자 | `AUTOCVE_JEV_PROVIDER` (`none`/`typesafe`/`openrouter`) | 웹 화면에서 선택 |
| JEV 키 | `AUTOCVE_TYPESAFE_API_KEY`, `AUTOCVE_OPENROUTER_API_KEY` | 웹 화면에서 입력 |
| GitHub 토큰 | `AUTOCVE_GITHUB_TOKEN` | 웹 화면에서 입력 |
| 월 예산 (USD) | `AUTOCVE_MONTHLY_BUDGET_USD` | 웹 화면에서 설정 (기본 제한 없음) |
| 즉시 알림 기준 | `AUTOCVE_NOTIFY_IMMEDIATE_GRADE` (`high`/`critical`) | 웹 화면에서 설정 (기본 `high`) |
| 일일 요약 | `AUTOCVE_NOTIFY_DIGEST` (`true`/`false`) | 웹 화면에서 설정 (기본 켬) |
| Slack Webhook | `AUTOCVE_SLACK_WEBHOOK_URL` | 웹 화면에서 입력 |
| 이메일 받는 사람 | `AUTOCVE_NOTIFY_EMAIL_TO` (쉼표로 구분) | 웹 화면에서 입력 |
| SMTP | `AUTOCVE_SMTP_HOST`, `_PORT`, `_USERNAME`, `_PASSWORD`, `_FROM`, `_STARTTLS` | 이메일 안 보냄 |
| DB 비밀번호 | `AUTOCVE_DB_PASSWORD` | `autocve` |

**.env와 웹 화면의 관계**

- API 키, JEV 제공자, 예산, 알림 항목에 값을 넣으면 시작할 때 DB에 반영됩니다. 그 항목은 웹 화면에서 잠기고 "`.env`로 관리합니다" 표시가 나옵니다.
- 비워 둔 항목은 웹 화면에서 자유롭게 바꿀 수 있습니다. 둘을 섞어 써도 됩니다.
- `.env`의 키는 형식만 확인하고 "검증 못 함" 상태로 저장합니다. 웹 화면의 **재검증**을 누르면 실제로 호출해서 확인합니다. 값이 그대로면 다시 저장하지 않으므로 재검증 결과가 유지됩니다.
- `.env`에서 키를 지우고 다시 시작하면 그 키는 DB에서도 지워집니다. 웹 화면에서 입력한 키는 건드리지 않습니다.
- `AUTOCVE_DB_PASSWORD`는 DB를 처음 만들 때만 적용됩니다. 그 뒤에는 바꾸지 마세요.

## 4. API 키 등록

상단 메뉴 **API 키** 화면입니다. `.env`에 넣은 키는 이미 등록되어 있습니다.

1. **Anthropic** (필수): 키(`sk-ant-...`)를 넣고 **검증 후 저장**을 누릅니다. 모델 목록 조회로 검증하므로 토큰을 쓰지 않습니다.
2. **JEV 판별 모델** (선택)
   - TypeSafe 키 또는 OpenRouter 키(`sk-or-...`) 중 하나를 등록합니다.
   - **사용할 제공자**에서 고르고 **변경**을 누릅니다.
   - "사용 안 함"이면 규칙 기반으로 판별합니다. 규칙 기반은 자동 종결을 하지 않으므로 Claude 분석이 더 많이 일어납니다.
3. **월 예산**: Claude 사용액 상한(USD)입니다 ([9. 비용 관리](#9-비용-관리와-사용량)).
4. **GitHub** (선택): 비공개 저장소용입니다. 읽기 전용(Contents: Read) fine-grained 토큰을 권장합니다. github.com 저장소에만 전송합니다.

키 상태는 세 가지입니다.

| 상태 | 의미 |
|------|------|
| 검증됨 | 실제 호출로 확인함 |
| 검증 못 함 | 네트워크 문제 등으로 확인하지 못함. 저장은 되며 **재검증**으로 다시 확인 |
| 거부됨 | 제공자가 거부함. 저장하지 않음 |

키는 AES-256-GCM으로 암호화해서 저장하고, 화면에는 끝 4자리만 보입니다. 로그에도 키 값은 가려서 남습니다.

## 5. 저장소 등록과 스캔

상단 메뉴 **프로젝트** 화면 아래의 **저장소 등록**에서 입력합니다.

| 입력 | 설명 |
|------|------|
| 이름 | 화면에 보일 이름 |
| 저장소 주소 | `https://github.com/owner/repo` 형식 |
| 브랜치 | 비우면 기본 브랜치 |
| 노출 범위 | 위험도 계산에 쓰입니다 (아래 표) |

| 노출 범위 | 언제 고르나 | 위험도 가중치 |
|-----------|-------------|---------------|
| prod, 인터넷 노출 | 외부에 공개된 서비스 | 1.0 |
| prod, 내부망 | 사내망에서만 쓰는 서비스 | 0.7 |
| 개발 전용 | 배포하지 않는 도구, 예제 | 0.2 |

**등록하고 스캔**을 누르면 다음이 바로 진행됩니다.

1. 저장소를 clone해 의존성 파일과 코드의 import를 읽습니다. 코드는 스캔이 끝나면 지우고 import 목록과 파일 해시만 남깁니다.
2. 의존성 버전을 OSV 취약점의 영향 범위와 대조해 **후보 취약점**을 만듭니다.
3. 후보를 판별·분석해 위험도를 매깁니다.

이후에는 매일 자동으로 다시 스캔하고, 새 취약점이 들어오면 바로 대조합니다. 직접 다시 돌리려면 프로젝트 화면에서 **다시 스캔**을 누릅니다.

**프로젝트 화면의 설정**

- **노출 범위**: 바꾸면 위험도를 다시 계산합니다.
- **JEV 판별 요청에 코드 스니펫 포함**: 끄면 JEV에 코드 없이 메타데이터(패키지, 버전, import 수 등)만 보냅니다. 코드 외부 전송이 걱정될 때 끕니다. 판별 정확도는 조금 떨어질 수 있습니다.
- **삭제**: 프로젝트와 후보 기록을 모두 지웁니다.

## 6. 결과 읽기

### 프로젝트 화면

위쪽에는 마지막 스캔 시각, 미처리 위험 등급별 개수, 컴포넌트 수(생태계별, 직접/dev)가 나옵니다. 아래 **후보 취약점** 표는 위험도 순입니다.

| 열 | 내용 |
|----|------|
| 위험 | 등급과 점수 (0~100) |
| 취약점 | 취약점 ID와 요약. 누르면 상세 화면 |
| 패키지 | `이름@버전`, 의존성 파일 위치, 직접/간접, prod/dev |
| 신호 | `악성 패키지`, `KEV`(실제 악용 확인됨), `EPSS`(30일 내 악용 확률) |
| 판별·분석 | 판별 결과와 Claude 분석 결론 |

흐리게 표시된 줄은 이미 닫힌 후보입니다 (자동 종결, 해당 없음, 해소됨).

### 위험 등급

위험도 = 100 × 심각도 × 악용 가능성 × 도달성 × 노출도

| 요소 | 계산 |
|------|------|
| 심각도 | CVSS ÷ 10. 정보가 없으면 0.5. 악성 패키지는 1.0 |
| 악용 가능성 | KEV 등재면 1.0, 아니면 0.7 + 0.3 × EPSS |
| 도달성 | 영향 있음 1.0, 판단 보류·분석 전 0.6, 영향 없음 0.05 |
| 노출도 | 프로젝트 노출 범위 가중치. dev 의존성은 최대 0.2 |

| 등급 | 점수 | 알림 |
|------|------|------|
| Critical | 70 이상 | 즉시 |
| High | 40 이상 | 즉시 (설정으로 Critical만 가능) |
| Medium | 20 이상 | 일일 요약 |
| Low | 5 이상 | 일일 요약 |
| Info | 5 미만 | 없음 |

### 판별 결과

| 표시 | 의미 |
|------|------|
| 자동 종결 | JEV가 영향 없음으로 높은 확신(기본 0.90 이상)을 보여 Claude 없이 닫음 |
| 분석 대기 → Haiku/Sonnet/Opus | 해당 모델로 분석하도록 보냄 |
| 악성 패키지 | 악성 패키지로 등록된 버전. 분석 없이 최고 위험 |
| dev 전용, 분석 생략 | 개발 의존성이라 분석하지 않음 |
| 영향 버전 아님 / 취약점 철회 | 버전이 범위 밖이거나 취약점이 철회됨 |
| 예산 소진, 분석 보류 | 월 예산을 다 써서 분석을 미룸 |
| (감사 표본) | 자동 종결 대상이지만 정확도 확인을 위해 일부(5%)를 분석에 보냄 |

판별 주체는 `JEV`, `규칙`(JEV 키가 없을 때), `캐시`(같은 판별 재사용)로 표시됩니다. "JEV 실패로 대체"는 JEV 호출이 실패해 규칙으로 대신 판별했다는 뜻입니다.

### Claude 분석 결론

| 결론 | 의미 |
|------|------|
| 영향 있음 | 취약한 코드가 실제로 쓰이는 경로를 찾음 |
| 영향 없음 | 취약한 기능을 쓰지 않거나 입력이 닿지 않음 |
| 판단 보류(사람 검토) | 코드만으로 판단하기 어려움. 직접 확인 필요 |
| 분석 거부 | 모델이 분석을 거부함. 직접 검토 필요 |
| 분석 실패 | API 오류 등. 다음 분석 때 다시 시도 |

KEV 등재나 CVSS 9 이상은 최소 Sonnet으로 분석합니다. 분석 결과가 불확실하면 한 단계 위 모델로 다시 분석합니다.

### 취약점 상세 화면

후보를 누르면 다음을 볼 수 있습니다.

- **패키지**: 설치 위치, 별칭(CVE, GHSA 등), osv.dev 원문 링크
- **위험도 구성**: 위 네 요소의 실제 값과 근거 (CVSS, EPSS, 판정, 노출 범위)
- **Claude 분석**: 모델, 확신도, 결론 근거, 데이터 흐름, 관련 코드 위치(`파일:줄`)
- **판별**: 판별 이력과 증거 (패키지를 import하는 prod/테스트 파일 수, 취약 함수 사용 위치와 코드)
- **취약점 설명**: OSV 원문

## 7. 취약점 처리

상세 화면의 **처리**에서 고릅니다. 처리 기록은 [평가](#10-평가)의 정답으로 쌓여 자동 종결 기준을 보정하는 데 쓰입니다.

| 버튼 | 언제 | 결과 |
|------|------|------|
| 영향 있음 확인 | 실제로 영향이 있다고 확인했을 때 | 판정을 "영향 있음"으로 고정 |
| 수정 완료 | 패키지를 업그레이드했을 때 | "해소됨"으로 닫음 |
| 해당 없음으로 닫기 | 영향이 없다고 판단했을 때. **사유 필수** | 닫고 알림에서 제외 |
| 다시 열기 | 닫은 후보를 다시 볼 때 | 미처리로 되돌림. "해당 없음"이었다면 판정을 "판단 보류"로 바꿈 |

업그레이드한 뒤 다음 스캔에서 버전이 영향 범위를 벗어나면, 미처리 후보는 자동으로 "해소됨"이 됩니다.

## 8. 알림

상단 메뉴 **알림** 화면입니다.

| 설정 | 내용 |
|------|------|
| 즉시 알림 | High 이상(기본) 또는 Critical만. 스캔·판별·분석·EPSS/KEV 갱신이 끝날 때마다 보냅니다. |
| 일일 요약 | 그 아래 등급(Medium, Low)을 매일 00:07 UTC(한국 09:07)에 모아 보냅니다. |
| Slack | Incoming Webhook 주소 (`https://hooks.slack.com/services/...`) |
| 이메일 | 받는 사람(쉼표로 구분). `.env`에 SMTP가 설정되어 있어야 보냅니다. |

- 이미 알린 취약점은 등급이 올라갈 때만 다시 알립니다.
- 영향 없음으로 판정됐거나 직접 닫은 취약점은 알리지 않습니다.
- 알림 속 링크는 `AUTOCVE_PUBLIC_URL` 주소로 만듭니다.
- **테스트 알림 보내기**로 설정을 확인할 수 있고, 아래에 최근 전송 결과가 나옵니다.

Slack Webhook은 Slack 앱 설정의 **Incoming Webhooks**에서 채널을 골라 만듭니다.

## 9. 비용 관리와 사용량

### 비용이 드는 곳

1. **취약점 요약 (Haiku)**: 취약점당 한 번만 만들고 모든 프로젝트가 같이 씁니다.
2. **JEV 판별**: 후보마다 한 번. Claude보다 훨씬 저렴합니다.
3. **Claude 분석 (Haiku/Sonnet/Opus)**: JEV가 필요하다고 판단한 후보만 분석합니다. 실시간이 필요 없는 Haiku 분석이 많으면 Batch API(50% 할인)로 보냅니다.

같은 취약점·같은 코드 조건의 판별과 분석은 캐시해서 다시 호출하지 않습니다.

### 월 예산

**API 키** 화면 또는 `AUTOCVE_MONTHLY_BUDGET_USD`로 정합니다.

| 사용액 | 동작 |
|--------|------|
| 80% 미만 | 정상 |
| 80% 이상 | Opus 대신 Sonnet 사용 |
| 100% | Claude 호출 중단. 후보는 "예산 소진으로 분석 보류"로 남고, 다음 달이나 예산을 올린 뒤 다시 처리 |

### 사용량 화면

상단 메뉴 **사용량**에서 이번 달 기준으로 봅니다.

- 이번 달 비용과 예산 대비 비율
- **Claude 없이 종결**: 판별만으로 닫은 비율. 높을수록 비용이 절약됩니다.
- 프롬프트 캐시 적중률, JEV·Claude 호출 수
- 최근 30일 일별 비용, 단계별·모델별 비용, 분석 경로(Haiku/Sonnet/Opus)

비용은 단가표로 계산한 추정치입니다. 정확한 청구액은 Anthropic 콘솔과 OpenRouter에서 확인하세요.

## 10. 평가

상단 메뉴 **평가** 화면입니다.

- **성공 지표**: 알림 지연(p90), Claude 없이 종결된 비율, 자동 종결 감사 오판율, Opus 도달 비율, 사용자가 판정을 뒤집은 비율, 후보 1건당 비용의 목표 달성 여부
- **정확도**: [7. 취약점 처리](#7-취약점-처리)에서 처리한 후보를 정답으로 삼아 계산합니다. 정확도, 놓친 비율(영향이 있는데 없다고 판정), 정밀도·재현율을 보여줍니다.
- **자동 종결 임계값**: 처리 기록으로 계산한 권장값입니다. 적용하려면 `./run.sh cli eval calibrate --apply`를 실행합니다.

감사 표본에서 자동 종결이 틀린 경우가 많으면 임계값을 자동으로 올립니다. 자세한 내용은 [docs/03-evaluation.md](docs/03-evaluation.md)에 있습니다.

## 11. 자동으로 돌아가는 작업

워커가 다음 일정으로 돌립니다 (UTC).

| 작업 | 주기 | 내용 |
|------|------|------|
| 취약점 수집 (`sync_feeds`) | 매시 7분, 워커 시작 시 | OSV npm/PyPI 변경분 수집 → 바뀐 취약점만 다시 대조 |
| 악용 정보 갱신 (`sync_exploits`) | 매일 06:17, 워커 시작 시 | EPSS, CISA KEV 갱신 → 위험도 재계산 |
| 전체 재스캔 (`scan_all_projects`) | 매일 03:23 | 모든 저장소 재스캔 → 바뀐 의존성만 다시 대조 → 판별 |
| 판별·분석 (`triage_project`) | 새 후보가 생길 때 | 저장소를 다시 clone해 판별·분석 |
| 배치 결과 반영 (`collect_batches`) | 10분마다 | Batch API로 보낸 분석 결과 반영 |
| 일일 요약 (`send_digest`) | 매일 00:07 | Medium·Low 등급 요약 알림 |

같은 취약점이 여러 DB에 있으면(CVE, GHSA, PYSEC 등 별칭) 후보는 하나만 만듭니다.

## 12. CLI

워커를 기다리지 않고 직접 돌릴 때 씁니다. Docker로 실행 중이면 `./run.sh cli`를 앞에 붙입니다.

```bash
./run.sh cli sync-feeds [--ecosystem npm]     # 취약점 수집 → 대조
./run.sh cli sync-exploits                    # EPSS, KEV 갱신
./run.sh cli add-project NAME https://github.com/owner/repo [--branch main] [--exposure internet|internal|dev]
./run.sh cli scan PROJECT_ID                  # 스캔 → 대조 → 판별
./run.sh cli triage PROJECT_ID                # 판별·분석 (저장소를 다시 clone)
./run.sh cli findings PROJECT_ID              # 후보 목록 (상태, 취약점 ID, 패키지)
./run.sh cli rematch                          # 모든 의존성을 취약점 DB와 다시 대조
./run.sh cli collect-batches                  # Batch API 결과 반영
./run.sh cli notify [--digest]                # 즉시 알림 / 일일 요약 보내기
./run.sh cli eval report [--dataset FILE]     # 평가 리포트 (Markdown)
./run.sh cli eval export-feedback             # 처리 기록을 정답 셋 JSON으로 내보내기
./run.sh cli eval calibrate [--apply]         # 자동 종결 임계값 보정
./run.sh cli eval experiment [--yes]          # 현재 방식과 Opus 단일 분석 비교 (--yes면 비용 발생)
```

`PROJECT_ID`는 프로젝트 화면 주소(`/projects/<번호>`)의 번호입니다.

## 13. 운영: 백업, 업그레이드, 외부 공개

### 백업

```bash
./run.sh backup        # backups/autocve-<날짜>.sql.gz
```

백업에는 API 키가 암호화된 채로 들어 있습니다. 복구하려면 같은 `AUTOCVE_MASTER_KEY`가 필요하므로 **백업 파일과 `.env`를 함께 보관하세요.** 백업 파일 권한은 600입니다.

복구는 다음 순서로 합니다. 현재 DB 내용은 지워집니다.

```bash
docker compose stop app worker
docker compose exec -T db dropdb -U autocve autocve
docker compose exec -T db createdb -U autocve autocve
gunzip -c backups/autocve-<날짜>.sql.gz | docker compose exec -T db psql -q -U autocve autocve
./run.sh restart
```

### 업그레이드

소스로 실행 중이면:

```bash
./run.sh backup
git pull
./run.sh up            # 다시 빌드하고, 시작할 때 DB 마이그레이션 적용
```

배포 번들로 실행 중이면 [14. 배포 번들 만들기](#14-배포-번들-만들기)의 업그레이드 절차를 따릅니다.

### 외부에 열기

기본값은 같은 PC(127.0.0.1)에서만 접속됩니다. 다른 PC에서 접속하려면 `.env`를 다음처럼 바꾸고 `./run.sh restart`를 실행합니다.

```bash
AUTOCVE_BIND=0.0.0.0
AUTOCVE_ADMIN_PASSWORD=<긴 비밀번호>
AUTOCVE_PUBLIC_URL=https://autocve.example.com
```

비밀번호 없이 외부에 열면 `run.sh`가 경고합니다. 인터넷에 열 때는 HTTPS 리버스 프록시(Caddy, nginx 등) 뒤에 두세요. 예를 들어 Caddy는 다음 설정이면 됩니다.

```
autocve.example.com {
    reverse_proxy 127.0.0.1:8000
}
```

## 14. 배포 번들 만들기

소스 없이 서버에 설치할 파일을 만듭니다.

```bash
./build.sh               # 검사(ruff, pytest) → 이미지 빌드 → dist/autocve-<버전>.tar.gz
./build.sh --skip-tests  # 검사 생략
./build.sh --offline     # postgres, redis 이미지도 포함 (인터넷 없는 서버용)
./build.sh --image-only  # 번들 없이 이미지만 빌드
```

번들에는 Docker 이미지, `docker-compose.yml`, `run.sh`, `.env.example`, 설치 안내가 들어 있습니다. 서버에는 Docker만 있으면 됩니다.

```bash
scp dist/autocve-<버전>.tar.gz server:
ssh server
tar xzf autocve-<버전>.tar.gz && cd autocve-<버전> && ./run.sh up
```

**번들 업그레이드**: 새 번들을 풀고, 이전 폴더의 `.env`를 복사한 뒤 실행합니다. Compose 프로젝트 이름이 `autocve`로 고정되어 있어 같은 DB를 그대로 씁니다.

```bash
cd autocve-<이전 버전> && ./run.sh backup && cd ..
tar xzf autocve-<새 버전>.tar.gz
cp autocve-<이전 버전>/.env autocve-<새 버전>/
cd autocve-<새 버전> && ./run.sh up
```

## 15. 문제 해결

| 증상 | 확인할 것 |
|------|-----------|
| `./run.sh up`이 "앱이 정상 상태가 되지 않았습니다"로 끝남 | 출력된 로그 확인. 대개 `.env` 값 오류(예산이 0 이하, 알림 등급 오타 등) |
| 프로젝트 화면에 "문제"가 표시됨 | 비공개 저장소면 GitHub 토큰 등록. 브랜치 이름 확인. 지원하는 의존성 파일이 있는지 확인 |
| 컴포넌트가 0개 | 지원 형식([1. 준비물](#1-준비물))의 lockfile이 없음. `requirements.txt`는 `==`로 고정된 줄만 읽음 |
| 후보가 하나도 없음 | 첫 실행이면 OSV 적재가 끝났는지 `./run.sh logs worker`로 확인. 끝나면 자동으로 다시 대조 |
| 판별까지만 되고 Claude 분석이 없음 | Anthropic 키 등록 여부와 상태 확인. 키를 등록한 뒤 **다시 스캔** |
| "예산 소진으로 분석 보류" | 월 예산을 올리거나 다음 달까지 대기 |
| 판별 주체가 계속 "규칙" | JEV 키와 제공자 선택 확인. "JEV 실패로 대체"면 JEV 키 재검증 |
| 키 상태가 "검증 못 함" | 서버에서 해당 API로 나가는 네트워크 확인 후 **재검증** |
| 웹 화면에서 키·설정을 못 바꿈 | `.env`로 관리 중인 항목. `.env`를 고치고 `./run.sh restart` |
| 알림이 안 옴 | **테스트 알림 보내기**와 최근 전송 결과 확인. 이메일은 SMTP 설정 필요 |
| "저장된 키를 복호화할 수 없습니다" | 마스터 키가 바뀜. 원래 `.env`를 복구하거나 키를 다시 입력 |
| `.env` 변경이 반영되지 않음 | `./run.sh restart` 실행 (`docker compose restart`로는 반영되지 않음) |

로그는 `./run.sh logs app`(웹), `./run.sh logs worker`(수집·스캔·분석)로 봅니다.

---

# 개발

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check .
```

로컬에서 Docker 없이 실행합니다. PostgreSQL과 Redis가 필요하며, `.env`의 `AUTOCVE_DATABASE_URL`, `AUTOCVE_REDIS_URL`을 씁니다. 마이그레이션 → 워커 → 웹(자동 재시작) 순서로 띄웁니다.

```bash
./run.sh dev
```

- 테스트는 `.env`와 `AUTOCVE_*` 환경변수를 읽지 않습니다.
- 모델을 바꾼 뒤에는 `alembic revision --autogenerate -m "<설명>"`으로 마이그레이션을 만듭니다.

## 진행 상태

- M0(기반): 저장소 골격, DB 스키마, Docker Compose, API 키 저장소
- M1(데이터): OSV/EPSS/KEV 수집, 저장소 스캔(lockfile, 코드 import 인덱스), 버전 범위 매칭으로 후보 생성
- M2(판별): 취약점 프로파일(Haiku, 취약점당 1회), 증거 수집, JEV 판별·라우팅(TypeSafe/OpenRouter), 규칙 기반 대체, 라우팅 정책, 사용량·예산 기록
- M3(분석·점수): Haiku 경량 분석, Sonnet/Opus 도구 기반 심층 분석, 불확실 시 한 단계 상향, 거부 대비 fallback, Batch API, 자동 종결 감사 피드백, 위험도 산정
- M4(알림·UI): Slack/이메일 즉시 알림과 일일 요약, Finding 상세와 처리, 사용량 대시보드
- M5(평가): 성공 지표 리포트, 정답 셋, 정확도·놓친 비율, 자동 종결 임계값 보정, 캐스케이드 vs Opus 단일 비교 실험
- 실행·배포: `.env` 설정 관리, `run.sh` 실행, `build.sh` 배포 번들

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
