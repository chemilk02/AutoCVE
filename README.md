# AutoCVE

공개 취약점 DB(OSV, EPSS, CISA KEV)를 주기적으로 수집합니다. 새 취약점이 연결된 저장소에 실제로 영향을 주는지 판별하고, 근거와 위험도를 알려주는 서비스입니다.

- **판별 우선**: 저비용 판별 모델 JEV가 먼저 위험 여부와 분석 모델(없음/Haiku/Sonnet/Opus)을 정합니다. Claude는 근거가 필요한 경우에만 호출합니다.
- **BYOK**: 사용자 본인의 Anthropic API 키(필수)와 JEV 키(선택)를 사용합니다. JEV는 TypeSafe에 직접 호출하거나 OpenRouter를 거쳐 호출할 수 있습니다.

## 문서

- [MVP 범위](docs/01-mvp-scope.md)
- [아키텍처](docs/02-architecture.md)

## 상태

M0(기반) 완료: 저장소 골격, DB 스키마, Docker Compose, API 키 저장소.
취약점 수집과 분석 기능은 M1부터 들어갑니다.

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

   거부된 키는 저장하지 않습니다. 네트워크 문제로 검증하지 못한 키는 "검증 못 함" 상태로 저장되며, 나중에 재검증할 수 있습니다.

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
  api/            # FastAPI 앱, 접근 제어(Basic 인증, 출처 검사), 설정 화면 라우트
  credentials/    # 제공자별 키 검증, 키 저장/재검증/삭제 서비스
  security/       # keyvault.py(AES-256-GCM 암호화), redaction.py(로그 키 마스킹)
  web/            # 템플릿, CSS
  models.py       # DB 스키마 (docs/02-architecture.md §7)
  worker.py       # arq 워커 (M0는 heartbeat만)
migrations/       # Alembic
tests/
```
