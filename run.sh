#!/usr/bin/env bash
# AutoCVE 실행 스크립트. 설정은 모두 .env에서 읽는다 (.env.example 참고).
#
#   ./run.sh up          .env 준비 → (이미지 빌드 또는 적재) → 실행 → 상태 확인
#   ./run.sh down        중지 (데이터는 유지)
#   ./run.sh restart     .env를 바꾼 뒤 앱과 워커를 새 설정으로 다시 시작
#   ./run.sh logs [서비스]  로그 보기 (app, worker, db, redis)
#   ./run.sh status      컨테이너 상태
#   ./run.sh cli ...     운영 CLI (예: ./run.sh cli scan 1)
#   ./run.sh backup      DB를 backups/에 덤프
#   ./run.sh dev         Docker 없이 로컬에서 실행 (PostgreSQL, Redis, .venv 필요)
set -euo pipefail

cd "$(dirname "$0")"
ENV_FILE=.env

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m경고:\033[0m %s\n' "$*" >&2; }
die() {
  printf '\033[1;31m오류:\033[0m %s\n' "$*" >&2
  exit 1
}

# .env에서 값 하나를 읽는다. 따옴표는 벗긴다.
# 읽기에 실패하면 (set -e로) 멈춘다. 빈 값으로 오인해 마스터 키를 다시 만들면 안 된다.
env_get() {
  [ -f "$ENV_FILE" ] || return 0
  awk -v key="$1" -v q="'" '
    $0 ~ "^[[:space:]]*" key "=" {
      v = $0
      sub(/^[^=]*=/, "", v)
      sub(/\r$/, "", v)
      first = substr(v, 1, 1)
      if (length(v) >= 2 && (first == "\"" || first == q) && substr(v, length(v), 1) == first)
        v = substr(v, 2, length(v) - 2)
      found = v
    }
    END { printf "%s", found }
  ' "$ENV_FILE"
}

# .env의 값을 바꾼다. 줄이 없으면 끝에 붙인다.
env_set() {
  local tmp
  tmp=$(mktemp "$ENV_FILE.XXXXXX")
  awk -v key="$1" -v value="$2" '
    BEGIN { done = 0 }
    $0 ~ "^[[:space:]]*" key "=" { if (!done) print key "=" value; done = 1; next }
    { print }
    END { if (!done) print key "=" value }
  ' "$ENV_FILE" >"$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$ENV_FILE"
}

random_b64() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 "$1"
  else
    head -c "$1" /dev/urandom | base64 | tr -d '\n'
  fi
}

random_hex() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$1"
  else
    head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

prepare_env() {
  local created=0 master_key db_password
  if [ ! -f "$ENV_FILE" ]; then
    [ -f .env.example ] || die ".env.example이 없습니다"
    (umask 077 && cp .env.example "$ENV_FILE")
    created=1
    info ".env를 만들었습니다 (.env.example 복사)"
  fi
  # 대입으로 읽어야 읽기 실패 시 set -e로 멈춘다 ([ ] 안의 $(...)는 실패를 무시한다).
  master_key=$(env_get AUTOCVE_MASTER_KEY)
  db_password=$(env_get AUTOCVE_DB_PASSWORD)
  if [ -z "$master_key" ]; then
    env_set AUTOCVE_MASTER_KEY "$(random_b64 32)"
    warn "AUTOCVE_MASTER_KEY를 새로 만들었습니다. 이 값을 잃어버리면 저장된 API 키를 복호화할 수 없으니 .env를 안전한 곳에 백업하세요."
  fi
  # DB 비밀번호는 DB를 처음 만들 때만 적용되므로, .env를 새로 만들 때만 생성한다.
  if [ "$created" = 1 ] && [ -z "$db_password" ]; then
    env_set AUTOCVE_DB_PASSWORD "$(random_hex 16)"
  fi
  check_env
}

check_env() {
  local key bytes bind password db_password
  key=$(env_get AUTOCVE_MASTER_KEY)
  bytes=$(printf '%s' "$key" | base64 -d 2>/dev/null | wc -c | tr -d ' ')
  [ "$bytes" = 32 ] || die "AUTOCVE_MASTER_KEY는 base64로 인코딩한 32바이트여야 합니다 (.env 확인)"
  db_password=$(env_get AUTOCVE_DB_PASSWORD)
  case "$db_password" in
    *[!A-Za-z0-9_-]*) die "AUTOCVE_DB_PASSWORD에는 영문, 숫자, -, _만 쓸 수 있습니다" ;;
  esac
  bind=$(env_get AUTOCVE_BIND)
  password=$(env_get AUTOCVE_ADMIN_PASSWORD)
  if [ -n "$bind" ] && [ "$bind" != 127.0.0.1 ] && [ "$bind" != localhost ] && [ -z "$password" ]; then
    warn "AUTOCVE_BIND=$bind 로 외부에 열지만 AUTOCVE_ADMIN_PASSWORD가 비어 있어 누구나 접속할 수 있습니다."
  fi
  if [ -n "$(env_get AUTOCVE_JEV_PROVIDER)" ]; then
    case "$(env_get AUTOCVE_JEV_PROVIDER)" in
      none | typesafe | openrouter) ;;
      *) die "AUTOCVE_JEV_PROVIDER는 none, typesafe, openrouter 중 하나여야 합니다" ;;
    esac
  fi
  if [ -z "$(env_get AUTOCVE_ANTHROPIC_API_KEY)" ]; then
    info "AUTOCVE_ANTHROPIC_API_KEY가 비어 있습니다. 웹 화면(설정 > API 키)에서 입력하세요."
  fi
}

COMPOSE=()
find_compose() {
  command -v docker >/dev/null 2>&1 || die "docker가 없습니다. Docker를 먼저 설치하세요"
  if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
  else
    die "Docker Compose가 없습니다 (docker compose 플러그인을 설치하세요)"
  fi
}

compose() { "${COMPOSE[@]}" "$@"; }

# 배포 번들에는 Dockerfile 대신 이미지 파일이 들어 있다.
load_bundle_images() {
  local image
  image=$(env_get AUTOCVE_IMAGE)
  [ -n "$image" ] || image=$(cat IMAGE 2>/dev/null || true)
  [ -n "$image" ] || die "실행할 이미지를 알 수 없습니다 (IMAGE 파일 또는 AUTOCVE_IMAGE)"
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    [ -f images/autocve.tar.gz ] || die "이미지 $image 이 없고 images/autocve.tar.gz도 없습니다"
    info "이미지 적재: images/autocve.tar.gz"
    gunzip -c images/autocve.tar.gz | docker load
  fi
  if [ -f images/deps.tar.gz ]; then
    for dep in postgres:16-alpine redis:7-alpine; do
      if ! docker image inspect "$dep" >/dev/null 2>&1; then
        info "의존 이미지 적재: images/deps.tar.gz"
        gunzip -c images/deps.tar.gz | docker load
        break
      fi
    done
  fi
  export AUTOCVE_IMAGE="$image"
}

wait_healthy() {
  local port bind host i status
  port=$(env_get AUTOCVE_PORT)
  bind=$(env_get AUTOCVE_BIND)
  host=${bind:-127.0.0.1}
  [ "$host" = 0.0.0.0 ] && host=127.0.0.1
  info "앱이 준비되기를 기다립니다"
  for i in $(seq 1 60); do
    status=$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q app)" 2>/dev/null || true)
    case "$status" in
      healthy)
        info "실행 중: http://$host:${port:-8000}"
        info "처음 실행이면 워커가 OSV 전체 덤프를 적재합니다 (수 분). 진행 상황: ./run.sh logs worker"
        return 0
        ;;
      unhealthy) break ;;
    esac
    sleep 2
  done
  fail_logs
}

fail_logs() {
  compose logs --tail=40 app >&2 || true
  die "앱이 정상 상태가 되지 않았습니다. 위 로그나 ./run.sh logs app 으로 확인하세요"
}

cmd_up() {
  prepare_env
  find_compose
  local args=(up -d)
  if [ -f Dockerfile ]; then
    args+=(--build)
  else
    load_bundle_images
  fi
  # 워커는 앱이 정상 상태가 된 뒤 시작하므로, 앱이 실패하면 여기서 멈춘다.
  compose "${args[@]}" || fail_logs
  wait_healthy
}

cmd_restart() {
  check_env
  find_compose
  [ -f Dockerfile ] || load_bundle_images
  # restart는 .env 변경을 반영하지 않으므로 컨테이너를 다시 만든다.
  compose up -d --force-recreate app worker || fail_logs
  wait_healthy
}

cmd_backup() {
  find_compose
  (umask 077 && mkdir -p backups)
  local file
  file="backups/autocve-$(date +%Y%m%d-%H%M%S).sql.gz"
  (umask 077 && compose exec -T db pg_dump -U autocve autocve | gzip >"$file")
  info "DB 백업: $file (API 키는 암호화된 상태로 들어 있으며, 복구하려면 같은 AUTOCVE_MASTER_KEY가 필요합니다)"
}

cmd_dev() {
  prepare_env
  local py=python3
  [ -x .venv/bin/python ] && py=.venv/bin/python
  "$py" -c "import autocve" 2>/dev/null || die "autocve 패키지가 없습니다: python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'"
  info "DB 마이그레이션"
  "$py" -m alembic upgrade head
  info "워커 시작"
  "$py" -m arq autocve.worker.WorkerSettings &
  local worker=$!
  trap 'kill "$worker" 2>/dev/null || true' EXIT INT TERM
  local port
  port=$(env_get AUTOCVE_PORT)
  info "웹 시작: http://127.0.0.1:${port:-8000}"
  "$py" -m uvicorn autocve.api.app:create_app --factory --reload --host 127.0.0.1 --port "${port:-8000}"
}

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
}

main() {
  local cmd=${1:-up}
  [ $# -gt 0 ] && shift
  case "$cmd" in
    up) cmd_up ;;
    down)
      find_compose
      compose down
      ;;
    restart) cmd_restart ;;
    logs)
      find_compose
      compose logs -f --tail=200 "$@"
      ;;
    status | ps)
      find_compose
      compose ps
      ;;
    cli)
      find_compose
      # 파이프나 cron에서 부를 때는 TTY를 붙이지 않는다.
      if [ -t 0 ]; then
        compose exec app python -m autocve.cli "$@"
      else
        compose exec -T app python -m autocve.cli "$@"
      fi
      ;;
    backup) cmd_backup ;;
    dev) cmd_dev ;;
    -h | --help | help) usage ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
