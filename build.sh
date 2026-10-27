#!/usr/bin/env bash
# AutoCVE 배포 번들을 만든다.
#
#   ./build.sh                 검사 → 이미지 빌드 → dist/autocve-<버전>.tar.gz
#   ./build.sh --skip-tests    검사(ruff, pytest) 생략
#   ./build.sh --offline       postgres, redis 이미지도 번들에 넣는다 (인터넷 없는 서버용)
#   ./build.sh --image-only    번들 없이 Docker 이미지만 빌드
#   ./build.sh --dockerfile F  다른 Dockerfile로 빌드
#   ./build.sh -- ARGS...      나머지 인자를 docker build에 그대로 넘긴다 (예: -- --build-arg X=1)
#
# 번들을 서버에 복사한 뒤:
#   tar xzf autocve-<버전>.tar.gz && cd autocve-<버전> && ./run.sh up
set -euo pipefail

cd "$(dirname "$0")"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() {
  printf '\033[1;31m오류:\033[0m %s\n' "$*" >&2
  exit 1
}

RUN_TESTS=1
OFFLINE=0
BUNDLE=1
DOCKERFILE=Dockerfile
BUILD_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --skip-tests) RUN_TESTS=0 ;;
    --offline) OFFLINE=1 ;;
    --image-only) BUNDLE=0 ;;
    --dockerfile)
      [ $# -ge 2 ] || die "--dockerfile 다음에 파일 경로를 주세요"
      DOCKERFILE=$2
      shift
      ;;
    --)
      shift
      BUILD_ARGS=("$@")
      break
      ;;
    -h | --help)
      sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) die "알 수 없는 옵션: $1 (./build.sh --help)" ;;
  esac
  shift
done

command -v docker >/dev/null 2>&1 || die "docker가 없습니다"
[ -f "$DOCKERFILE" ] || die "$DOCKERFILE 이 없습니다"

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml | head -n 1)
[ -n "$VERSION" ] || die "pyproject.toml에서 버전을 읽지 못했습니다"
if git rev-parse --short HEAD >/dev/null 2>&1; then
  VERSION="$VERSION-$(git rev-parse --short HEAD)"
  if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    VERSION="$VERSION-dirty"
  fi
fi
IMAGE="autocve:$VERSION"
NAME="autocve-$VERSION"

if [ "$RUN_TESTS" = 1 ]; then
  py=python3
  [ -x .venv/bin/python ] && py=.venv/bin/python
  "$py" -m pytest --version >/dev/null 2>&1 ||
    die "pytest가 없습니다. pip install -e '.[dev]' 후 다시 실행하거나 --skip-tests를 쓰세요"
  info "검사: ruff, pytest"
  "$py" -m ruff check .
  "$py" -m ruff format --check .
  "$py" -m pytest -q
fi

info "이미지 빌드: $IMAGE"
docker build -f "$DOCKERFILE" -t "$IMAGE" -t autocve:latest ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"} .

if [ "$BUNDLE" = 0 ]; then
  info "완료: $IMAGE"
  exit 0
fi

OUT="dist/$NAME"
rm -rf "$OUT" "dist/$NAME.tar.gz"
mkdir -p "$OUT/images"

info "이미지 저장"
docker save "$IMAGE" | gzip >"$OUT/images/autocve.tar.gz"
if [ "$OFFLINE" = 1 ]; then
  for dep in postgres:16-alpine redis:7-alpine; do
    docker image inspect "$dep" >/dev/null 2>&1 || docker pull "$dep"
  done
  docker save postgres:16-alpine redis:7-alpine | gzip >"$OUT/images/deps.tar.gz"
fi

# 번들에는 소스가 없으므로 build 항목을 빼고 이미지 태그를 이 버전으로 고정한다.
grep -v '^    build: \.$' docker-compose.yml |
  sed "s|\${AUTOCVE_IMAGE:-autocve:local}|\${AUTOCVE_IMAGE:-$IMAGE}|" >"$OUT/docker-compose.yml"
grep -q 'build:' "$OUT/docker-compose.yml" && die "번들 compose에 build 항목이 남았습니다"
printf '%s\n' "$IMAGE" >"$OUT/IMAGE"
cp .env.example run.sh "$OUT/"
chmod +x "$OUT/run.sh"

cat >"$OUT/README.md" <<EOF
# AutoCVE $VERSION 배포 번들

Docker와 Docker Compose 플러그인이 있는 Linux 서버에서 실행합니다.

## 설치

\`\`\`bash
./run.sh up
\`\`\`

처음 실행하면 \`.env.example\`을 \`.env\`로 복사하고 마스터 키와 DB 비밀번호를 만들어 넣습니다.
**\`.env\`를 안전한 곳에 백업하세요.** 마스터 키를 잃어버리면 저장된 API 키를 복호화할 수 없습니다.

API 키, JEV 제공자, 예산, 알림은 \`.env\`에 넣거나 웹 화면에서 설정합니다.
\`.env\`에 넣은 값은 웹 화면에서 바꿀 수 없습니다. \`.env\`를 고친 뒤에는 \`./run.sh restart\`를 실행하세요.

외부에서 접속하려면 \`AUTOCVE_BIND=0.0.0.0\`과 \`AUTOCVE_ADMIN_PASSWORD\`를 설정하세요.
인터넷에 열 때는 HTTPS 리버스 프록시(Caddy, nginx 등) 뒤에 두는 것을 권장합니다.

## 명령

| 명령 | 내용 |
|------|------|
| \`./run.sh up\` | 실행 (이미지가 없으면 \`images/\`에서 적재) |
| \`./run.sh down\` | 중지 (데이터 유지) |
| \`./run.sh restart\` | \`.env\` 변경 반영 |
| \`./run.sh logs [app\\|worker]\` | 로그 |
| \`./run.sh status\` | 상태 |
| \`./run.sh cli <명령>\` | 운영 CLI (예: \`./run.sh cli scan 1\`) |
| \`./run.sh backup\` | DB 백업 (\`backups/\`) |

## 업그레이드

새 번들을 풀고 기존 \`.env\`를 복사한 뒤 실행합니다. DB는 Docker 볼륨(\`autocve_db-data\`)에 있으므로 그대로 이어집니다.
앱이 시작할 때 DB 마이그레이션을 자동으로 적용합니다.

\`\`\`bash
./run.sh backup                      # 이전 번들 폴더에서
tar xzf autocve-<새 버전>.tar.gz
cp autocve-<이전 버전>/.env autocve-<새 버전>/
cd autocve-<새 버전> && ./run.sh up
\`\`\`
EOF

info "번들 압축"
tar -C dist -czf "dist/$NAME.tar.gz" "$NAME"
if command -v sha256sum >/dev/null 2>&1; then
  (cd dist && sha256sum "$NAME.tar.gz" >"$NAME.tar.gz.sha256")
else
  (cd dist && shasum -a 256 "$NAME.tar.gz" >"$NAME.tar.gz.sha256")
fi

info "완료"
printf '  이미지  %s\n  번들    dist/%s.tar.gz (%s)\n' \
  "$IMAGE" "$NAME" "$(du -h "dist/$NAME.tar.gz" | cut -f1)"
