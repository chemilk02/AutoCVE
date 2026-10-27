"""저장소 clone.

- https URL만 받는다. `ext::` 같은 git 전송 방식이나 옵션 주입을 막기 위해서다.
- GitHub PAT는 github.com 저장소에만 붙인다. 다른 호스트로 토큰이 새지 않게 하기 위해서다.
- 토큰은 URL이나 명령행 인자가 아니라 환경변수로 넘긴다 (프로세스 목록, .git/config에 남지 않게).
"""

import base64
import os
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

CLONE_TIMEOUT_SECONDS = 300
GITHUB_HOSTS = {"github.com", "www.github.com"}


class RepoError(Exception):
    pass


def validate_repo_url(url: str) -> str:
    url = url.strip()
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise RepoError("저장소 주소는 계정 정보가 없는 https:// URL이어야 합니다")
    if url.startswith("-") or " " in url:
        raise RepoError("저장소 주소 형식이 올바르지 않습니다")
    return url


def is_github(url: str) -> bool:
    return (urlsplit(url).hostname or "").lower() in GITHUB_HOSTS


def _git_env(token: str | None, allow_protocols: str) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": allow_protocols,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE", "GIT_SSL_CAINFO"):
        if key in os.environ:
            env[key] = os.environ[key]
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env.update(
            {
                "GIT_CONFIG_COUNT": "2",
                "GIT_CONFIG_KEY_0": "http.extraHeader",
                "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}",
                # 다른 호스트로 리다이렉트되면 토큰 헤더가 따라가지 않도록 막는다.
                "GIT_CONFIG_KEY_1": "http.followRedirects",
                "GIT_CONFIG_VALUE_1": "false",
            }
        )
    return env


def clone(
    url: str,
    dest: Path,
    *,
    branch: str | None = None,
    token: str | None = None,
    allow_local: bool = False,
) -> str:
    """얕은 clone 후 HEAD 커밋 해시를 돌려준다. `allow_local`은 테스트용이다."""
    if not allow_local:
        url = validate_repo_url(url)
    token = token if token and is_github(url) else None
    cmd = ["git", "clone", "--depth", "1", "--single-branch", "--no-tags", "--quiet"]
    if branch:
        cmd += ["--branch", branch]
    cmd += ["--", url, str(dest)]
    env = _git_env(token, "https:file" if allow_local else "https")
    try:
        subprocess.run(
            cmd, env=env, check=True, capture_output=True, text=True, timeout=CLONE_TIMEOUT_SECONDS
        )
        head = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.TimeoutExpired as e:
        raise RepoError("저장소 clone 시간이 초과되었습니다") from e
    except subprocess.CalledProcessError as e:
        # git 오류 메시지에는 URL이 들어갈 수 있지만 토큰은 환경변수로만 넘겼으므로 포함되지 않는다.
        detail = (e.stderr or "").strip().splitlines()[-1:] or ["알 수 없는 오류"]
        raise RepoError(f"저장소를 clone하지 못했습니다: {detail[0][:200]}") from e
    return head.stdout.strip()
