"""로그와 에러 메시지에서 API 키를 가린다.

알려진 형식(Anthropic, OpenRouter, Bearer 헤더)은 패턴으로 가리고,
형식이 알려지지 않은 키(TypeSafe 등)는 사용 시점에 `register_secret`으로 등록해
문자열 그대로 가린다.
"""

import logging
import re
import threading
from collections.abc import Mapping

MASK = "[REDACTED]"

_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"sk-or-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"(?i)(?<=bearer )[A-Za-z0-9._~+/=\-]{8,}"),
    re.compile(r"(?i)(?<=x-api-key)(['\"]?\s*[:=]\s*['\"]?)[^'\"\s,}]+"),
]

_secrets: set[str] = set()
_lock = threading.Lock()


def register_secret(value: str) -> None:
    # 너무 짧은 값은 일반 문자열까지 가려 버리므로 등록하지 않는다.
    if len(value) >= 8:
        with _lock:
            _secrets.add(value)


def redact(text: str) -> str:
    with _lock:
        secrets = sorted(_secrets, key=len, reverse=True)
    for secret in secrets:
        text = text.replace(secret, MASK)
    for pattern in _PATTERNS:
        if pattern.groups:
            text = pattern.sub(lambda m: m.group(1) + MASK, text)
        else:
            text = pattern.sub(MASK, text)
    return text


def _redact_value(value: object) -> object:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact(value if isinstance(value, str) else str(value))


def _redact_args(record: logging.LogRecord) -> bool:
    """args 구조를 유지한 채 값만 가린다. 결과에 키가 남거나 포맷이 깨지면 False."""
    if not record.args:
        return False
    if isinstance(record.args, tuple):
        args: object = tuple(_redact_value(a) for a in record.args)
    elif isinstance(record.args, Mapping):
        args = {k: _redact_value(v) for k, v in record.args.items()}
    else:
        return False
    msg = redact(str(record.msg))
    try:
        message = msg % args
    except (TypeError, ValueError, KeyError):
        return False
    if redact(message) != message:
        return False
    record.msg, record.args = msg, args
    return True


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        redacted = redact(message)
        # uvicorn 액세스 로그처럼 포매터가 record.args를 직접 쓰는 경우가 있으므로,
        # 가릴 것이 없으면 그대로 두고, 있으면 가능한 한 args 구조를 남긴다.
        if redacted != message and not _redact_args(record):
            record.msg, record.args = redacted, None
        if record.exc_info:
            # 예외 메시지에도 키가 섞일 수 있으므로 미리 포맷해서 가린다.
            record.exc_text = redact(logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
        return True


def install_log_redaction() -> None:
    """현재 등록된 모든 로그 핸들러에 필터를 붙인다. 로깅 설정 이후에 호출한다."""
    redacting = RedactingFilter()
    loggers = [logging.getLogger()]
    loggers += [
        logger
        for logger in logging.Logger.manager.loggerDict.values()
        if isinstance(logger, logging.Logger)
    ]
    for logger in loggers:
        for handler in logger.handlers:
            if not any(isinstance(f, RedactingFilter) for f in handler.filters):
                handler.addFilter(redacting)
