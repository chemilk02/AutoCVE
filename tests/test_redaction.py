import io
import logging

from autocve.security.redaction import MASK, RedactingFilter, redact, register_secret


def test_redacts_known_key_formats():
    text = (
        "anthropic=sk-ant-api03-abcdefghijkl openrouter=sk-or-v1-0123456789abcdef "
        "Authorization: Bearer abcdefghijklmnop x-api-key: 'zzzzzzzzzzzz'"
    )
    redacted = redact(text)
    assert "sk-ant-api03" not in redacted
    assert "sk-or-v1" not in redacted
    assert "abcdefghijklmnop" not in redacted
    assert "zzzzzzzzzzzz" not in redacted
    assert redacted.count(MASK) == 4


def test_redacts_registered_secret_of_unknown_format():
    register_secret("typesafe-key-7f3a9c")
    assert redact("calling with typesafe-key-7f3a9c now") == f"calling with {MASK} now"


def test_ignores_short_secrets():
    register_secret("abc")
    assert redact("abc") == "abc"


def test_log_filter_redacts_message_args_and_exception(caplog):
    logger = logging.getLogger("test.redaction")
    caplog.handler.addFilter(RedactingFilter())
    try:
        raise RuntimeError("failed with sk-ant-api03-exceptionkey")
    except RuntimeError:
        logger.exception("request with %s", "sk-or-v1-argumentkey123")

    output = caplog.text
    assert "sk-or-v1-argumentkey123" not in output
    assert "sk-ant-api03-exceptionkey" not in output
    assert MASK in output


def test_log_filter_keeps_args_for_uvicorn_access_formatter(capsys):
    from uvicorn.logging import AccessFormatter

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(
        AccessFormatter('%(client_addr)s - "%(request_line)s" %(status_code)s', use_colors=False)
    )
    handler.addFilter(RedactingFilter())
    logger = logging.getLogger("test.redaction.access")
    logger.addHandler(handler)
    logger.propagate = False
    access = '%s - "%s %s HTTP/%s" %d'
    try:
        logger.warning(access, "127.0.0.1:5000", "GET", "/healthz", "1.1", 200)
        logger.warning(access, "127.0.0.1:5000", "GET", "/x?k=sk-or-v1-querykey123", "1.1", 401)
    finally:
        logger.removeHandler(handler)

    lines = stream.getvalue().splitlines()
    assert lines == [
        '127.0.0.1:5000 - "GET /healthz HTTP/1.1" 200 OK',
        f'127.0.0.1:5000 - "GET /x?k={MASK} HTTP/1.1" 401 Unauthorized',
    ]
    assert "Logging error" not in capsys.readouterr().err


def test_log_filter_falls_back_when_args_cannot_be_kept(caplog):
    logger = logging.getLogger("test.redaction.fallback")
    caplog.handler.addFilter(RedactingFilter())
    logger.warning("payload %r", {"x-api-key": "zzzzzzzzzzzz"})
    logger.warning("dict style %(key)s", {"key": "sk-ant-api03-mappingkey"})

    assert "zzzzzzzzzzzz" not in caplog.text
    assert "sk-ant-api03-mappingkey" not in caplog.text
    assert caplog.text.count(MASK) == 2
