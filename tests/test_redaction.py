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
