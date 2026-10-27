"""알림 채널: Slack Incoming Webhook, 이메일(SMTP)."""

import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol

import httpx

from autocve.notify.messages import Message


class NotifyError(Exception):
    pass


class Channel(Protocol):
    name: str

    def send(self, message: Message) -> None: ...


SLACK_PREFIX = "https://hooks.slack.com/"


class SlackChannel:
    name = "slack"

    def __init__(self, webhook_url: str, http: httpx.Client | None = None):
        if not webhook_url.startswith(SLACK_PREFIX):
            raise NotifyError("Slack Webhook 주소 형식이 아닙니다")
        self._url = webhook_url
        self._http = http or httpx.Client(timeout=15.0)

    def send(self, message: Message) -> None:
        payload = {"text": message.subject, "blocks": message.slack_blocks()}
        try:
            response = self._http.post(self._url, json=payload)
        except httpx.HTTPError as e:
            raise NotifyError(f"Slack 전송 실패: {type(e).__name__}") from e
        if not response.is_success:
            # 응답 본문에는 웹훅 주소가 들어 있지 않다. 상태 코드와 짧은 사유만 남긴다.
            raise NotifyError(
                f"Slack 전송 실패 (HTTP {response.status_code}: {response.text[:80]})"
            )


@dataclass
class SmtpConfig:
    host: str
    port: int
    username: str | None
    password: str | None
    sender: str
    starttls: bool = True


class EmailChannel:
    name = "email"

    def __init__(self, config: SmtpConfig, recipients: list[str], smtp_factory=smtplib.SMTP):
        if not recipients:
            raise NotifyError("받는 사람이 없습니다")
        self._config = config
        self._recipients = recipients
        self._smtp_factory = smtp_factory

    def send(self, message: Message) -> None:
        email = EmailMessage()
        email["Subject"] = message.subject
        email["From"] = self._config.sender
        email["To"] = ", ".join(self._recipients)
        email.set_content(message.plain_text())
        try:
            with self._smtp_factory(self._config.host, self._config.port, timeout=20) as smtp:
                if self._config.starttls:
                    smtp.starttls()
                if self._config.username:
                    smtp.login(self._config.username, self._config.password or "")
                smtp.send_message(email)
        except (smtplib.SMTPException, OSError) as e:
            raise NotifyError(f"이메일 전송 실패: {type(e).__name__}") from e
