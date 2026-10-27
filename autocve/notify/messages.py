"""알림 메시지 구성. Slack 블록과 이메일 본문을 같은 데이터에서 만든다."""

from dataclasses import dataclass, field

from autocve.scoring.risk import GRADE_LABELS

VERDICT_LABELS = {
    "affected": "영향 있음",
    "uncertain": "판단 보류",
    "not_affected": "영향 없음",
    None: "분석 전",
}
MAX_ITEMS = 30
SLACK_TEXT_LIMIT = 2900  # Slack 섹션 블록 텍스트 한도(3000자)보다 조금 작게


@dataclass
class Item:
    grade: str
    score: float
    project: str
    package: str
    advisory_id: str
    summary: str
    verdict: str | None
    rationale: str
    url: str

    def line(self) -> str:
        grade = GRADE_LABELS.get(self.grade, self.grade)
        return f"[{grade} {self.score:.0f}] {self.project} · {self.package} · {self.advisory_id}"


@dataclass
class Message:
    subject: str
    intro: str
    items: list[Item] = field(default_factory=list)
    footer: str = ""

    def _shown(self) -> tuple[list[Item], int]:
        return self.items[:MAX_ITEMS], max(0, len(self.items) - MAX_ITEMS)

    def plain_text(self) -> str:
        shown, hidden = self._shown()
        lines = [self.intro, ""]
        for item in shown:
            lines.append(item.line())
            lines.append(f"  {item.summary}")
            lines.append(f"  판정: {VERDICT_LABELS.get(item.verdict, item.verdict)}")
            if item.rationale:
                lines.append(f"  근거: {item.rationale}")
            lines.append(f"  {item.url}")
            lines.append("")
        if hidden:
            lines.append(f"외 {hidden}건은 웹 화면에서 확인하세요.")
        if self.footer:
            lines.append(self.footer)
        return "\n".join(lines).strip() + "\n"

    def slack_blocks(self) -> list[dict]:
        shown, hidden = self._shown()
        blocks: list[dict] = [{"type": "section", "text": {"type": "mrkdwn", "text": self.intro}}]
        for item in shown:
            text = (
                f"*<{item.url}|{_escape(item.line())}>*\n{_escape(item.summary)}\n"
                f"판정: {VERDICT_LABELS.get(item.verdict, item.verdict)}"
            )
            if item.rationale:
                text += f"\n{_escape(item.rationale)}"
            blocks.append(
                {"type": "section", "text": {"type": "mrkdwn", "text": text[:SLACK_TEXT_LIMIT]}}
            )
        if hidden:
            blocks.append(
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"외 {hidden}건은 웹 화면에서 확인하세요."}
                    ],
                }
            )
        return blocks


def _escape(text: str) -> str:
    # Slack mrkdwn 제어 문자. 취약점 요약은 외부 데이터라 그대로 넣지 않는다.
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
