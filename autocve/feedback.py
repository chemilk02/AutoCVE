"""사용자 판정 처리 (§F11). 시스템 판정과 함께 기록해 평가(M5)와 임계값 보정에 쓴다."""

from sqlalchemy.orm import Session

from autocve.models import Feedback, FeedbackAction, Finding, FindingStatus, Verdict
from autocve.scoring.risk import score_findings


class FeedbackError(Exception):
    pass


def apply_feedback(
    session: Session, finding: Finding, action: FeedbackAction, reason: str | None = None
) -> Feedback:
    reason = (reason or "").strip() or None
    if action == FeedbackAction.NOT_AFFECTED and not reason:
        raise FeedbackError("해당 없음으로 처리하려면 사유를 적어 주세요")

    record = Feedback(
        finding_id=finding.id,
        user_verdict=action.value,
        reason=reason,
        system_verdict=finding.verdict,
    )
    session.add(record)
    if action == FeedbackAction.CONFIRM:
        finding.verdict = Verdict.AFFECTED
        if finding.status not in (FindingStatus.NOTIFIED,):
            finding.status = FindingStatus.ANALYZED
    elif action == FeedbackAction.NOT_AFFECTED:
        finding.verdict = Verdict.NOT_AFFECTED
        finding.status = FindingStatus.DISMISSED
    elif action == FeedbackAction.FIXED:
        # 취약한 버전이 그대로 남아 있으면 다음 매칭에서 다시 열린다.
        finding.status = FindingStatus.RESOLVED
    elif action == FeedbackAction.REOPEN:
        finding.status = FindingStatus.ANALYZED
        if finding.verdict == Verdict.NOT_AFFECTED:
            finding.verdict = Verdict.UNCERTAIN
    session.commit()
    score_findings(session, finding_ids=[finding.id], include_closed=True)
    return record
