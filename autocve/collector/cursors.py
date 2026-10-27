from sqlalchemy.orm import Session

from autocve.models import FeedCursor


def get_cursor(session: Session, source: str) -> str | None:
    cursor = session.get(FeedCursor, source)
    return cursor.cursor if cursor else None


def set_cursor(session: Session, source: str, value: str | None) -> None:
    cursor = session.get(FeedCursor, source)
    if cursor is None:
        session.add(FeedCursor(source=source, cursor=value))
    else:
        cursor.cursor = value
