"""
Central place to write audit log entries. Every security-relevant event
(upload, risk analysis, rotation, re-encryption, download) goes through here
so the audit trail stays consistent and complete.
"""

from sqlalchemy.orm import Session

from models.models import AuditLog


def log_event(
    db: Session,
    action: str,
    file_id: int | None = None,
    user_id: int | None = None,
    old_version: int | None = None,
    new_version: int | None = None,
    risk_score: float | None = None,
    details: str | None = None,
) -> AuditLog:
    entry = AuditLog(
        file_id=file_id,
        user_id=user_id,
        action=action,
        old_version=old_version,
        new_version=new_version,
        risk_score=risk_score,
        details=details,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
