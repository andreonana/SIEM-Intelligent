# backend/app/services/audit_service.py
#
# Journalisation des actions utilisateurs (CDC — traçabilité obligatoire).
# Toutes les actions sensibles sont persistées en SQL.
# Actions reconnues : login | logout | create_user | role_update | alert_view | alert_acknowledge

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from app.models.audit_log import AuditLog


async def log_action(
    db: AsyncSession,
    username: str,
    action: str,
    target: str | None = None,
    detail: str | None = None,
    ip_address: str | None = None,
    result: str = "success",
    role: str | None = None,
) -> AuditLog:
    entry = AuditLog(
        username=username,
        role=role,
        action=action,
        target=target,
        detail=detail,
        ip_address=ip_address,
        result=result,
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry


async def get_audit_logs(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 50,
    username_filter: str | None = None,
    action_filter: str | None = None,
) -> dict:
    query = select(AuditLog).order_by(desc(AuditLog.timestamp))
    if username_filter:
        query = query.where(AuditLog.username == username_filter)
    if action_filter:
        query = query.where(AuditLog.action == action_filter)

    offset = (page - 1) * page_size
    result = await db.execute(query.offset(offset).limit(page_size))
    entries = result.scalars().all()

    count_q = select(func.count()).select_from(AuditLog)
    if username_filter:
        count_q = count_q.where(AuditLog.username == username_filter)
    if action_filter:
        count_q = count_q.where(AuditLog.action == action_filter)
    total = (await db.execute(count_q)).scalar_one()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "entries": [
            {
                "id":         e.id,
                "timestamp":  e.timestamp.isoformat() if e.timestamp else None,
                "username":   e.username,
                "role":       e.role,
                "action":     e.action,
                "target":     e.target,
                "detail":     e.detail,
                "ip_address": e.ip_address,
                "result":     e.result,
            }
            for e in entries
        ],
    }
