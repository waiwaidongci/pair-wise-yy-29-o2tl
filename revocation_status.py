"""预约撤销的状态判断：时刻解析、状态推导以及对核验结果的影响。"""
from __future__ import annotations

from datetime import datetime, timezone

PENDING = "pending"      # 待生效
EFFECTIVE = "effective"  # 已生效
CANCELLED = "cancelled"  # 已取消

STATUSES = (PENDING, EFFECTIVE, CANCELLED)


class ApiError(Exception):
    """业务校验失败，携带 HTTP 状态码。"""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None = None) -> str:
    return (value or now()).astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value: str | None) -> datetime:
    if not value:
        return now()
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def status_at(record, at: datetime) -> str:
    """判断记录在指定时刻的状态：到点的待生效预约按已生效处理。"""
    if record["status"] == PENDING and parse_time(record["effective_at"]) <= at:
        return EFFECTIVE
    return record["status"]


def verify_effect(record, check_at: datetime) -> dict:
    """待生效预约对核验结果的影响：生效时刻前原证继续可用，越过即按撤销处理。"""
    if check_at >= parse_time(record["effective_at"]):
        return {"valid": False, "status": "revoked", "reason": record["reason"]}
    return {"status": "valid_until_revocation", "revocation_starts_at": record["effective_at"]}


def group_by_status(records: list, at: datetime) -> dict:
    """按待生效、已生效、已取消分组，供页面列出。"""
    groups = {PENDING: [], EFFECTIVE: [], CANCELLED: []}
    for record in records:
        groups[status_at(record, at)].append(record)
    return groups
