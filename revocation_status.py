"""预约撤销的状态判断。

预约撤销记录只持久化 pending / effective / cancelled，
其中“已生效”主要由生效时刻与当前时间推导：记录到点即视为生效，
不依赖定时任务是否在那一刻恰好运行。
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

PENDING = "pending"      # 待生效
EFFECTIVE = "effective"  # 已生效
CANCELLED = "cancelled"  # 已取消


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_moment(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def derive_status(stored_status: str, effective_at: str, moment: datetime | None = None) -> str:
    """由存储状态和生效时刻推导对外状态。"""
    if stored_status in (CANCELLED, EFFECTIVE):
        return stored_status
    return EFFECTIVE if parse_moment(effective_at) <= (moment or utcnow()) else PENDING


def is_due(stored_status: str, effective_at: str, moment: datetime | None = None) -> bool:
    """存储状态仍为 pending 但生效时刻已到。"""
    return stored_status == PENDING and derive_status(stored_status, effective_at, moment) == EFFECTIVE


def decorate(row: sqlite3.Row, moment: datetime | None = None) -> dict:
    """把数据库行转成带推导状态的对外记录。"""
    return {
        "id": row["id"],
        "credential_id": row["credential_id"],
        "issuer": row["issuer"],
        "reason": row["reason"],
        "effective_at": row["effective_at"],
        "status": derive_status(row["status"], row["effective_at"], moment),
        "created_at": row["created_at"],
        "cancelled_by": row["cancelled_by"],
        "cancelled_at": row["cancelled_at"],
    }


def group_by_status(rows: list[sqlite3.Row], moment: datetime | None = None) -> dict:
    """按待生效、已生效、已取消分组，供页面展示。"""
    groups = {PENDING: [], EFFECTIVE: [], CANCELLED: []}
    for row in rows:
        record = decorate(row, moment)
        groups[record["status"]].append(record)
    return groups
