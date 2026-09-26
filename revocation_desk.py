"""预约撤销受理：登记预约、取消预约、到点应用与分组查询。"""
from __future__ import annotations

import sqlite3
from datetime import datetime

from revocation_repository import RevocationRepository
from revocation_status import PENDING, ApiError, group_by_status, iso, now, parse_time


class RevocationDesk:
    """预约撤销台：登记原因与生效时刻，预约期间原证继续可用，到点按撤销处理。"""

    def __init__(self, store):
        self.store = store
        self.conn = store.conn
        self.repo: RevocationRepository = store.revocations

    @staticmethod
    def _require_issuer(actor: str | None, role: str | None) -> str:
        if not actor:
            raise ApiError(401, "缺少身份")
        if role != "issuer":
            raise ApiError(403, "需要角色 issuer")
        return actor

    def _credential(self, credential_id: int) -> sqlite3.Row:
        row = self.conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
        if not row:
            raise ApiError(404, "对象不存在")
        return row

    def schedule(self, actor: str | None, role: str | None, credential_id: int, reason: str, effective_at: str | None, idempotency_key: str) -> dict:
        """登记预约撤销；相同幂等键重复提交沿用首次结果。"""
        actor = self._require_issuer(actor, role)
        credential = self._credential(credential_id)
        if credential["issuer"] != actor:
            raise ApiError(403, "只能撤销本机构签发的凭证")
        existing = self.repo.find_by_idempotency(credential_id, idempotency_key or "")
        if existing:
            return self._dict(existing)
        reason = (reason or "").strip()
        idempotency_key = (idempotency_key or "").strip()
        if not reason:
            raise ApiError(400, "撤销原因不能为空")
        if not idempotency_key:
            raise ApiError(400, "幂等键不能为空")
        if not effective_at:
            raise ApiError(400, "生效时刻不能为空")
        try:
            effective = parse_time(effective_at)
        except ValueError as exc:
            raise ApiError(400, "生效时刻格式错误") from exc
        if effective <= now():
            raise ApiError(400, "生效时刻必须晚于当前时间")
        if credential["status"] != "active":
            raise ApiError(409, "只有有效凭证可以预约撤销")
        if self.repo.find_pending_for_credential(credential_id):
            raise ApiError(409, "已有待生效的撤销预约")
        try:
            with self.conn:
                schedule_id = self.repo.insert(credential_id, actor, reason, iso(effective), idempotency_key, iso())
                self.store.audit(actor, "revocation.schedule", "revocation_schedule", schedule_id,
                                 {"credential_id": credential_id, "effective_at": iso(effective), "reason": reason})
        except sqlite3.IntegrityError:
            # 并发登记时同一幂等键沿用首次结果，同一凭证只保留一条待生效预约
            existing = self.repo.find_by_idempotency(credential_id, idempotency_key)
            if existing:
                return self._dict(existing)
            raise ApiError(409, "已有待生效的撤销预约")
        return self._dict(self.repo.get(schedule_id))

    def cancel(self, actor: str | None, role: str | None, schedule_id: int) -> dict:
        """取消预约：记下是谁在何时取消；仅待生效的预约可以取消。"""
        actor = self._require_issuer(actor, role)
        self.apply_due()
        row = self.repo.get(schedule_id)
        if not row:
            raise ApiError(404, "预约不存在")
        credential = self._credential(row["credential_id"])
        if credential["issuer"] != actor:
            raise ApiError(403, "只能取消本机构的预约")
        if row["status"] != PENDING:
            raise ApiError(409, "预约已生效或已取消")
        moment = iso()
        with self.conn:
            self.repo.mark_cancelled(schedule_id, actor, moment)
            self.store.audit(actor, "revocation.cancel", "revocation_schedule", schedule_id,
                             {"credential_id": row["credential_id"], "cancelled_by": actor, "cancelled_at": moment})
        return self._dict(self.repo.get(schedule_id))

    def apply_due(self, at: datetime | None = None) -> list[int]:
        """到点应用：预约转已生效，原证按撤销处理，返回本次生效的预约编号。"""
        moment = iso(at)
        applied = []
        for row in self.repo.due(moment):
            with self.conn:
                self.repo.mark_effective(row["id"], moment)
                credential = self.conn.execute("SELECT status FROM credentials WHERE id=?", (row["credential_id"],)).fetchone()
                if credential and credential["status"] != "revoked":
                    self.conn.execute(
                        "UPDATE credentials SET status='revoked', revocation_reason=?, revocation_effective_at=? WHERE id=?",
                        (row["reason"], row["effective_at"], row["credential_id"]),
                    )
                self.store.audit("system", "revocation.apply", "revocation_schedule", row["id"],
                                 {"credential_id": row["credential_id"], "effective_at": row["effective_at"]})
            applied.append(row["id"])
        return applied

    def list_grouped(self) -> dict:
        """按待生效、已生效、已取消分组列出，供页面展示。"""
        self.apply_due()
        records = [self._dict(row) for row in self.repo.list_all()]
        return group_by_status(records, now())

    @staticmethod
    def _dict(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "credential_id": row["credential_id"],
            "issuer": row["issuer"],
            "reason": row["reason"],
            "effective_at": row["effective_at"],
            "status": row["status"],
            "idempotency_key": row["idempotency_key"],
            "created_at": row["created_at"],
            "cancelled_by": row["cancelled_by"],
            "cancelled_at": row["cancelled_at"],
            "applied_at": row["applied_at"],
        }
