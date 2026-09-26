"""预约撤销的受理：登记预约、取消预约、到点生效与分组查询。

状态推导规则在 revocation_status，表读写委托 revocation_store。
"""
from __future__ import annotations

import sqlite3
from typing import Callable

from revocation_status import (
    CANCELLED,
    EFFECTIVE,
    PENDING,
    decorate,
    derive_status,
    group_by_status,
    parse_moment,
    to_iso,
    utcnow,
)
from revocation_store import RevocationStore


class RevocationError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class RevocationIntake:
    def __init__(self, store: RevocationStore, conn: sqlite3.Connection, audit: Callable[..., None]):
        self.store = store
        self.conn = conn
        self.audit = audit

    @staticmethod
    def _require_issuer(actor: str | None, role: str | None) -> str:
        if not actor:
            raise RevocationError(401, "缺少身份")
        if role != "issuer":
            raise RevocationError(403, "需要角色 issuer")
        return actor

    def _credential(self, credential_id: int) -> sqlite3.Row:
        row = self.conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
        if not row:
            raise RevocationError(404, "凭证不存在")
        return row

    def schedule(self, actor: str | None, role: str | None, credential_id: int, reason: str, effective_at: str | None) -> dict:
        """登记预约撤销：记录原因与生效时刻，重复提交沿用首次结果。"""
        actor = self._require_issuer(actor, role)
        credential = self._credential(credential_id)
        if credential["issuer"] != actor:
            raise RevocationError(403, "只能撤销本机构签发的凭证")
        reason = (reason or "").strip()
        if not reason:
            raise RevocationError(400, "撤销原因不能为空")
        if not effective_at:
            raise RevocationError(400, "必须登记生效时刻")
        try:
            effective = parse_moment(effective_at)
        except ValueError as exc:
            raise RevocationError(400, "生效时刻格式错误") from exc
        self.sweep_due()
        pending = self.store.for_credential(credential_id, (PENDING,))
        if pending:
            return decorate(pending)
        if credential["status"] == "revoked":
            prior = self.store.for_credential(credential_id, (EFFECTIVE,))
            if prior:
                return decorate(prior)
            raise RevocationError(409, "凭证已经撤销")
        if credential["status"] == "disputed":
            raise RevocationError(409, "凭证争议处理中，暂不能预约撤销")
        try:
            with self.conn:
                schedule_id = self.store.insert(credential_id, actor, reason, to_iso(effective), to_iso(utcnow()))
                self.audit(actor, "revocation.schedule", "scheduled_revocation", schedule_id,
                           {"credential_id": credential_id, "reason": reason, "effective_at": to_iso(effective)})
        except sqlite3.IntegrityError:
            return decorate(self.store.for_credential(credential_id, (PENDING,)))
        self.sweep_due()
        return decorate(self.store.get(schedule_id))

    def cancel(self, actor: str | None, role: str | None, schedule_id: int) -> dict:
        """取消预约：记下是谁在何时取消；到点后不能再取消。"""
        actor = self._require_issuer(actor, role)
        row = self.store.get(schedule_id)
        if not row:
            raise RevocationError(404, "预约撤销记录不存在")
        credential = self._credential(row["credential_id"])
        if credential["issuer"] != actor:
            raise RevocationError(403, "只能取消本机构的预约撤销")
        if row["status"] == CANCELLED:
            return decorate(row)
        if derive_status(row["status"], row["effective_at"]) == EFFECTIVE:
            raise RevocationError(409, "预约撤销已到生效时刻，无法取消")
        cancelled_at = to_iso(utcnow())
        with self.conn:
            self.store.mark_cancelled(schedule_id, actor, cancelled_at)
            self.audit(actor, "revocation.cancel", "scheduled_revocation", schedule_id,
                       {"credential_id": row["credential_id"], "cancelled_by": actor, "cancelled_at": cancelled_at})
        return decorate(self.store.get(schedule_id))

    def overturn(self, credential_id: int, actor: str) -> None:
        """争议驳回撤销决定时，把已生效的预约记录取消，记下操作者与时刻。"""
        row = self.store.for_credential(credential_id, (EFFECTIVE,))
        if not row:
            return
        cancelled_at = to_iso(utcnow())
        self.store.mark_cancelled(row["id"], actor, cancelled_at)
        self.audit(actor, "revocation.cancel", "scheduled_revocation", row["id"],
                   {"credential_id": credential_id, "cancelled_by": actor, "cancelled_at": cancelled_at, "via": "dispute_rejected"})

    def sweep_due(self) -> list[int]:
        """把到点的预约落成凭证撤销；幂等，可随任何操作调用。"""
        due = self.store.due_pending(to_iso(utcnow()))
        for row in due:
            with self.conn:
                self.store.mark_effective(row["id"])
                self.conn.execute(
                    """UPDATE credentials SET status='revoked',revocation_reason=?,revocation_effective_at=?
                       WHERE id=? AND status='active'""",
                    (row["reason"], row["effective_at"], row["credential_id"]),
                )
                self.audit("system", "revocation.take_effect", "scheduled_revocation", row["id"],
                           {"credential_id": row["credential_id"], "effective_at": row["effective_at"]})
        return [row["id"] for row in due]

    def overview(self) -> dict:
        """按待生效、已生效、已取消分组列出全部预约记录。"""
        self.sweep_due()
        return group_by_status(self.store.list_all())

    def schedule_for_credential(self, credential_id: int) -> sqlite3.Row | None:
        return self.store.for_credential(credential_id, (PENDING, EFFECTIVE))

    def pending_for_template_holder(self, template_id: int, holder_id: str) -> sqlite3.Row | None:
        return self.store.pending_for_template_holder(template_id, holder_id)
