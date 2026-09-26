"""预约撤销记录的保存：表结构、写入与查询。"""
from __future__ import annotations

import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS revocation_schedules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  credential_id INTEGER NOT NULL REFERENCES credentials(id),
  issuer TEXT NOT NULL,
  reason TEXT NOT NULL,
  effective_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','effective','cancelled')),
  idempotency_key TEXT NOT NULL,
  created_at TEXT NOT NULL,
  cancelled_by TEXT,
  cancelled_at TEXT,
  applied_at TEXT,
  UNIQUE(credential_id, idempotency_key)
);
CREATE UNIQUE INDEX IF NOT EXISTS one_pending_revocation
  ON revocation_schedules(credential_id) WHERE status='pending';
"""


class RevocationRepository:
    """revocation_schedules 表的增查改；状态流转时机由受理层决定。"""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def init_schema(self) -> None:
        self.conn.executescript(SCHEMA)

    def insert(self, credential_id: int, issuer: str, reason: str, effective_at: str, idempotency_key: str, created_at: str) -> int:
        cur = self.conn.execute(
            """INSERT INTO revocation_schedules(credential_id,issuer,reason,effective_at,status,idempotency_key,created_at)
               VALUES(?,?,?,?,'pending',?,?)""",
            (credential_id, issuer, reason, effective_at, idempotency_key, created_at),
        )
        return cur.lastrowid

    def get(self, schedule_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM revocation_schedules WHERE id=?", (schedule_id,)).fetchone()

    def find_by_idempotency(self, credential_id: int, idempotency_key: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM revocation_schedules WHERE credential_id=? AND idempotency_key=?",
            (credential_id, idempotency_key),
        ).fetchone()

    def find_pending_for_credential(self, credential_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM revocation_schedules WHERE credential_id=? AND status='pending' ORDER BY id DESC LIMIT 1",
            (credential_id,),
        ).fetchone()

    def find_pending_for_template_holder(self, template_id: int, holder_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            """SELECT rs.* FROM revocation_schedules rs
               JOIN credentials c ON c.id = rs.credential_id
               WHERE c.template_id=? AND c.holder_id=? AND rs.status='pending'
               ORDER BY rs.id DESC LIMIT 1""",
            (template_id, holder_id),
        ).fetchone()

    def due(self, moment: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM revocation_schedules WHERE status='pending' AND effective_at<=? ORDER BY id",
            (moment,),
        ).fetchall()

    def mark_effective(self, schedule_id: int, applied_at: str) -> None:
        self.conn.execute(
            "UPDATE revocation_schedules SET status='effective', applied_at=? WHERE id=? AND status='pending'",
            (applied_at, schedule_id),
        )

    def mark_cancelled(self, schedule_id: int, cancelled_by: str, cancelled_at: str) -> None:
        self.conn.execute(
            "UPDATE revocation_schedules SET status='cancelled', cancelled_by=?, cancelled_at=? WHERE id=? AND status='pending'",
            (cancelled_by, cancelled_at, schedule_id),
        )

    def list_all(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM revocation_schedules ORDER BY id DESC").fetchall()
