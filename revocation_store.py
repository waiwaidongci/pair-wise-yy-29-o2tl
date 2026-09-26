"""预约撤销台的数据保存：表结构、写入与查询，不含业务判断。"""
from __future__ import annotations

import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS scheduled_revocations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  credential_id INTEGER NOT NULL REFERENCES credentials(id),
  issuer TEXT NOT NULL,
  reason TEXT NOT NULL,
  effective_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','effective','cancelled')),
  created_at TEXT NOT NULL,
  cancelled_by TEXT,
  cancelled_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS one_pending_revocation
  ON scheduled_revocations(credential_id) WHERE status='pending';
"""


class RevocationStore:
    """只负责 scheduled_revocations 表的读写。"""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def init_schema(self) -> None:
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def insert(self, credential_id: int, issuer: str, reason: str, effective_at: str, created_at: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO scheduled_revocations(credential_id,issuer,reason,effective_at,status,created_at) VALUES(?,?,?,?,'pending',?)",
            (credential_id, issuer, reason, effective_at, created_at),
        )
        return cur.lastrowid

    def get(self, schedule_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM scheduled_revocations WHERE id=?", (schedule_id,)).fetchone()

    def for_credential(self, credential_id: int, statuses: tuple[str, ...]) -> sqlite3.Row | None:
        marks = ",".join("?" for _ in statuses)
        return self.conn.execute(
            f"SELECT * FROM scheduled_revocations WHERE credential_id=? AND status IN ({marks}) ORDER BY id DESC LIMIT 1",
            (credential_id, *statuses),
        ).fetchone()

    def due_pending(self, now_iso: str) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM scheduled_revocations WHERE status='pending' AND effective_at<=? ORDER BY id",
            (now_iso,),
        ))

    def mark_effective(self, schedule_id: int) -> None:
        self.conn.execute("UPDATE scheduled_revocations SET status='effective' WHERE id=?", (schedule_id,))

    def mark_cancelled(self, schedule_id: int, actor: str, cancelled_at: str) -> None:
        self.conn.execute(
            "UPDATE scheduled_revocations SET status='cancelled',cancelled_by=?,cancelled_at=? WHERE id=?",
            (actor, cancelled_at, schedule_id),
        )

    def list_all(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("SELECT * FROM scheduled_revocations ORDER BY id DESC"))

    def pending_for_template_holder(self, template_id: int, holder_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            """SELECT sr.* FROM scheduled_revocations sr
               JOIN credentials c ON c.id = sr.credential_id
               WHERE c.template_id=? AND c.holder_id=? AND sr.status='pending'
               ORDER BY sr.id DESC LIMIT 1""",
            (template_id, holder_id),
        ).fetchone()
