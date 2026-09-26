import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import ApiError, CredentialService, Store
from revocation_intake import RevocationError


def iso_of(moment):
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


def future(**kwargs):
    return iso_of(datetime.now(timezone.utc) + timedelta(**kwargs))


def past(**kwargs):
    return iso_of(datetime.now(timezone.utc) - timedelta(**kwargs))


class ScheduledRevocationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = CredentialService(Store(Path(self.tmp.name) / "test.db"))
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        self.template = self.service.create_template("issuer-a", "issuer", "degree", "学位凭证", [{"name": "name", "required": True}], 365)
        self.credential = self.service.issue("issuer-a", "issuer", self.template["id"], "alice", {"name": "Alice"}, "issue-1")

    def tearDown(self):
        self.service.store.close()
        self.tmp.cleanup()

    def schedule(self, credential_id, reason, effective_at):
        return self.service.revocations.schedule("issuer-a", "issuer", credential_id, reason, effective_at)

    def test_pending_schedule_keeps_credential_valid_and_blocks_reissue(self):
        record = self.schedule(self.credential["id"], "信息登记错误", future(hours=1))
        self.assertEqual("pending", record["status"])
        proof = self.service.present("alice", "holder", self.credential["id"], ["name"])
        result = self.service.verify(proof["token"])
        self.assertTrue(result["valid"])
        self.assertEqual(record["effective_at"], result["scheduled_revocation_at"])
        with self.assertRaises(ApiError) as ctx:
            self.service.issue("issuer-a", "issuer", self.template["id"], "alice", {"name": "Alice"}, "issue-2")
        self.assertEqual(409, ctx.exception.status)
        revoked_later = self.service.verify(proof["token"], at=future(hours=2))
        self.assertEqual("revoked", revoked_later["status"])
        self.assertEqual("信息登记错误", revoked_later["reason"])

    def test_repeated_schedule_reuses_first_record(self):
        first = self.schedule(self.credential["id"], "原因一", future(hours=1))
        second = self.schedule(self.credential["id"], "原因二", future(hours=2))
        self.assertEqual(first["id"], second["id"])
        self.assertEqual("原因一", second["reason"])
        self.assertEqual(first["effective_at"], second["effective_at"])

    def test_due_schedule_revokes_and_allows_reissue(self):
        record = self.schedule(self.credential["id"], "模板填错", past(seconds=1))
        self.assertEqual("effective", record["status"])
        proof = self.service.present("alice", "holder", self.credential["id"], ["name"])
        checked = self.service.verify(proof["token"])
        self.assertEqual("revoked", checked["status"])
        self.assertEqual("模板填错", checked["reason"])
        reissued = self.service.issue("issuer-a", "issuer", self.template["id"], "alice", {"name": "Alice"}, "issue-2")
        self.assertEqual("active", reissued["status"])
        again = self.schedule(self.credential["id"], "模板填错", future(hours=1))
        self.assertEqual(record["id"], again["id"])

    def test_dispute_after_scheduled_revocation(self):
        self.schedule(self.credential["id"], "模板填错", past(seconds=1))
        dispute = self.service.dispute("alice", "holder", self.credential["id"], "撤销依据错误")
        self.assertEqual("open", dispute["status"])
        result = self.service.resolve_dispute("regulator-1", "regulator", dispute["id"], "reject", "撤销依据不足")
        self.assertEqual("active", result["credential_status"])
        proof = self.service.present("alice", "holder", self.credential["id"], ["name"])
        self.assertTrue(self.service.verify(proof["token"])["valid"])

    def test_cancel_records_actor_and_moment(self):
        record = self.schedule(self.credential["id"], "拟撤销", future(hours=1))
        cancelled = self.service.revocations.cancel("issuer-a", "issuer", record["id"])
        self.assertEqual("cancelled", cancelled["status"])
        self.assertEqual("issuer-a", cancelled["cancelled_by"])
        self.assertTrue(cancelled["cancelled_at"])
        again = self.service.revocations.cancel("issuer-a", "issuer", record["id"])
        self.assertEqual(cancelled["cancelled_at"], again["cancelled_at"])
        proof = self.service.present("alice", "holder", self.credential["id"], ["name"])
        self.assertTrue(self.service.verify(proof["token"])["valid"])
        rescheduled = self.schedule(self.credential["id"], "重新登记", future(hours=1))
        self.assertNotEqual(record["id"], rescheduled["id"])

    def test_cancel_permission_and_missing_record(self):
        record = self.schedule(self.credential["id"], "拟撤销", future(hours=1))
        with self.assertRaises(RevocationError) as ctx:
            self.service.revocations.cancel("issuer-b", "issuer", record["id"])
        self.assertEqual(403, ctx.exception.status)
        with self.assertRaises(RevocationError) as ctx:
            self.service.revocations.cancel("issuer-a", "issuer", 9999)
        self.assertEqual(404, ctx.exception.status)
        with self.assertRaises(RevocationError) as ctx:
            self.service.revocations.schedule("issuer-b", "issuer", self.credential["id"], "越权", future(hours=1))
        self.assertEqual(403, ctx.exception.status)

    def test_cancel_after_effective_rejected(self):
        record = self.schedule(self.credential["id"], "立即生效", past(seconds=1))
        self.assertEqual("effective", record["status"])
        with self.assertRaises(RevocationError) as ctx:
            self.service.revocations.cancel("issuer-a", "issuer", record["id"])
        self.assertEqual(409, ctx.exception.status)

    def test_overview_groups_records(self):
        cancelled = self.schedule(self.credential["id"], "待生效", future(hours=1))
        self.service.revocations.cancel("issuer-a", "issuer", cancelled["id"])
        effective = self.schedule(self.credential["id"], "已生效", past(seconds=1))
        second = self.service.issue("issuer-a", "issuer", self.template["id"], "alice", {"name": "Alice"}, "issue-2")
        upcoming = self.schedule(second["id"], "下一批", future(hours=1))
        groups = self.service.state()["revocation_schedules"]
        self.assertEqual([upcoming["id"]], [r["id"] for r in groups["pending"]])
        self.assertEqual([effective["id"]], [r["id"] for r in groups["effective"]])
        self.assertEqual([cancelled["id"]], [r["id"] for r in groups["cancelled"]])


if __name__ == "__main__":
    unittest.main()
