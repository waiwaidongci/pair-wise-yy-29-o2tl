import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import ApiError, CredentialService, Store
from revocation_status import iso, now


class RevocationScheduleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = CredentialService(Store(Path(self.tmp.name) / "test.db"))
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        self.template = self.service.create_template(
            "issuer-a", "issuer", "degree", "学位凭证", [{"name": "name", "required": True}], 365
        )
        self.credential = self.service.issue(
            "issuer-a", "issuer", self.template["id"], "alice", {"name": "Alice"}, "issue-1"
        )

    def tearDown(self):
        self.service.store.close()
        self.tmp.cleanup()

    def schedule(self, key="rev-1", reason="信息登记错误", seconds=3600):
        return self.service.desk.schedule(
            "issuer-a", "issuer", self.credential["id"], reason, iso(now() + timedelta(seconds=seconds)), key
        )

    def test_pending_schedule_keeps_credential_usable_and_blocks_reissue(self):
        scheduled = self.schedule()
        self.assertEqual("pending", scheduled["status"])
        self.assertEqual("信息登记错误", scheduled["reason"])
        proof = self.service.present("alice", "holder", self.credential["id"], None)
        result = self.service.verify(proof["token"])
        self.assertTrue(result["valid"])
        self.assertEqual("valid_until_revocation", result["status"])
        self.assertEqual(scheduled["effective_at"], result["revocation_starts_at"])
        # 预约期间即使机构先直接撤销，也不能补发同模板新证
        self.service.revoke("issuer-a", "issuer", self.credential["id"], "先下架")
        with self.assertRaises(ApiError) as ctx:
            self.service.issue("issuer-a", "issuer", self.template["id"], "alice", {"name": "Alice"}, "issue-2")
        self.assertEqual(409, ctx.exception.status)
        self.assertIn("预约撤销", ctx.exception.message)

    def test_idempotent_resubmission_reuses_first_result(self):
        first = self.schedule(key="rev-1", reason="首次原因")
        second = self.schedule(key="rev-1", reason="重复提交")
        self.assertEqual(first["id"], second["id"])
        self.assertEqual("首次原因", second["reason"])
        with self.assertRaises(ApiError) as ctx:
            self.schedule(key="rev-2")
        self.assertEqual(409, ctx.exception.status)

    def test_cancel_records_actor_and_time(self):
        scheduled = self.schedule()
        cancelled = self.service.desk.cancel("issuer-a", "issuer", scheduled["id"])
        self.assertEqual("cancelled", cancelled["status"])
        self.assertEqual("issuer-a", cancelled["cancelled_by"])
        self.assertTrue(cancelled["cancelled_at"])
        proof = self.service.present("alice", "holder", self.credential["id"], None)
        self.assertEqual("valid", self.service.verify(proof["token"])["status"])
        groups = self.service.desk.list_grouped()
        self.assertEqual([scheduled["id"]], [record["id"] for record in groups["cancelled"]])
        with self.assertRaises(ApiError) as ctx:
            self.service.desk.cancel("issuer-a", "issuer", scheduled["id"])
        self.assertEqual(409, ctx.exception.status)

    def test_due_schedule_marks_effective_and_revokes_credential(self):
        scheduled = self.schedule(seconds=3600)
        proof = self.service.present("alice", "holder", self.credential["id"], None)
        # 核验时刻越过生效时刻即按撤销处理
        future = iso(now() + timedelta(seconds=3700))
        result = self.service.verify(proof["token"], at=future)
        self.assertFalse(result["valid"])
        self.assertEqual("revoked", result["status"])
        self.assertEqual("信息登记错误", result["reason"])
        # 到点应用：记录转已生效、原证按撤销处理、之后可重新签发
        applied = self.service.desk.apply_due(now() + timedelta(seconds=3700))
        self.assertEqual([scheduled["id"]], applied)
        credential = [c for c in self.service.state()["credentials"] if c["id"] == self.credential["id"]][0]
        self.assertEqual("revoked", credential["status"])
        self.assertEqual("信息登记错误", credential["revocation_reason"])
        self.assertEqual(scheduled["effective_at"], credential["revocation_effective_at"])
        groups = self.service.desk.list_grouped()
        self.assertEqual([scheduled["id"]], [record["id"] for record in groups["effective"]])
        reissued = self.service.issue("issuer-a", "issuer", self.template["id"], "alice", {"name": "Alice"}, "issue-3")
        self.assertEqual("active", reissued["status"])

    def test_grouped_listing_and_validation(self):
        scheduled = self.schedule()
        groups = self.service.desk.list_grouped()
        self.assertEqual([scheduled["id"]], [record["id"] for record in groups["pending"]])
        self.assertEqual([], groups["effective"])
        self.assertEqual([], groups["cancelled"])
        with self.assertRaises(ApiError) as ctx:
            self.service.desk.schedule(None, None, self.credential["id"], "原因", iso(now() + timedelta(seconds=60)), "k")
        self.assertEqual(401, ctx.exception.status)
        with self.assertRaises(ApiError) as ctx:
            self.service.desk.schedule("alice", "holder", self.credential["id"], "原因", iso(now() + timedelta(seconds=60)), "k")
        self.assertEqual(403, ctx.exception.status)
        with self.assertRaises(ApiError) as ctx:
            self.service.desk.schedule("issuer-b", "issuer", self.credential["id"], "原因", iso(now() + timedelta(seconds=60)), "k")
        self.assertEqual(403, ctx.exception.status)
        with self.assertRaises(ApiError) as ctx:
            self.service.desk.schedule("issuer-a", "issuer", self.credential["id"], "", iso(now() + timedelta(seconds=60)), "k")
        self.assertEqual(400, ctx.exception.status)
        with self.assertRaises(ApiError) as ctx:
            self.service.desk.schedule("issuer-a", "issuer", self.credential["id"], "原因", iso(now() - timedelta(seconds=60)), "k")
        self.assertEqual(400, ctx.exception.status)
        # 已撤销凭证不能再预约
        self.service.revoke("issuer-a", "issuer", self.credential["id"], "直接撤销")
        with self.assertRaises(ApiError) as ctx:
            self.schedule(key="rev-9")
        self.assertEqual(409, ctx.exception.status)


if __name__ == "__main__":
    unittest.main()
