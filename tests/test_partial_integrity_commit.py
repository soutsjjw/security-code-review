"""分類審查證據的預寫日誌與持久化提交測試；中斷後復原保留給獨立流程。"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from partial_review import _category_dir, _atomic, initialize, integrate, read_category, stage
from partial_evidence_integrity import (
    IntegrityError, JOURNAL, LOCK, MANIFEST, PENDING, STAGED,
    commit, errors, initialize as seal, _sha, _json_bytes,
)
from review_scope import ScopeError, load_catalog


class CategoryIntegrityCommitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_catalog()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "Orders.cs").write_text(
            "public class Orders { public bool Allowed() => true; }\n",
            encoding="utf-8")
        formal = self.root / "reports/security-code-review"
        formal.mkdir(parents=True)
        self.official = formal / "assessment.json"
        self.official.write_text('{"keep":"full-70"}', encoding="utf-8")
        initialize(self.root, ("AC", "AU"), self.catalog)

    def _folder(self, category="AC"):
        return _category_dir(self.root, category)

    def _payload(self, category="AC"):
        data = read_category(self.root, category, self.catalog)
        change = json.loads(json.dumps(data["checks"][0]))
        change["execution"]["summary"] = "實際逐檔閱讀授權入口、依賴與控制路徑，繼續待查證。"
        return {
            "checks": [change],
            "closures": {f"{category}-01": {"status": "review", "open_issues": ["待核對部署政策"]}},
            "decision_audits": {f"{category}-01": {"status": "review"}},
        }

    def _stage(self, category="AC"):
        target = self._folder(category) / "batch.json"
        target.write_text(json.dumps(self._payload(category), ensure_ascii=False),
                          encoding="utf-8")
        return stage(self.root, category, target, self.catalog)

    def test_first_stage_initializes_seal_without_full_review_changes(self):
        self.assertFalse((self._folder() / MANIFEST).exists())
        pending = self._stage()
        self.assertTrue(pending.is_file())
        self.assertEqual(errors(self.root, "AC"), [])
        self.assertEqual(json.loads((self._folder() / MANIFEST).read_text("utf-8"))["sequence"], 0)
        self.assertFalse((self._folder("AU") / MANIFEST).exists())
        self.assertEqual(self.official.read_text("utf-8"), '{"keep":"full-70"}')

    def test_commit_writes_multiple_evidence_and_sha_chain(self):
        staged = self._stage()
        digest = _sha(staged.read_bytes())
        outcome = integrate(self.root, "AC", self.catalog)
        self.assertEqual(outcome["integrity_sequence"], 1)
        self.assertFalse(staged.exists())
        self.assertFalse((self._folder() / PENDING).exists())
        self.assertFalse((self._folder() / LOCK).exists())
        self.assertEqual(errors(self.root, "AC"), [])
        journal = json.loads((self._folder() / JOURNAL / "00000001.json").read_text("utf-8"))
        first = json.loads((self._folder() / JOURNAL / "00000000.json").read_text("utf-8"))
        self.assertEqual(journal["previous"], first["entry_hash"])
        self.assertEqual(journal["staged_sha256"][STAGED.as_posix()], digest)
        self.assertEqual(journal["file_hashes"]["assessment.json"],
                         hashlib.sha256((self._folder() / "assessment.json").read_bytes()).hexdigest())
        self.assertEqual(journal["file_hashes"]["analysis/rule-closures.json"],
                         hashlib.sha256((self._folder() / "analysis/rule-closures.json").read_bytes()).hexdigest())
        self.assertEqual(self.official.read_text("utf-8"), '{"keep":"full-70"}')

    def test_repeated_batches_advance_chain_without_losing_findings(self):
        self._stage()
        integrate(self.root, "AC", self.catalog)
        payload_path = self._folder() / "batch.json"
        next_check = read_category(self.root, "AC", self.catalog)["checks"][1]
        payload_path.write_text(json.dumps({
            "checks": [next_check], "findings": [{"id": "F-AC", "check_ids": ["AC-02"]}],
        }), encoding="utf-8")
        stage(self.root, "AC", payload_path, self.catalog)
        receipt = integrate(self.root, "AC", self.catalog)
        self.assertEqual(receipt["integrity_sequence"], 2)
        self.assertEqual([f["id"] for f in read_category(self.root, "AC", self.catalog)["findings"]],
                         ["F-AC"])
        self.assertEqual(errors(self.root, "AC"), [])

    def test_interruption_after_first_evidence_preserves_pending_and_blocks_retry(self):
        self._stage()
        before = (self._folder() / "assessment.json").read_bytes()
        from partial_evidence_integrity import _atomic as original
        def fail_assessment(path, data):
            if path.name == "assessment.json":
                raise OSError("injected disk failure before assessment replacement")
            return original(path, data)
        with patch("partial_evidence_integrity._atomic", side_effect=fail_assessment):
            with self.assertRaises(OSError):
                integrate(self.root, "AC", self.catalog)
        pending = json.loads((self._folder() / PENDING).read_text("utf-8"))
        self.assertEqual(pending["category"], "AC")
        self.assertEqual(pending["sequence"], 1)
        self.assertIn("analysis/rule-closures.json", pending["after_hashes"])
        self.assertIn("assessment.json", pending["updates"])
        self.assertEqual((self._folder() / "assessment.json").read_bytes(), before)
        self.assertTrue((self._folder() / STAGED).is_file())
        self.assertTrue(errors(self.root, "AC"))
        with self.assertRaises(ScopeError):
            integrate(self.root, "AC", self.catalog)
        with self.assertRaises(ScopeError):
            self._stage()
        self.assertFalse((self._folder() / LOCK).exists())
        self.assertEqual(self.official.read_text("utf-8"), '{"keep":"full-70"}')

    def test_pending_write_failure_never_starts_evidence_replacement(self):
        self._stage()
        assessment = (self._folder() / "assessment.json").read_bytes()
        from partial_evidence_integrity import _atomic as original
        def refuse_ahead_log(path, data):
            if path.name == PENDING.name:
                raise OSError("no space for ahead-log")
            return original(path, data)
        with patch("partial_evidence_integrity._atomic", side_effect=refuse_ahead_log):
            with self.assertRaises(OSError):
                integrate(self.root, "AC", self.catalog)
        self.assertEqual((self._folder() / "assessment.json").read_bytes(), assessment)
        self.assertFalse((self._folder() / PENDING).exists())
        self.assertFalse((self._folder() / "analysis/rule-closures.json").exists())
        self.assertTrue((self._folder() / STAGED).is_file())
        self.assertEqual(errors(self.root, "AC"), [])

    def test_journal_failure_preserves_pending_for_explicit_recovery(self):
        self._stage()
        from partial_evidence_integrity import _atomic as original
        def fail_journal(path, data):
            if path.name == "00000001.json":
                raise OSError("injected failure before durable journal")
            return original(path, data)
        with patch("partial_evidence_integrity._atomic", side_effect=fail_journal):
            with self.assertRaises(OSError):
                integrate(self.root, "AC", self.catalog)
        self.assertTrue((self._folder() / PENDING).is_file())
        self.assertTrue((self._folder() / STAGED).is_file())
        self.assertEqual(json.loads((self._folder() / MANIFEST).read_text("utf-8"))["sequence"], 0)
        self.assertTrue(errors(self.root, "AC"))

    def test_manifest_failure_preserves_journal_and_pending(self):
        self._stage()
        from partial_evidence_integrity import _atomic as original
        def fail_manifest(path, data):
            if path.name == MANIFEST.name:
                raise OSError("injected failure between journal and manifest")
            return original(path, data)
        with patch("partial_evidence_integrity._atomic", side_effect=fail_manifest):
            with self.assertRaises(OSError):
                integrate(self.root, "AC", self.catalog)
        self.assertTrue((self._folder() / PENDING).is_file())
        self.assertTrue((self._folder() / JOURNAL / "00000001.json").is_file())
        self.assertEqual(json.loads((self._folder() / MANIFEST).read_text("utf-8"))["sequence"], 0)
        self.assertTrue(errors(self.root, "AC"))

    def test_cross_category_transaction_isolation(self):
        self._stage("AC")
        self._stage("AU")
        integrate(self.root, "AU", self.catalog)
        au_before = (self._folder("AU") / MANIFEST).read_bytes()
        from partial_evidence_integrity import _atomic as original
        def fail_ac(path, data):
            if path.name == "assessment.json":
                raise OSError("AC write failed")
            return original(path, data)
        with patch("partial_evidence_integrity._atomic", side_effect=fail_ac):
            with self.assertRaises(OSError):
                integrate(self.root, "AC", self.catalog)
        self.assertEqual(errors(self.root, "AU"), [])
        self.assertEqual((self._folder("AU") / MANIFEST).read_bytes(), au_before)
        self.assertEqual(self.official.read_text("utf-8"), '{"keep":"full-70"}')

    def test_existing_unsealed_progress_requires_explicit_review(self):
        data = read_category(self.root, "AC", self.catalog)
        data["checks"][0]["execution"]["state"] = "completed"
        _atomic(self._folder() / "assessment.json", data)
        p = self._folder() / "batch.json"
        p.write_text(json.dumps({"checks": [data["checks"][1]]}), encoding="utf-8")
        with self.assertRaises(IntegrityError):
            stage(self.root, "AC", p, self.catalog)
        self.assertFalse((self._folder() / MANIFEST).exists())
        seal(self.root, "AC", explicit=True)
        stage(self.root, "AC", p, self.catalog)
        integrate(self.root, "AC", self.catalog)
        self.assertEqual(errors(self.root, "AC"), [])

    def test_direct_commit_rejects_untracked_path_and_symlink(self):
        seal(self.root, "AC")
        with self.assertRaises(IntegrityError):
            commit(self.root, "AC", {"../../report.json": {}}, event="malicious")
        self.assertFalse((self._folder() / PENDING).exists())
        self.assertEqual(self.official.read_text("utf-8"), '{"keep":"full-70"}')

    def test_no_implicit_recovery_after_interruption(self):
        self._stage()
        from partial_evidence_integrity import _atomic as original
        with patch("partial_evidence_integrity._atomic",
                   side_effect=lambda p,d: (_ for _ in ()).throw(OSError("stop"))
                   if p.name == "assessment.json" else original(p,d)):
            with self.assertRaises(OSError):
                integrate(self.root, "AC", self.catalog)
        with self.assertRaises(IntegrityError):
            seal(self.root, "AC")
        self.assertTrue((self._folder() / PENDING).exists())


if __name__ == "__main__":
    unittest.main()
