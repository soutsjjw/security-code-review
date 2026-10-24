"""分類證據交易明確復原：逐故障點、篡改拒絕、冪等及範圍隔離。"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from partial_review import _atomic, _category_dir, initialize, integrate, read_category, stage
from partial_evidence_integrity import (IntegrityError, JOURNAL, LOCK, MANIFEST,
                                        PENDING, STAGED, errors, recover, _sha)
from review_scope import ScopeError, load_catalog


class CategoryExplicitRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_catalog()

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.source = self.root / "Order.cs"
        self.source.write_text(
            "public sealed class Order { public int Id => 1; }\n", encoding="utf-8")
        self.formal = self.root / "reports/security-code-review/assessment.json"
        self.formal.parent.mkdir(parents=True)
        self.formal.write_text('{"formal":true}', encoding="utf-8")
        initialize(self.root, ("AC", "AU"), self.catalog)

    def folder(self, cat="AC"):
        return _category_dir(self.root, cat)

    def prepare(self, cat="AC", *, with_history=False):
        current = read_category(self.root, cat, self.catalog)
        check = json.loads(json.dumps(current["checks"][0]))
        check["execution"]["summary"] = "實際查閱對應來源和呼叫鏈，紀錄待完成控制驗證。"
        payload = {
            "checks": [check],
            "closures": {f"{cat}-01": {"status": "review", "open_issues": ["部署 policy"]}},
            "decision_audits": {f"{cat}-01": {"status": "review"}},
        }
        if with_history:
            payload["findings"] = [{"id": "F-001", "check_ids": [f"{cat}-01"]}]
        path = self.folder(cat) / "batch.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        stage(self.root, cat, path, self.catalog)
        return path

    def interrupt(self, component: str, cat="AC"):
        self.prepare(cat)
        from partial_evidence_integrity import _atomic as original
        def fail(path, value):
            if path.name == component:
                raise OSError("failure injected at " + component)
            return original(path, value)
        with patch("partial_evidence_integrity._atomic", side_effect=fail):
            with self.assertRaises(OSError):
                integrate(self.root, cat, self.catalog)
        self.assertTrue((self.folder(cat) / PENDING).is_file())

    def assert_clean(self, cat="AC"):
        self.assertEqual(errors(self.root, cat), [])
        self.assertFalse((self.folder(cat) / PENDING).exists())
        self.assertFalse((self.folder(cat) / STAGED).exists())
        self.assertFalse((self.folder(cat) / LOCK).exists())
        self.assertEqual(self.formal.read_text(encoding="utf-8"), '{"formal":true}')

    def assert_pending_retained(self):
        self.assertTrue((self.folder() / PENDING).is_file())
        self.assertTrue((self.folder() / STAGED).is_file())

    def test_recover_before_first_file_update(self):
        self.interrupt("analysis/rule-closures.json".split("/")[-1])
        result = recover(self.root, "AC")
        self.assertTrue(result["recovered"])
        self.assertEqual(result["sequence"], 1)
        self.assert_clean()

    def test_recover_after_partial_evidence_updates(self):
        self.interrupt("decision-audits.json")
        before = (self.folder() / "assessment.json").read_bytes()
        self.assertEqual(before, (self.folder() / "assessment.json").read_bytes())
        self.assertTrue((self.folder() / "analysis/rule-closures.json").is_file())
        self.assertEqual(recover(self.root, "AC")["sequence"], 1)
        self.assertEqual(read_category(self.root, "AC", self.catalog)["checks"][0]
                         ["execution"]["summary"],
                         "實際查閱對應來源和呼叫鏈，紀錄待完成控制驗證。")
        self.assert_clean()

    def test_recover_after_all_files_but_before_journal(self):
        self.interrupt("00000001.json")
        self.assertEqual(json.loads((self.folder() / MANIFEST).read_text("utf-8"))["sequence"], 0)
        r = recover(self.root, "AC")
        self.assertEqual(r["sequence"], 1)
        self.assert_clean()

    def test_recover_after_journal_but_before_manifest(self):
        self.interrupt(MANIFEST.name)
        self.assertTrue((self.folder() / JOURNAL / "00000001.json").is_file())
        self.assertEqual(recover(self.root, "AC")["sequence"], 1)
        self.assert_clean()

    def test_recover_after_manifest_but_before_stage_cleanup(self):
        self.prepare()
        original = Path.unlink
        def fail_unlink(path, *args, **kwargs):
            if path.name == STAGED.name and path.parent.name == "staged":
                raise OSError("simulate failure deleting stage")
            return original(path, *args, **kwargs)
        with patch.object(Path, "unlink", fail_unlink):
            with self.assertRaises(OSError):
                integrate(self.root, "AC", self.catalog)
        self.assertEqual(json.loads((self.folder() / MANIFEST).read_text("utf-8"))["sequence"], 1)
        self.assertTrue((self.folder() / STAGED).exists())
        self.assertTrue(recover(self.root, "AC")["recovered"])
        self.assert_clean()

    def test_recover_after_stage_deleted_but_before_pending_cleanup(self):
        self.prepare()
        original = Path.unlink
        def fail_unlink(path, *args, **kwargs):
            if path.name == PENDING.name:
                raise OSError("simulate failure deleting pending")
            return original(path, *args, **kwargs)
        with patch.object(Path, "unlink", fail_unlink):
            with self.assertRaises(OSError):
                integrate(self.root, "AC", self.catalog)
        self.assertFalse((self.folder() / STAGED).exists())
        self.assertTrue((self.folder() / PENDING).is_file())
        self.assertTrue(recover(self.root, "AC")["recovered"])
        self.assert_clean()

    def test_repeated_recovery_does_not_duplicate_journal_or_findings(self):
        self.interrupt("decision-audits.json")
        first = recover(self.root, "AC")
        second = recover(self.root, "AC")
        self.assertTrue(first["recovered"])
        self.assertFalse(second["recovered"])
        self.assertTrue(second["already_completed"])
        self.assertEqual(first["sequence"], second["sequence"])
        self.assertEqual(len(list((self.folder() / JOURNAL).glob("*.json"))), 2)
        self.assert_clean()

    def test_unmodified_category_isolated_from_other_failure(self):
        self.interrupt("assessment.json")
        self.prepare("AU")
        integrate(self.root, "AU", self.catalog)
        previous = (self.folder("AU") / MANIFEST).read_bytes()
        self.assertTrue(recover(self.root, "AC")["recovered"])
        self.assertEqual((self.folder("AU") / MANIFEST).read_bytes(), previous)
        self.assert_clean("AU")
        self.assert_clean("AC")

    def test_tampered_source_refuses_without_mutations(self):
        self.interrupt("assessment.json")
        pending_before = (self.folder() / PENDING).read_bytes()
        self.source.write_text("public sealed class Order { public int Id => 2; }\n", encoding="utf-8")
        with self.assertRaises(IntegrityError):
            recover(self.root, "AC")
        self.assertEqual((self.folder() / PENDING).read_bytes(), pending_before)

    def test_tampered_staged_refuses_without_mutations(self):
        self.interrupt("assessment.json")
        stage_file = self.folder() / STAGED
        stage_file.write_text('{"tampered":true}', encoding="utf-8")
        original = (self.folder() / "assessment.json").read_bytes()
        with self.assertRaises(IntegrityError):
            recover(self.root, "AC")
        self.assertEqual((self.folder() / "assessment.json").read_bytes(), original)
        self.assert_pending_retained()

    def test_third_content_in_evidence_refuses_and_preserves_pending(self):
        self.interrupt("assessment.json")
        self.folder().joinpath("analysis/rule-closures.json").write_text('{"third":1}', encoding="utf-8")
        old = (self.folder() / "assessment.json").read_bytes()
        with self.assertRaises(IntegrityError):
            recover(self.root, "AC")
        self.assertEqual((self.folder() / "assessment.json").read_bytes(), old)
        self.assert_pending_retained()

    def test_missing_staged_before_commit_refuses(self):
        self.interrupt("assessment.json")
        (self.folder() / STAGED).unlink()
        with self.assertRaises(IntegrityError):
            recover(self.root, "AC")
        self.assertTrue((self.folder() / PENDING).is_file())

    def test_tampered_pending_updates_refuses_without_writes(self):
        self.interrupt("assessment.json")
        pending_path = self.folder() / PENDING
        pending = json.loads(pending_path.read_text(encoding="utf-8"))
        pending["updates"]["assessment.json"]["checks"][0]["status"] = "pass"
        _atomic(pending_path, pending)
        old = (self.folder() / "assessment.json").read_bytes()
        with self.assertRaises(IntegrityError):
            recover(self.root, "AC")
        self.assertEqual((self.folder() / "assessment.json").read_bytes(), old)

    def test_extra_journal_entry_refuses(self):
        self.interrupt("assessment.json")
        _atomic(self.folder() / JOURNAL / "00000002.json", {"rogue": True})
        with self.assertRaises(IntegrityError):
            recover(self.root, "AC")
        self.assertTrue((self.folder() / PENDING).is_file())

    def test_modified_previous_chain_refuses(self):
        self.interrupt("assessment.json")
        old = self.folder() / JOURNAL / "00000000.json"
        entry = json.loads(old.read_text("utf-8"))
        entry["entry_hash"] = "0" * 64
        _atomic(old, entry)
        with self.assertRaises(IntegrityError):
            recover(self.root, "AC")

    def test_cross_category_pending_cannot_recover_other_category(self):
        self.interrupt("assessment.json")
        with self.assertRaises(IntegrityError):
            recover(self.root, "AU")
        self.assert_pending_retained()
        self.assertFalse((self.folder("AU") / MANIFEST).exists())

    def test_validate_and_report_refuse_pending_before_completion(self):
        self.interrupt("assessment.json")
        from partial_review_safety import validate
        from partial_report import build_report
        verdict = validate(self.root, "AC", self.catalog)
        self.assertFalse(verdict["safety_valid"])
        self.assertTrue(verdict["safety_integrity_errors"])
        with self.assertRaises(ScopeError):
            build_report(self.root, "AC", self.catalog)
        self.assert_pending_retained()

    def test_cli_recovery_then_repeated_recovery(self):
        self.interrupt("assessment.json")
        script = str(ROOT / "scripts/review_queue.py")
        command = [sys.executable, script, "--target", str(self.root),
                   "--categories", "AC", "--recover-integrity"]
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        run = subprocess.run(command, text=True, encoding="utf-8", env=env,
                             capture_output=True, check=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(json.loads(run.stdout)["recovered"])
        again = subprocess.run(command, text=True, encoding="utf-8", env=env,
                               capture_output=True, check=False)
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertFalse(json.loads(again.stdout)["recovered"])
        invalid = subprocess.run(command[:-2] + ["AC,AU", "--recover-integrity"],
                                 text=True, encoding="utf-8", env=env,
                                 capture_output=True, check=False)
        self.assertNotEqual(invalid.returncode, 0)
        self.assert_clean()

    def test_recover_obeys_classification_lock(self):
        self.interrupt("assessment.json")
        from partial_evidence_integrity import locked
        with locked(self.root, "AC"):
            with self.assertRaises(IntegrityError):
                recover(self.root, "AC")
        self.assert_pending_retained()
        self.assertTrue(recover(self.root, "AC")["recovered"])


if __name__ == "__main__":
    unittest.main()
