"""Wave 2 uncommitted-stage abortion: complete, replay and unsafe cases."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from review_waves_state import REPORT, STATE, _read, _write_state
from review_snapshot import SNAPSHOT
from review_waves_abort import abort_uncommitted, inspect_uncommitted


class AbortWave2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.target = Path(self.tmp.name)
        analysis = self.target / REPORT / "analysis"
        analysis.mkdir(parents=True)
        self.manifest_head = "e" * 64
        (analysis / "integrity-manifest.json").write_text(json.dumps({
            "schema_version": 1, "sequence": 90, "head": self.manifest_head
        }), encoding="utf-8")
        self.snapshot = {"git_revision": "test", "source_hashes": {
            "src/Service.cs": "c" * 64}}
        (self.target / REPORT / SNAPSHOT).write_text(
            json.dumps(self.snapshot), encoding="utf-8")
        self.payload = {"checks": [{"id": "AC-01", "status": "review"}]}
        self.payload_path = self.target / "candidate.json"
        self.payload_path.write_text(json.dumps(self.payload), encoding="utf-8")
        self.staged_record = {
            "snapshot_git_revision": "test",
            "source_hashes": self.snapshot["source_hashes"],
            "payload": self.payload, "integrity_head": self.manifest_head}
        self.staged_dir = analysis / "staged"
        self.staged_dir.mkdir()
        self.staged_path = self._write_staged(self.staged_record)
        self.evidence = {"assessment_sha256": "a" * 64,
                         "source_snapshot_sha256": "b" * 64,
                         "manifest_sha256": "d" * 64,
                         "tracked_sha256": {"assessment.json": "a" * 64}}
        self.fp = {"checks": {"AC-01": {"digest": "q"}}, "findings": {}}
        self.state = {
            "schema_version": 2, "phase": "first_pass", "paused": False,
            "last_evidence": self.evidence, "formal_fingerprints": self.fp,
            "completed_batches": [], "changed_rules": [], "mandatory_rules": [],
            "batches": [{"batch_id": "execution-01", "rule_ids": ["AC-01"],
                         "task_ids": ["AC-01:P1"], "depends_on_batch_ids": []}],
            "inflight": {"phase": "first_pass", "batch_id": "execution-01",
                         "payload_sha256": hashlib.sha256(
                             self.payload_path.read_bytes()).hexdigest(),
                         "prior_evidence": self.evidence,
                         "prior_fingerprints": self.fp}}
        _write_state(self.target / STATE, self.state)

    def _write_staged(self, value):
        raw = json.dumps(value, sort_keys=True, ensure_ascii=False)
        name = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24] + ".json"
        path = self.staged_dir / name
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
        return path

    @contextmanager
    def verified(self, *, evidence=None, fingerprints=None):
        with patch("review_waves_state._evidence_state",
                   return_value=evidence if evidence is not None else self.evidence), \
             patch("review_waves_state._formal_fingerprints",
                   return_value=fingerprints if fingerprints is not None else self.fp):
            yield

    def abort(self, **kwargs):
        return abort_uncommitted(self.target, "execution-01",
                                 payload_path=kwargs.pop("payload_path", self.payload_path),
                                 acknowledged=kwargs.pop("acknowledged", True), **kwargs)

    def test_read_only_preflight_identifies_missing_legacy_payload(self):
        with self.verified():
            result = inspect_uncommitted(self.target, "execution-01")
        self.assertEqual(result["status"], "needs_original_payload")
        self.assertFalse(result["can_abort"])
        self.assertTrue(result["read_only"])
        self.assertEqual(result["manifest_sequence"], 90)
        self.assertTrue(self.staged_path.is_file())
        self.assertFalse((self.target / REPORT / "logs/repair-waves/aborted").exists())
        self.assertIsNotNone(_read(self.target / STATE)["inflight"])

    def test_read_only_preflight_proves_exact_original_payload(self):
        with self.verified():
            result = inspect_uncommitted(
                self.target, "execution-01", payload_path=self.payload_path)
        self.assertEqual(result["status"], "ready_to_abort")
        self.assertTrue(result["can_abort"])
        self.assertEqual(result["staged_count"], 1)
        self.assertEqual(result["inflight_payload_sha256"],
                         self.state["inflight"]["payload_sha256"])
        self.assertFalse((self.target / REPORT / "logs/repair-waves/aborted").exists())

    def test_preflight_rejects_bad_original_payload_without_changes(self):
        self.payload_path.write_text('{"checks":[]}', encoding="utf-8")
        with self.verified():
            with self.assertRaisesRegex(ValueError, "SHA256"):
                inspect_uncommitted(self.target, "execution-01",
                                    payload_path=self.payload_path)
        self.assertTrue(self.staged_path.exists())

    def test_preflight_rejects_committed_manifest(self):
        altered = dict(self.evidence, manifest_sha256="f" * 64)
        with self.verified(evidence=altered):
            with self.assertRaisesRegex(ValueError, "Manifest"):
                inspect_uncommitted(self.target, "execution-01",
                                    payload_path=self.payload_path)
        self.assertTrue(self.staged_path.exists())

    def test_preflight_cli_needs_no_mutating_authorization(self):
        from review_repair_waves import main
        with self.verified():
            status = main(["--target", str(self.target),
                           "--inspect-uncommitted", "execution-01"])
            self.assertEqual(status, 0)
        self.assertTrue(self.staged_path.exists())
        self.assertIsNotNone(_read(self.target / STATE)["inflight"])

    def test_legacy_staged_only_requires_independent_explicit_sha(self):
        original_sha = hashlib.sha256(self.staged_path.read_bytes()).hexdigest()
        with self.verified():
            with self.assertRaisesRegex(ValueError, "舊版 inflight"):
                self.abort(payload_path=None, expected_staged_sha256=original_sha)
            with self.assertRaisesRegex(ValueError, "64 字 SHA256"):
                self.abort(payload_path=None, expected_staged_sha256="0" * 64,
                           allow_unbound_legacy=True)
            self.assertTrue(self.staged_path.exists())
            self.assertIsNotNone(_read(self.target / STATE)["inflight"])

    def test_explicit_sha_bound_staged_only_quarantine_is_audited(self):
        original_sha = hashlib.sha256(self.staged_path.read_bytes()).hexdigest()
        with self.verified():
            inspected = inspect_uncommitted(
                self.target, "execution-01", expected_staged_sha256=original_sha,
                allow_unbound_legacy=True)
            self.assertTrue(inspected["can_abort"])
            self.assertEqual(inspected["status"], "ready_to_abort_unbound")
            self.assertFalse(inspected["raw_payload_verified"])
            result = self.abort(payload_path=None, expected_staged_sha256=original_sha,
                                allow_unbound_legacy=True)
        self.assertTrue(result["legacy_unbound_staged_only"])
        self.assertFalse(self.staged_path.exists())
        receipt = _read(self.target / result["receipt"])
        self.assertTrue(receipt["legacy_unbound"])
        self.assertFalse(receipt["raw_payload_verified"])
        self.assertIsNone(_read(self.target / STATE)["inflight"])

    def test_staged_only_refuses_changed_formal_journal_even_with_exact_sha(self):
        original_sha = hashlib.sha256(self.staged_path.read_bytes()).hexdigest()
        modified = dict(self.evidence, manifest_sha256="0" * 64)
        with self.verified(evidence=modified):
            with self.assertRaisesRegex(ValueError, "Manifest"):
                self.abort(payload_path=None, expected_staged_sha256=original_sha,
                           allow_unbound_legacy=True)
        self.assertTrue(self.staged_path.exists())

    def test_staged_only_crash_recovery_requires_same_explicit_sha(self):
        original_sha = hashlib.sha256(self.staged_path.read_bytes()).hexdigest()
        with self.verified():
            with patch("review_waves_state._write_state", side_effect=RuntimeError("crash")):
                with self.assertRaisesRegex(RuntimeError, "crash"):
                    self.abort(payload_path=None, allow_unbound_legacy=True,
                               expected_staged_sha256=original_sha)
            self.assertIsNotNone(_read(self.target / STATE)["inflight"])
            with self.assertRaisesRegex(ValueError, "staged-only 例外"):
                self.abort(payload_path=None, expected_staged_sha256=original_sha)
            with self.assertRaisesRegex(ValueError, "staged-only 例外"):
                self.abort(payload_path=None, allow_unbound_legacy=True,
                           expected_staged_sha256="0" * 64)
            result = self.abort(payload_path=None, allow_unbound_legacy=True,
                                expected_staged_sha256=original_sha)
        self.assertEqual(result["status"], "aborted_uncommitted")
        self.assertTrue(result["legacy_unbound_staged_only"])
        self.assertIsNone(_read(self.target / STATE)["inflight"])

    def test_staged_only_cli_requires_both_explicit_legacy_flags(self):
        from review_repair_waves import main
        original_sha = hashlib.sha256(self.staged_path.read_bytes()).hexdigest()
        with self.verified():
            fail = main(["--target", str(self.target),
                         "--abort-uncommitted", "execution-01",
                         "--expected-staged-sha256", original_sha,
                         "--acknowledge-investigation"])
            self.assertEqual(fail, 2)
            result = main(["--target", str(self.target),
                           "--abort-uncommitted", "execution-01",
                           "--expected-staged-sha256", original_sha,
                           "--allow-unbound-legacy-stage",
                           "--acknowledge-investigation"])
            self.assertEqual(result, 0)
        self.assertFalse(self.staged_path.exists())

    def test_requires_explicit_acknowledgement(self):
        with self.assertRaisesRegex(ValueError, "acknowledge-investigation"):
            self.abort(acknowledged=False)
        self.assertTrue(self.staged_path.exists())

    def test_quarantines_exact_single_staged_without_formal_modification(self):
        with self.verified():
            result = self.abort()
        self.assertEqual(result["status"], "aborted_uncommitted")
        self.assertEqual(result["manifest_sequence_unchanged"], 90)
        self.assertEqual(result["completed_batches_unchanged"], 0)
        archive = self.target / result["archive"]
        self.assertTrue(archive.is_file())
        self.assertFalse(self.staged_path.exists())
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(),
                         result["staged_sha256"])
        receipt = _read(self.target / result["receipt"])
        self.assertEqual(receipt["manifest_head"], self.manifest_head)
        self.assertTrue(receipt["not_formal_journal"])
        self.assertEqual(_read(self.target / STATE)["inflight"], None)
        self.assertEqual(_read(self.target / STATE)["completed_batches"], [])
        self.assertEqual(_read(self.target / REPORT / "analysis/integrity-manifest.json")["sequence"], 90)

    def test_repetition_does_not_modify_or_reapply_anything(self):
        with self.verified():
            first = self.abort()
            again = self.abort()
        self.assertEqual(again["status"], "already_aborted")
        self.assertEqual(first["archive"], again["archive"])

    def test_refuses_changed_manifest_or_tracked_evidence(self):
        altered = dict(self.evidence, manifest_sha256="f" * 64)
        with self.verified(evidence=altered):
            with self.assertRaisesRegex(ValueError, "Manifest"):
                self.abort()
        self.assertTrue(self.staged_path.exists())

    def test_refuses_changed_formal_records(self):
        with self.verified(fingerprints={"checks": {}}):
            with self.assertRaisesRegex(ValueError, "逐條證據"):
                self.abort()

    def test_refuses_pending_journal_transaction(self):
        pending = self.target / REPORT / "analysis/integrity-pending.json"
        pending.write_text("{}", encoding="utf-8")
        with self.verified():
            with self.assertRaisesRegex(ValueError, "待提交"):
                self.abort()

    def test_refuses_multiple_staged_candidates(self):
        (self.staged_dir / "extra.json").write_text("{}", encoding="utf-8")
        with self.verified():
            with self.assertRaisesRegex(ValueError, "不只一筆"):
                self.abort()

    def test_refuses_different_original_payload(self):
        self.payload_path.write_text('{"checks":[]}', encoding="utf-8")
        with self.verified():
            with self.assertRaisesRegex(ValueError, "SHA256"):
                self.abort()

    def test_refuses_missing_original_legacy_payload(self):
        with self.verified():
            with self.assertRaisesRegex(ValueError, "舊版 inflight"):
                self.abort(payload_path=None)

    def test_refuses_staged_payload_not_matching_original(self):
        self.staged_path.unlink()
        self.staged_record["payload"] = {"checks": [{"id": "AU-01"}]}
        self.staged_path = self._write_staged(self.staged_record)
        with self.verified():
            with self.assertRaisesRegex(ValueError, "SHA256／內容"):
                self.abort()

    def test_refuses_staged_manifest_head_mismatch(self):
        self.staged_path.unlink()
        self.staged_record["integrity_head"] = "0" * 64
        self.staged_path = self._write_staged(self.staged_record)
        with self.verified():
            with self.assertRaisesRegex(ValueError, "head"):
                self.abort()

    def test_refuses_wrong_batch_without_mutation(self):
        with self.verified():
            with self.assertRaisesRegex(ValueError, "明確指定"):
                abort_uncommitted(self.target, "execution-02",
                                  payload_path=self.payload_path, acknowledged=True)
        self.assertTrue(self.staged_path.exists())

    def test_idempotent_retry_rejects_tampered_archive(self):
        with self.verified():
            result = self.abort()
            archived = self.target / result["archive"]
            archived.write_text('{"tampered": true}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "隔離封存"):
                self.abort()

    def test_cli_requires_acknowledgement_and_selects_only_requested_batch(self):
        from review_repair_waves import main
        with self.verified():
            status = main(["--target", str(self.target),
                           "--abort-uncommitted", "execution-01",
                           "--payload", str(self.payload_path)])
            self.assertEqual(status, 2)
            self.assertTrue(self.staged_path.exists())
            status = main(["--target", str(self.target),
                           "--abort-uncommitted", "execution-01",
                           "--payload", str(self.payload_path),
                           "--acknowledge-investigation"])
            self.assertEqual(status, 0)
            self.assertFalse(self.staged_path.exists())

    def test_restart_after_move_but_before_checkpoint_write(self):
        from review_waves_state import _write_state as real_write
        with self.verified():
            with patch("review_waves_state._write_state",
                       side_effect=RuntimeError("simulated crash")):
                with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                    self.abort()
            self.assertTrue(self.staged_dir.is_dir())
            self.assertEqual(list(self.staged_dir.iterdir()), [])
            self.assertIsNotNone(_read(self.target / STATE)["inflight"])
            receipt_files = list((self.target / REPORT /
                                  "logs/repair-waves/aborted").glob("*/receipt.json"))
            self.assertEqual(len(receipt_files), 1)
            with patch("review_waves_state._write_state", side_effect=real_write):
                result = self.abort()
        self.assertEqual(result["status"], "aborted_uncommitted")
        self.assertIsNone(_read(self.target / STATE)["inflight"])

    def test_refuses_archive_modified_before_recovery(self):
        with self.verified():
            with patch("review_waves_state._write_state", side_effect=RuntimeError("crash")):
                with self.assertRaises(RuntimeError):
                    self.abort()
            archived = next((self.target / REPORT /
                             "logs/repair-waves/aborted").glob("*/staged.json"))
            archived.write_text('{"tampered": true}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "SHA256"):
                self.abort()
        self.assertIsNotNone(_read(self.target / STATE)["inflight"])


if __name__ == "__main__":
    unittest.main()
