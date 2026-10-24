"""分類證據交易驗收：以真實 .NET 多專案來源進行端對端 CLI 與逐寫入點故障注入。

此套件只驗證交易、證據保存與報告 fail-closed，不捏造規則 Pass、
不以模擬的安全審查結果充作實際專案完成審查。
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
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

from partial_evidence_integrity import (
    IntegrityError, JOURNAL, LOCK, MANIFEST, PENDING, STAGED,
    errors as integrity_errors, recover,
)
from partial_report import build_report
from partial_review import _category_dir, initialize, integrate, read_category, stage
from partial_review_safety import prepare_index, validate
from review_scope import ScopeError, load_catalog
from test_partial_dotnet_integration import SOURCES


class CategoryTransactionAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_catalog()

    def new_project(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for name, source in SOURCES.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8")
        official = root / "reports/security-code-review"
        official.mkdir(parents=True)
        for name in ("assessment.json", "report.json", "CodeReview_20261024.html"):
            (official / name).write_text(f"FORMAL/{name}", encoding="utf-8")
        initialize(root, ("AC", "AU"), self.catalog)
        return root

    def hashes(self, root: Path, category: str):
        folder = _category_dir(root, category)
        return {
            path.relative_to(folder).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in folder.rglob("*") if path.is_file()
            and not path.name.startswith(".review-")
            and path.name != LOCK.name
        }

    def official(self, root: Path):
        base = root / "reports/security-code-review"
        return {
            name: (base / name).read_bytes() for name in
            ("assessment.json", "report.json", "CodeReview_20261024.html")
        }

    def stage_batch(self, root: Path, category: str, *, finding=False):
        current = read_category(root, category, self.catalog)
        check = json.loads(json.dumps(current["checks"][0]))
        # Pending 仍為 pending，不使用不存在的來源證據冒充 Pass。
        check["execution"]["summary"] = (
            "已記錄此規則的來源追查工作，安全判定尚未完成。"
        )
        payload = {
            "checks": [check],
            "closures": {f"{category}-01": {"status": "review", "open_issues": ["待查執行路徑"]}},
            "decision_audits": {f"{category}-01": {"status": "review"}},
        }
        if finding:
            payload["findings"] = [{"id": f"F-{category}", "check_ids": [f"{category}-01"]}]
        batch = _category_dir(root, category) / "batch.json"
        batch.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        stage(root, category, batch, self.catalog)
        return batch

    def cli(self, root: Path, category: str, *more: str):
        cmd = [sys.executable, str(ROOT / "scripts/review_queue.py"),
               "--target", str(root), "--categories", category, *more]
        return subprocess.run(cmd, text=True, encoding="utf-8", errors="replace",
                              capture_output=True, check=False,
                              env={**os.environ, "PYTHONIOENCODING": "utf-8"})

    def _fail_integrate(self, root: Path, point: str):
        from partial_evidence_integrity import _atomic as original_atomic
        original_unlink = Path.unlink

        def write(path, value):
            # Inject exactly once so cleanup and future recovery can proceed.
            if point == path.name and not was_triggered[0]:
                was_triggered[0] = True
                raise OSError(f"injected write at {point}")
            return original_atomic(path, value)

        def unlink(path, *args, **kwargs):
            if (point == "staged-cleanup" and path == _category_dir(root, "AC") / STAGED
                    and not was_triggered[0]):
                was_triggered[0] = True
                raise OSError("injected staged cleanup")
            if (point == "pending-cleanup" and path == _category_dir(root, "AC") / PENDING
                    and not was_triggered[0]):
                was_triggered[0] = True
                raise OSError("injected pending cleanup")
            return original_unlink(path, *args, **kwargs)

        was_triggered = [False]
        with ExitStack() as stack:
            stack.enter_context(patch("partial_evidence_integrity._atomic",
                                      side_effect=write))
            stack.enter_context(patch.object(Path, "unlink", unlink))
            with self.assertRaisesRegex(OSError, "injected"):
                integrate(root, "AC", self.catalog)
        self.assertTrue(was_triggered[0], f"fault point was not reached: {point}")

    def test_every_commit_boundary_rejects_delivery_then_recovers_with_identical_evidence(self):
        # 固定寫入順序：先 pending，再 closures、decision-audits、assessment，
        # 再 Journal、Manifest、staged 清理、pending 清理。
        phases = ("rule-closures.json", "decision-audits.json", "assessment.json",
                  "00000001.json", MANIFEST.name, "staged-cleanup", "pending-cleanup")
        for point in phases:
            with self.subTest(point=point):
                root = self.new_project()
                self.stage_batch(root, "AU", finding=True)
                au_receipt = integrate(root, "AU", self.catalog)
                self.assertEqual(au_receipt["integrity_sequence"], 1)
                au_before = self.hashes(root, "AU")
                official_before = self.official(root)
                self.stage_batch(root, "AC", finding=True)
                self._fail_integrate(root, point)
                folder = _category_dir(root, "AC")
                self.assertTrue((folder / PENDING).is_file())
                self.assertTrue(integrity_errors(root, "AC"))
                verdict = validate(root, "AC", self.catalog)
                self.assertFalse(verdict["safety_valid"])
                self.assertTrue(verdict["safety_integrity_errors"])
                with self.assertRaises(ScopeError):
                    build_report(root, "AC", self.catalog)
                # 失敗交易期間不能覆寫原本分類及正式報告。
                self.assertEqual(self.hashes(root, "AU"), au_before)
                self.assertEqual(self.official(root), official_before)
                result = self.cli(root, "AC", "--recover-integrity")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(json.loads(result.stdout)["recovered"])
                self.assertEqual(integrity_errors(root, "AC"), [])
                self.assertFalse((folder / PENDING).exists())
                self.assertFalse((folder / STAGED).exists())
                self.assertEqual([f["id"] for f in read_category(root, "AC", self.catalog)["findings"]],
                                 ["F-AC"])
                self.assertEqual([f["id"] for f in read_category(root, "AU", self.catalog)["findings"]],
                                 ["F-AU"])
                journal = folder / JOURNAL
                self.assertEqual(sorted(p.name for p in journal.glob("*.json")),
                                 ["00000000.json", "00000001.json"])
                # 第二次復原不能重複寫入新紀錄或 Finding。
                before_repeat = self.hashes(root, "AC")
                again = self.cli(root, "AC", "--recover-integrity")
                self.assertEqual(again.returncode, 0, again.stderr)
                self.assertTrue(json.loads(again.stdout)["already_completed"])
                self.assertEqual(self.hashes(root, "AC"), before_repeat)
                self.assertEqual(self.hashes(root, "AU"), au_before)
                self.assertEqual(self.official(root), official_before)

    def test_pending_write_refusal_keeps_previous_integrity_and_allows_safe_retry(self):
        root = self.new_project()
        self.stage_batch(root, "AC", finding=True)
        folder = _category_dir(root, "AC")
        before = hashlib.sha256((folder / "assessment.json").read_bytes()).hexdigest()
        from partial_evidence_integrity import _atomic as original
        def refuse_pending(path, value):
            if path.name == PENDING.name:
                raise OSError("injected disk full before ahead-log")
            return original(path, value)
        with patch("partial_evidence_integrity._atomic", side_effect=refuse_pending):
            with self.assertRaises(OSError):
                integrate(root, "AC", self.catalog)
        self.assertFalse((folder / PENDING).exists())
        self.assertEqual(hashlib.sha256((folder / "assessment.json").read_bytes()).hexdigest(),
                         before)
        self.assertEqual(integrity_errors(root, "AC"), [])
        # 還沒有 durable pending：不應宣稱這次交易需要 Roll Forward。
        self.assertNotEqual(self.cli(root, "AC", "--recover-integrity").returncode, 0)
        receipt = integrate(root, "AC", self.catalog)
        self.assertEqual(receipt["integrity_sequence"], 1)
        self.assertEqual(integrity_errors(root, "AC"), [])

    def test_real_dotnet_projects_are_in_shared_index_but_not_formal_review(self):
        root = self.new_project()
        with patch("analysis_prepare.probe_roslyn", return_value={"available": False}), \
             patch("analysis_prepare.probe_codegraph", return_value={"available": False}):
            summary = prepare_index(root, self.catalog)
        self.assertEqual(summary["source_file_count"], len(SOURCES))
        index = json.loads((root / "reports/security-code-review/partial/_shared/analysis/"
                            "structure-index.json").read_text(encoding="utf-8"))
        edges = index["typed_relationships"]
        self.assertTrue(any(edge["kind"] == "di_registration" for edge in edges))
        self.assertTrue(any(edge["kind"] == "project_reference" for edge in edges))
        self.assertTrue(any(edge["kind"] == "endpoint_authorization" for edge in edges))
        self.assertFalse((root / "reports/security-code-review/analysis/structure-index.json").exists())
        self.stage_batch(root, "AC")
        self._fail_integrate(root, "assessment.json")
        self.assertTrue(recover(root, "AC")["recovered"])
        self.assertEqual(integrity_errors(root, "AC"), [])
        self.assertFalse(validate(root, "AC", self.catalog)["safety_valid"])
        self.assertEqual(len(validate(root, "AC", self.catalog)["remaining_ids"]), 8)
        self.assertEqual(len(read_category(root, "AC", self.catalog)["checks"]), 8)
        self.assertEqual(len(read_category(root, "AU", self.catalog)["checks"]), 10)

    def test_new_source_revision_refuses_recovery_without_mutating_pending(self):
        root = self.new_project()
        self.stage_batch(root, "AC")
        self._fail_integrate(root, "assessment.json")
        folder = _category_dir(root, "AC")
        original = (folder / PENDING).read_bytes()
        path = root / "Api/Controllers/OrdersController.cs"
        path.write_text(path.read_text(encoding="utf-8").replace("[Authorize]", "[AllowAnonymous]"),
                        encoding="utf-8")
        response = self.cli(root, "AC", "--recover-integrity")
        self.assertNotEqual(response.returncode, 0)
        self.assertEqual((folder / PENDING).read_bytes(), original)
        self.assertFalse((folder / "report.json").exists())

    def test_lock_refuses_recovery_and_preserves_formal_full_report(self):
        root = self.new_project()
        self.stage_batch(root, "AC")
        self._fail_integrate(root, "assessment.json")
        from partial_evidence_integrity import locked
        before = self.official(root)
        with locked(root, "AC"):
            response = self.cli(root, "AC", "--recover-integrity")
            self.assertNotEqual(response.returncode, 0)
            self.assertTrue((_category_dir(root, "AC") / PENDING).is_file())
        self.assertEqual(self.official(root), before)
        self.assertTrue(recover(root, "AC")["recovered"])


if __name__ == "__main__":
    unittest.main()
