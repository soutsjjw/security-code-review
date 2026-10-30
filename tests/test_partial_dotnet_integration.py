"""P5：具備 Web Controller → Service → Repository 的 .NET 8 跨專案整合測試。

來源為可實際閱讀的最小 .NET Web API；只模擬缺少 Roslyn 的可降級環境。
不偽造安全控制 Pass：缺乏 Agent 逐條證據時應明確拒絕報告。
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lib"))

from partial_report import complete, validate_saved
from partial_review import initialize, queue, read_category
from partial_review_store import category_dir, source_snapshot
from partial_review_safety import prepare_index, validate, _shared_path
from review_scope import ScopeError, load_catalog

def run_utf8_process(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    """不依賴 Windows cp950 解碼 dotnet 診斷訊息；保留非零退出碼。"""
    return subprocess.run(command, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", check=False, **kwargs)


SOURCES = {
    "Api/Orders.Api.csproj": """<Project Sdk="Microsoft.NET.Sdk.Web">
      <PropertyGroup><TargetFramework>net8.0</TargetFramework>
      <Nullable>enable</Nullable><ImplicitUsings>enable</ImplicitUsings></PropertyGroup>
      <ItemGroup><ProjectReference Include="..\\Infra\\Orders.Infrastructure.csproj" /></ItemGroup>
    </Project>""",
    "Infra/Orders.Infrastructure.csproj": """<Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup><TargetFramework>net8.0</TargetFramework>
      <Nullable>enable</Nullable><ImplicitUsings>enable</ImplicitUsings></PropertyGroup>
    </Project>""",
    "Api/Program.cs": """using Api.Services;
using Infrastructure;
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddAuthentication();
builder.Services.AddAuthorization();
builder.Services.AddScoped<IOrderRepository, OrderRepository>();
builder.Services.AddScoped<OrderService>();
var app = builder.Build();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
""",
    "Api/Controllers/OrdersController.cs": """using Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
namespace Api.Controllers;
[ApiController]
[Route("api/orders")]
[Authorize]
public sealed class OrdersController : ControllerBase {
    private readonly OrderService _service;
    public OrdersController(OrderService service) { _service = service; }
    [HttpGet]
    public ActionResult<string> GetOrder() => Ok(_service.GetOrder());
}
""",
    "Api/Services/OrderService.cs": """using Infrastructure;
namespace Api.Services;
public sealed class OrderService {
    private readonly IOrderRepository _repository;
    public OrderService(IOrderRepository repository) { _repository = repository; }
    public string GetOrder() => _repository.ReadOrder();
}
""",
    "Infra/OrderRepository.cs": """namespace Infrastructure;
public interface IOrderRepository { string ReadOrder(); }
public sealed class OrderRepository : IOrderRepository {
    public string ReadOrder() => "order-123";
}
""",
    "Api/appsettings.json": '{"Logging":{"LogLevel":{"Default":"Information"}}}',
}


class DotNetCategoryIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_catalog()

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)
        for name, text in SOURCES.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        formal_dir = self.root / "reports/security-code-review"
        formal_dir.mkdir(parents=True, exist_ok=True)
        self.formal = {name: formal_dir / name
                       for name in ("assessment.json", "report.json", "CodeReview_20261024.html")}
        for name, path in self.formal.items():
            path.write_text(f"FORMAL-{name}", encoding="utf-8")
        self.formal_before = {name: path.read_bytes() for name, path in self.formal.items()}

    def initialize_and_prepare(self):
        created = initialize(self.root, ("AC", "AU"), self.catalog)
        self.assertEqual(created, ["AC", "AU"])
        with patch("analysis_prepare.probe_roslyn", return_value={"available": False}), \
             patch("analysis_prepare.probe_codegraph", return_value={"available": False}):
            return prepare_index(self.root, self.catalog)

    def assert_formal_unchanged(self):
        self.assertEqual({name: path.read_bytes() for name, path in self.formal.items()},
                         self.formal_before)

    def test_dotnet_fixture_compiles_without_external_nuget_packages(self):
        dotnet = shutil.which("dotnet")
        if not dotnet:
            self.skipTest("沒有 .NET SDK，仍可執行來源索引與驗證負向測試")
        env = {**os.environ, "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
               "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1"}
        project = self.root / "Api/Orders.Api.csproj"
        result = run_utf8_process(
            [dotnet, "build", str(project), "--nologo", "--verbosity", "quiet",
             "--ignore-failed-sources"], cwd=self.root, env=env, timeout=120,
        )
        self.assertEqual(result.returncode, 0,
                         (result.stdout or "")[-1500:] + (result.stderr or "")[-1500:])
        self.assert_formal_unchanged()

    def test_dotnet_output_decode_does_not_depend_on_windows_cp950(self):
        """UTF-8 與異常位元組必須可讀，不可讓 reader thread 丟失 stdout/stderr。"""
        command = (
            "import sys; "
            "sys.stdout.buffer.write(bytes([0xe6]) + '中文'.encode('utf-8')); "
            "sys.stderr.buffer.write(bytes([0xff])); "
            "sys.exit(7)"
        )
        result = run_utf8_process([sys.executable, "-c", command])
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, "\ufffd中文")
        self.assertEqual(result.stderr, "\ufffd")

    def test_index_discovers_cross_project_calls_and_auth_control_candidates(self):
        stats = self.initialize_and_prepare()
        self.assertFalse(stats["reused"])
        self.assertEqual(stats["source_file_count"], len(SOURCES))
        index = json.loads(_shared_path(self.root).read_text(encoding="utf-8"))
        self.assertEqual(set(index["source_hashes"]), set(SOURCES))
        self.assertEqual(index["source_hashes"], source_snapshot(self.root)["source_hashes"])
        edges = index["typed_relationships"]
        self.assertTrue(any(e["kind"] == "di_registration" and
                            e["source"] == "Api/Program.cs" and e["target"] == "Infra/OrderRepository.cs"
                            for e in edges), edges)
        self.assertTrue(any(e["kind"] == "endpoint_authorization" and
                            e["source"] == "Api/Controllers/OrdersController.cs"
                            for e in edges), edges)
        self.assertTrue(any(e["kind"] == "project_reference" and
                            e["source"] == "Api/Orders.Api.csproj" and
                            e["target"] == "Infra/Orders.Infrastructure.csproj"
                            for e in edges), edges)
        self.assertTrue(all(e["resolution"] == "candidate_only" for e in edges))
        self.assertFalse((self.root / "reports/security-code-review/analysis/structure-index.json").exists())
        self.assert_formal_unchanged()

    def test_shared_index_reuse_and_separate_category_queues(self):
        self.initialize_and_prepare()
        with patch("analysis_prepare.probe_roslyn", return_value={"available": False}), \
             patch("analysis_prepare.probe_codegraph", return_value={"available": False}):
            self.assertTrue(prepare_index(self.root, self.catalog)["reused"])
        results = queue(self.root, ("AC", "AU"), self.catalog, 10, compact=True)
        ac, au = results["category_queues"]
        self.assertEqual((ac["total"], au["total"]), (8, 10))
        self.assertEqual(len(ac["next_checks"]), 8)
        self.assertEqual(len(au["next_checks"]), 10)
        self.assertEqual(ac["source_coverage"]["source_file_count"], len(SOURCES))
        self.assertEqual(au["source_coverage"]["source_file_count"], len(SOURCES))
        self.assertEqual(ac["source_coverage"]["reviewed_source_file_count"], 0)
        self.assertFalse(ac["safety_valid"])
        self.assertFalse(au["safety_valid"])
        self.assertFalse(results["ready_for_report"])
        self.assert_formal_unchanged()

    def test_real_p3_gate_rejects_unreviewed_source_and_second_pass(self):
        self.initialize_and_prepare()
        check = validate(self.root, "AC", self.catalog)
        self.assertFalse(check["safety_valid"])
        self.assertEqual(len(check["remaining_ids"]), 8)
        self.assertEqual(check["second_pass"]["pending_count"], 8)
        with self.assertRaises(ScopeError):
            complete(self.root, ("AC", "AU"), self.catalog)
        self.assertFalse((category_dir(self.root, "AC") / "report.json").exists())
        self.assertFalse((category_dir(self.root, "AU") / "report.json").exists())
        self.assert_formal_unchanged()

    def test_source_change_invalidates_both_classes(self):
        self.initialize_and_prepare()
        controller = self.root / "Api/Controllers/OrdersController.cs"
        controller.write_text(controller.read_text("utf-8").replace("[Authorize]", "[AllowAnonymous]"),
                              encoding="utf-8")
        for category in ("AC", "AU"):
            with self.subTest(category=category), self.assertRaises(ScopeError):
                read_category(self.root, category, self.catalog)
        with self.assertRaises(ScopeError):
            complete(self.root, ("AC", "AU"), self.catalog)
        self.assert_formal_unchanged()

    def test_category_report_validation_does_not_inherit_formal_artifacts(self):
        self.initialize_and_prepare()
        self.assertTrue(validate_saved(self.root, ("AC", "AU"), self.catalog))
        self.assert_formal_unchanged()


if __name__ == "__main__":
    unittest.main()
