#!/usr/bin/env python3
"""保守的安全規則候選定位器；線索不是漏洞、適用性或完成結論。

目前只啟用現代 .NET 的可辨識語法；未來可增加 Framework / Vue profile，
不必變更 70 項規則、逐檔驗證或報告契約。
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from source_reader import read_source_text

# 僅放入高辨識度實作線索，避免把一般 Controller、using、檔名視為適用證據。
# 訊號可能由多個檔案共同實作；每檔可能同時命中數條規則。
DOTNET_SIGNALS: tuple[tuple[str, str, str], ...] = (
    ("AC-02", r"\b(?:SignOutAsync|SignOutManager)\s*\(", "登出流程"),
    ("AC-04", r"\b(?:AuthorizationHandler\s*<|IAuthorizationPolicyProvider\b|context\.Succeed\s*\(|GetPolicyAsync\s*\()", "授權政策或處理器"),
    ("AC-08", r"\b(?:IOwnedResource\b|GetMaxAllowedScope\s*\(|IAuthorizationService\.AuthorizeAsync\s*\()", "資源層授權"),
    ("AU-01", r"\b(?:PasswordOptions\b|Password\.RequireDigit\b|Password\.RequiredLength\b|Password\.RequireUppercase\b)", "密碼強度設定"),
    ("AU-03", r"\b(?:LockoutOptions\b|Lockout\.MaxFailedAccessAttempts\b|AccessFailedAsync\s*\()", "帳號鎖定控制"),
    ("AU-05", r"\b(?:Turnstile|Recaptcha|Captcha|VerifyTurnstileAsync)\b", "人機驗證"),
    ("AU-09", r"\b(?:Totp|TwoFactor|AuthenticatorTokenProvider)\b", "多因素認證"),
    ("IN-01", r"\b(?:FromSqlRaw|ExecuteSqlRaw|SqlCommand)\s*\(", "SQL 查詢入口"),
    ("IN-03", r"\b(?:ValidateAntiForgeryToken|AutoValidateAntiforgeryToken|AntiForgeryToken)\b", "CSRF Token"),
    ("IN-05", r"\b(?:IValidator\s*<|ValidationBehaviour\b|ModelState\.IsValid\b)", "伺服端驗證"),
    ("IN-06", r"\b(?:IFormFile\b|Request\.Form\.Files\b)", "上傳檔案處理"),
    ("CR-02", r"\b(?:Aes\.Create|SHA256\.HashData|HMACSHA256\b|Rfc2898DeriveBytes\b)", "密碼學操作"),
    ("CR-05", r"\b(?:UseHsts\s*\(|Content-Security-Policy|X-Frame-Options)", "HTTP 安全標頭"),
    ("CR-06", r"\b(?:CookiePolicyOptions\b|CookieSecurePolicy\b|Cookie\.HttpOnly\b|Cookie\.SameSite\b)", "Cookie 安全屬性"),
    ("EH-02", r"\b(?:UseExceptionHandler\s*\(|IExceptionHandler\b|ExceptionHandlingMiddleware\b)", "全域例外處理"),
    ("LG-01", r"\b(?:LogInformation|LogWarning|LogError|LogCritical)\s*\(", "安全事件與操作日誌"),
)
DOTNET_EXTENSIONS = frozenset({".cs", ".csx", ".razor", ".cshtml"})
COMPILED_DOTNET = tuple(
    (rid, re.compile(pattern, re.IGNORECASE), description)
    for rid, pattern, description in DOTNET_SIGNALS
)


def _code_lines(text: str) -> list[str]:
    """移除註解並保留行號；不把註解中的詞當成候選。"""
    without_blocks = re.sub(
        r"/\*.*?\*/",
        lambda match: "\n" * match.group().count("\n"), text,
        flags=re.DOTALL,
    )
    return [
        "" if line.lstrip().startswith(("//", "///", "*")) else line.split("//", 1)[0]
        for line in without_blocks.splitlines()
    ]


def candidate_hits(path: str, source: str) -> list[dict[str, object]]:
    """回傳高信心候選規則、行號及命中理由；呼叫端仍須逐條核對。"""
    suffix = Path(path).suffix.lower()
    if suffix not in DOTNET_EXTENSIONS:
        return []
    matched: dict[str, dict[str, object]] = {}
    for line_number, line in enumerate(_code_lines(source), 1):
        for rule_id, pattern, description in COMPILED_DOTNET:
            if rule_id not in matched and pattern.search(line):
                matched[rule_id] = {
                    "rule_id": rule_id, "line": line_number, "signal": description,
                }
    return [matched[rid] for rid in sorted(matched)]


def meaningful_source_excerpt(path: str, lines: list[str]) -> bool:
    """阻擋僅以 import、註解、宣告或空括號作為單獨的完成證據。

    僅驗證證據是否明顯無效；通過仍需人員核對資料流及安全控制。
    """
    code = [line.strip() for line in _code_lines("\n".join(lines)) if line.strip()]
    code = [line for line in code if line]
    if not code:
        return False
    meaningful = []
    for line in code:
        if line in {"{", "}", "[", "]", "(", ")", ";", "---"}:
            continue
        if re.match(r"^(?:using\s+[\w.]+\s*;|global\s+using\s+[\w.]+\s*;|namespace\s+[\w.]+\s*[;{]?)$", line):
            continue
        if line.startswith(("#nullable", "#pragma")):
            continue
        if (len(code) == 1 and Path(path).suffix.lower() in DOTNET_EXTENSIONS
                and re.match(r"^(?:public|private|protected|internal)\s+.*\([^;{}]*\)\s*\{?$", line)):
            continue
        meaningful.append(line)
    return bool(meaningful)


def main() -> int:
    parser = argparse.ArgumentParser(description="檢視來源中的規則候選（不自動判斷 pass/fail）")
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--path", required=True, help="相對於受測專案根目錄的來源路徑")
    args = parser.parse_args()
    root = args.source_root.resolve()
    path = (root / args.path).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        parser.error("無效來源路徑或越界")
    try:
        source = read_source_text(path)[0]
    except (OSError, UnicodeError) as exc:
        parser.error(str(exc))
    print(json.dumps({
        "path": path.relative_to(root).as_posix(),
        "candidates": candidate_hits(args.path, source),
        "notice": "候選須追蹤實際控制及資料流，不可直接寫入 completed/pass/fail。",
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
