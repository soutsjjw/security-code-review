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
    ("AU-09", r"\b(?:\w*Totp\w*|TwoFactor\w*|AuthenticatorTokenProvider)\b", "多因素認證"),
    ("IN-01", r"\b(?:FromSqlRaw|ExecuteSqlRaw|SqlCommand)\s*\(", "SQL 查詢入口"),
    ("IN-03", r"\b(?:ValidateAntiForgeryToken|AutoValidateAntiforgeryToken|AntiForgeryToken)\b", "CSRF Token"),
    ("IN-05", r"\b(?:IValidator\s*<|ValidationBehaviour\b|ModelState\.IsValid\b|ValidateAsync\s*\(|ValidationException\b)", "伺服端驗證"),
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


# 這些規則常因「相關名詞存在」而被錯誤判定 Pass。
# 只有明確控制語句／呼叫／配置才算合理候選；命中不等於安全。
RULE_EVIDENCE_SIGNALS = {
    "AC-04": r"\b(?:context\.Succeed|context\.Fail|HandleRequirementAsync|RequireRole|RequireClaim|AuthorizeAsync|AddPolicy)\s*\(",
    "AC-08": r"\b(?:GetMaxAllowedScope|AuthorizeAsync|CheckAccess|IsOwner|OwnerId\s*==|UserId\s*==)\b",
    "AU-01": r"\b(?:Password\.RequiredLength|Password\.RequireDigit|Password\.RequireUppercase|Password\.RequireLowercase|Password\.RequiredUniqueChars|RequiredLength\s*=|RequireNonAlphanumeric\s*=)\b",
    "AU-08": r"\b(?:PasswordHasher|HashPassword|VerifyHashedPassword|PasswordHasherOptions|PasswordHash\s*=|PasswordVerificationResult)\b",
    "AU-09": r"\b(?:ValidateTwoFactor|TwoFactorSignIn|VerifyTwoFactor|VerifyTotp|CheckTotp|TotpEnabled|AuthenticatorSignIn|GenerateTwoFactorToken)\b",
    "IN-05": r"\b(?:ValidateAsync|ValidateAndThrow|ModelState\.IsValid|ValidationException|ValidationFailure|MustAsync|RuleFor)\b",
    "IN-06": r"(?:\bIFormFile\b|\.Length\s*[<>]=?|\.ContentType\b|\.FileName\b|\.OpenReadStream\b|\.CopyToAsync\b|\bAllowedExtensions\b)",
    "PD-07": r"\b(?:DeleteAsync|DeletePersonalData|RemoveRange|RemoveAsync|PurgeAsync|EraseAsync|ForgetUser|ExecuteDeleteAsync)\b",
    "SI-01": r"\b(?:permissions:|pull_request:|codeql|dependabot|security[-_]scan|sast|dependency[-_]review)\b",
}
AC08_RESOURCE_OPERATION_SIGNALS = re.compile(
    r"\b(?:FindAsync|FirstOrDefaultAsync|SingleOrDefaultAsync|SaveChangesAsync|ExecuteDeleteAsync)\s*|"
    r"\.(?:Where|Any|Select)\s*\(|\b(?:context|_context)\.Orders\b",
    re.IGNORECASE,
)
AC08_RESOURCE_TERMS = re.compile(
    r"\b(?:order|orders|OrderId|IOwnedResource|CreatedBy|OfficeId|DepartmentId|IsDelete)\b",
    re.IGNORECASE,
)
AC08_CONTROL_SIGNALS = re.compile(RULE_EVIDENCE_SIGNALS["AC-08"], re.IGNORECASE)
AC08_WIRING_SIGNALS = re.compile(
    r"\bAddScoped\s*<\s*IAuthorizationHandler\b|"
    r"\bPermissionResourceAuthorizationHandler\b",
    re.IGNORECASE,
)
SPECIAL_EXTERNAL_PROOF = frozenset({"DP-01", "DP-04"})
SPECIAL_PATH_RE = re.compile(r"(?:^|/)(?:\.github/workflows/|azure-pipelines[^/]*\.ya?ml$|\.gitlab-ci\.yml$)")
_MEMBER_DECLARATION = re.compile(
    r"^(?:(?:\[[^\]]+\]\s*)*)(?:(?:public|private|protected|internal|static|readonly|virtual|sealed|override|new|partial|async)\s+)*"
    r"(?:[\w?.<>,\[\] ]+\s+)+\w+\s*(?:\{\s*(?:get\s*;\s*set\s*;|get\s*;\s*init\s*;)\s*\}|;\s*|=\s*(?:default|null|true|false|\d+|\"[^\"]*\")\s*;)\s*$"
)
_USING_LINE = re.compile(r"^(?:global\s+)?using\s+(?:static\s+)?[\w.]+\s*;$")
_NAMESPACE_LINE = re.compile(r"^namespace\s+[\w.]+\s*[;{]?$")
_DECLARATION = re.compile(
    r"^(?:(?:public|private|protected|internal|sealed|abstract|partial|static|record|async)\s+)*"
    r"(?:class|interface|struct|enum|record)\s+\w+"
)
_METHOD_SIGNATURE = re.compile(
    r"^(?:(?:public|private|protected|internal|static|virtual|override|async|sealed|new|abstract|partial)\s+)+"
    r"(?:[\w?.<>,\[\] ]+\s+)?\w+\s*\([^;{}]*\)\s*(?:\{|;|=>)?$"
)


def _substantive_lines(path: str, lines: list[str]) -> list[str]:
    """保留行號範圍內真正表達行為的語句；排除宣告、註解與空容器。

    此為保守快篩，無法證明行為符合安全要求。
    """
    code = [line.strip() for line in _code_lines("\n".join(lines)) if line.strip()]
    is_dotnet = Path(path).suffix.lower() in DOTNET_EXTENSIONS
    substantive: list[str] = []
    for line in code:
        if line in {"{", "}", "[", "]", "(", ")", ";", "---"}:
            continue
        if line.startswith(("#", "@using")) or _USING_LINE.match(line) or _NAMESPACE_LINE.match(line):
            continue
        if is_dotnet:
            if _DECLARATION.match(line) or _METHOD_SIGNATURE.match(line):
                continue
            if _MEMBER_DECLARATION.match(line):
                continue
            if re.match(r"^var\s+builder\s*=\s*WebApplication\.CreateBuilder\s*\(", line):
                continue
        substantive.append(line)
    return substantive


def meaningful_source_excerpt(path: str, lines: list[str]) -> bool:
    """僅核對片段是否具備可查驗的控制操作，非符合性的證明。"""
    return bool(_substantive_lines(path, lines))


def source_relevant_to_rule(rule_id: str, path: str, lines: list[str]) -> bool:
    """攔截明顯與該規則無關的單行證據，不自動推定安全。"""
    substantive = _substantive_lines(path, lines)
    if not substantive:
        return False
    if rule_id in SPECIAL_EXTERNAL_PROOF:
        # 管理套件版本、引用套件本身，不能證明已掃描漏洞／更新安全版本。
        return bool(re.search(
            r"\b(?:dotnet\s+list\s+package.*--vulnerable|dotnet\s+package\s+list.*--vulnerable|"
            r"osv-scanner|dependency-check|dependabot|renovate|security[_-]updates|"
            r"npm\s+audit|trivy\s+(?:fs|image))\b",
            "\n".join(substantive), flags=re.IGNORECASE))
    if rule_id == "SI-01" and not SPECIAL_PATH_RE.search(path):
        return False
    if rule_id == "AC-08":
        text = "\n".join(substantive)
        # AC-08 has two legitimate evidence forms: a positive resource-
        # authorization control, or a concrete resource operation where the
        # absence of that control is the finding. The decision layer must
        # determine effectiveness; relevance alone must not treat an
        # authorization keyword as proof of safety.
        return bool(AC08_CONTROL_SIGNALS.search(text) or AC08_WIRING_SIGNALS.search(text) or (
            AC08_RESOURCE_OPERATION_SIGNALS.search(text)
            and AC08_RESOURCE_TERMS.search(text)
        ))
    signal = RULE_EVIDENCE_SIGNALS.get(rule_id)
    return bool(re.search(signal, "\n".join(substantive), flags=re.IGNORECASE)) if signal else True


def has_executable_control(rule_id: str, path: str, source: str) -> bool:
    """若檔案包含真正控制呼叫，不得藉「只有宣告／無程式邏輯」排除候選。"""
    if rule_id not in ("IN-05", "AC-04", "AC-08", "IN-06"):
        return False
    return source_relevant_to_rule(rule_id, path, source.splitlines())

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
