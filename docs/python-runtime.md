# Python 執行環境確認與固定

此文件適用完整與分類審查；在任何 Python 審查初始化或執行 Log 之前讀取。無法執行時需保留審查進度並回報原因。

## Python 執行環境確認與固定（兩種模式共用）

開始任何審查初始化或 Log 前，由 **Agent 實際執行的 shell** 呼叫啟動器。不要僅根據另一個終端的 `python --version`，便宣稱 Codex 的環境已有或沒有 Python：

- Windows PowerShell：`& "<SKILL_ROOT>\\scripts\\run-python.cmd" --check`；`--resolve` 會在標準輸出回傳已驗證的 `python.exe` 絕對路徑。
- macOS／Linux／WSL：`sh "<SKILL_ROOT>/scripts/run-python.sh" --check`；同樣以 `--resolve` 取得直譯器位置。WSL 與 Windows 是不同執行環境，不能假設共用安裝。
- 同一次審查先執行 `--resolve` 並保存結果，將其設定為 `SECURITY_CODE_REVIEW_PYTHON_PINNED`，其後所有批次使用同一支直譯器。**不同工具呼叫若不保留環境變數，Agent 必須在每次呼叫前重新帶入既有絕對路徑**；不可重新自動選版冒充已固定。固定執行檔不存在、版本不足或相依驗證失敗時，必須阻斷並回報，不能切換版本。
- `SECURITY_CODE_REVIEW_PYTHON` 只表示偏好路徑；若失效會警告並繼續尋找。Windows 會檢查 PATH、`py`、虛擬環境、LocalAppData、Program Files、Scoop／pyenv-win 常見安裝位置。沒有找到時回報 **目前 Codex 環境不可見**，而不是斷言使用者未安裝。
- `--check` / `--resolve` 只讀；不安裝 Python 或套件，不建立／重置審查進度。若缺套件，只顯示具體缺失；若存取遭拒，檢查沙箱權限，不修改受測專案。

Windows 範例（同一 PowerShell 工作階段）：

```powershell
$resolvedPython = & "<SKILL_ROOT>\\scripts\\run-python.cmd" --resolve
if ($LASTEXITCODE -ne 0 -or -not $resolvedPython) { throw "Python 環境檢查失敗" }
$env:SECURITY_CODE_REVIEW_PYTHON_PINNED = $resolvedPython.Trim()
& "<SKILL_ROOT>\\scripts\\run-python.cmd" --check
```

POSIX 範例（同一 shell 工作階段）：

```bash
export SECURITY_CODE_REVIEW_PYTHON_PINNED="$(sh "<SKILL_ROOT>/scripts/run-python.sh" --resolve)"
test -n "$SECURITY_CODE_REVIEW_PYTHON_PINNED" || exit 2
sh "<SKILL_ROOT>/scripts/run-python.sh" --check
```
