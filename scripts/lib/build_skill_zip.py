#!/usr/bin/env python3
"""產生可上傳至 Claude Desktop／claude.ai 的 Skill Zip；只讀套件檔案，僅寫入輸出 Zip。

上傳限制：最多 200 個檔案、Zip 內需有 SKILL.md，且 frontmatter 只接受
name／description／license／allowed-tools／metadata。因此只收錄審查執行期需要的檔案，
並把其他 frontmatter 欄位（version、argument-hint）移入 metadata；原始 SKILL.md 不變。
"""
from __future__ import annotations

import argparse
import ast
import re
import sys
import zipfile
from pathlib import Path

from package_manifest import package_files

ROOT = Path(__file__).resolve().parents[2]
SKILL_NAME = "security-code-review"
DEFAULT_OUTPUT = ROOT / "dist" / f"{SKILL_NAME}.zip"
MAX_FILES = 200
ALLOWED_FRONTMATTER = {"name", "description", "license", "allowed-tools", "metadata"}
# 開發與驗收用檔案；審查執行期不讀取。rules.yaml 與 rules/*.yaml 是 rules.json 的
# 對照副本，只有 validate_package 會比對；執行期只讀 rules.json。
DEV_ONLY_DIRS = {"tests", "examples", "rules"}
DEV_ONLY_FILES = {"CLAUDE.md", "README.md", "rules.yaml"}
# 套件維護 CLI：需要 Git 工作樹、SHA256SUMS.txt 或 rules.yaml，在上傳 Zip 內本來就無法執行。
# 連同 scripts/<name>.py wrapper 與 scripts/lib/<name>.py 一起排除。
DEV_ONLY_SCRIPTS = {"build_skill_zip", "package_manifest", "render_rules_markdown",
                    "validate_package", "validate_skill_docs"}
_DOC_PATH = re.compile(r"docs/([\w.-]+)")
_RELATIVE_LINK = re.compile(r"\]\((?:\./)?([\w.-]+)[)#]")
# 固定時間戳，相同內容產生相同 Zip。
_ZIP_TIME = (2020, 1, 1, 0, 0, 0)


def _text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return ""


def _referenced_docs(root: Path, seeds: list[str], docs: set[str]) -> set[str]:
    """自非 docs 檔案出發，沿 docs 之間的相對連結找出所有被引用的文件。"""
    found: set[str] = set()
    pending = [_text(root / rel) for rel in seeds]
    while pending:
        text = pending.pop()
        names = set(_DOC_PATH.findall(text)) | set(_RELATIVE_LINK.findall(text))
        for name in names:
            rel = f"docs/{name}"
            if rel in docs and rel not in found:
                found.add(rel)
                pending.append(_text(root / rel))
    return found


def _dev_only(rel: str) -> bool:
    if rel.split("/")[0] in DEV_ONLY_DIRS or rel in DEV_ONLY_FILES:
        return True
    return any(rel in (f"scripts/{name}.py", f"scripts/lib/{name}.py") for name in DEV_ONLY_SCRIPTS)


def upload_files(root: Path = ROOT) -> list[str]:
    files = [rel for rel in package_files(root) if not _dev_only(rel)]
    docs = {rel for rel in files if rel.startswith("docs/")}
    seeds = [rel for rel in files if rel not in docs]
    return sorted(set(seeds) | _referenced_docs(root, seeds, docs))


def missing_imports(root: Path, files: list[str]) -> list[str]:
    """收錄的 scripts/lib 模組若 import 了未收錄的 lib 模組（含函式內延遲 import），逐一列出。"""
    lib = root / "scripts" / "lib"
    available = {path.stem for path in lib.glob("*.py")}
    shipped = {Path(rel).stem for rel in files if rel.startswith("scripts/lib/") and rel.endswith(".py")}
    errors: list[str] = []
    for rel in sorted(rel for rel in files if rel.startswith("scripts/lib/") and rel.endswith(".py")):
        tree = ast.parse((root / rel).read_bytes(), filename=rel)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            else:
                continue
            for name in names:
                top = name.split(".")[0]
                if top in available and top not in shipped:
                    errors.append(f"{rel} imports {top}, which is excluded from the upload zip")
    return errors


def upload_skill_md(text: str) -> str:
    """把上傳端不接受的頂層 frontmatter 欄位原樣移入 metadata。"""
    match = re.match(r"---\r?\n(.*?)\r?\n---\r?\n", text, re.S)
    if not match:
        raise ValueError("SKILL.md 缺少 YAML frontmatter")
    kept: list[str] = []
    moved: list[str] = []
    target = kept
    for line in match.group(1).splitlines():
        key = re.match(r"([\w-]+):", line)
        if key:
            if key.group(1) == "metadata":
                raise ValueError("SKILL.md 已有 metadata，請直接在其中維護欄位")
            target = kept if key.group(1) in ALLOWED_FRONTMATTER else moved
        target.append(line)
    if moved:
        kept += ["metadata:"] + [f"  {line}" for line in moved]
    return "---\n" + "\n".join(kept) + "\n---\n" + text[match.end():]


def build(output: Path, root: Path = ROOT) -> list[str]:
    files = upload_files(root)
    if len(files) > MAX_FILES:
        raise ValueError(f"上傳檔案 {len(files)} 個，超過上限 {MAX_FILES}")
    broken = missing_imports(root, files)
    if broken:
        raise ValueError("; ".join(broken))
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for rel in files:
            data = (root / rel).read_bytes()
            if rel == "SKILL.md":
                data = upload_skill_md(data.decode("utf-8")).encode("utf-8")
            info = zipfile.ZipInfo(f"{SKILL_NAME}/{rel}", _ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT,
                        help=f"輸出 Zip 路徑（預設 {DEFAULT_OUTPUT.relative_to(ROOT).as_posix()}）")
    args = parser.parse_args(argv)
    try:
        files = build(args.output)
    except ValueError as error:
        print("ERROR:", error, file=sys.stderr)
        return 1
    print(f"wrote {args.output}: {len(files)}/{MAX_FILES} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
