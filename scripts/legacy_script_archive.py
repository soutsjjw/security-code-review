#!/usr/bin/env python3
"""CLI 入口；實作位於 scripts/lib/legacy_script_archive.py，參數與結束碼完全相同。"""
import runpy
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# 移除 scripts/ 本身以免同名入口遮蔽 lib 模組，再讓 lib 優先載入。
sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() != HERE]
sys.path.insert(0, str(HERE / "lib"))
runpy.run_module("legacy_script_archive", run_name="__main__", alter_sys=True)
