#!/usr/bin/env python3
"""review_queue.py --categories 的分類審查 CLI 分派；參數由 review_queue 解析與驗證。"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from partial_review import (initialize as init_partial, integrate as integrate_partial,
                            queue as partial_queue, stage as stage_partial)
from partial_review_safety import (begin_second_pass as begin_partial_second_pass,
                                   prepare_index as prepare_partial_index, validate as validate_partial)
from review_scope import load_catalog, parse_categories


def run(args: argparse.Namespace, target: Path) -> int:
    try:
        selected = parse_categories(args.categories[0])
        catalog = load_catalog()
        if args.prepare:
            result = prepare_partial_index(target, catalog)
        elif args.begin_second_pass:
            if len(selected) != 1:
                raise ValueError("--begin-second-pass 每次只能指定單一分類")
            result = begin_partial_second_pass(target, selected[0], catalog)
        elif args.validate:
            results = [validate_partial(target, cat, catalog) for cat in selected]
            result = {"review_mode": "partial", "category_validation": results,
                      "safety_valid": all(r["safety_valid"] for r in results),
                      "ready_for_report": False}
        elif args.stage or args.integrate:
            if len(selected) != 1:
                raise ValueError("分類 --stage/--integrate 每次只能指定一個分類")
            category = selected[0]
            if args.stage:
                result = {"staged_path": str(stage_partial(target, category, args.stage, catalog)),
                          "ready_for_report": False}
            else:
                result = integrate_partial(target, category, catalog,
                                           allow_revision=args.allow_revision)
        else:
            if args.init:
                init_partial(target, selected, catalog)
            result = partial_queue(target, selected, catalog, args.batch_size,
                                   detail_id=args.detail_id, compact=args.compact)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if args.validate and not result["safety_valid"] else 0
