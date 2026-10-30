#!/usr/bin/env python3
"""從已實際審查的程式碼擷取分級線索，不取代法定核定。"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from source_reader import DEFAULT_LEGACY_ENCODINGS, read_source_text

ROLE_GUARDS = (
    re.compile(r'\[\s*Authorize\s*\(\s*Roles\s*=', re.I),
    re.compile(r'\bRequireRole\s*\(', re.I),
    re.compile(r'@\s*PreAuthorize\s*\([^)]*\bhas(?:Any)?Role\s*\(', re.I),
    re.compile(r'@\s*RolesAllowed\s*\(', re.I),
    re.compile(r'\bhasRole\s*\(\s*["\x27]', re.I),
    re.compile(r'^\s*@\s*permission_required\s*\(', re.I),
    re.compile(r'\b(?:user|principal|account)\.has_perm\s*\(', re.I),
)
SOURCE_EXTENSIONS = {'.cs', '.java', '.kt', '.js', '.jsx', '.ts', '.tsx',
                     '.py', '.php', '.go', '.rb', '.scala'}
MISSING_CONTEXT = [
    '機關是否適用本辦法及是否實際維運受測系統',
    '是否另符合第四條 A 級或第五條 B 級的較高等級條件',
    '權責機關正式分級認定或核定結果',
]


def infer_security_level(
    assessment: dict[str, Any], source_root: Path | None,
    source_encodings: tuple[str, ...] = DEFAULT_LEGACY_ENCODINGS,
) -> dict[str, Any]:
    """只使用 completed 的 inspected_paths；不寫入正式 security_level。"""
    inspected = set()
    for check in assessment.get('checks', []):
        execution = check.get('execution', {})
        if execution.get('state') == 'completed':
            inspected.update(execution.get('inspected_paths', []))

    evidence = []
    if source_root is not None:
        root = source_root.resolve()
        for candidate in sorted(inspected):
            name = str(candidate).replace('\\', '/')
            if (name.startswith(('/', '//')) or re.match(r'^[A-Za-z]:', name)
                    or '..' in name.split('/')):
                continue
            rel = Path(name)
            if rel.suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            if any(part.lower() in {'test', 'tests', '__tests__', 'fixtures', 'samples', 'examples'}
                   for part in rel.parts):
                continue
            path = (root / rel).resolve()
            if not path.is_relative_to(root) or not path.is_file():
                continue
            try:
                if path.stat().st_size > 1_000_000:
                    continue
                code = read_source_text(path, source_encodings)[0]
            except (OSError, UnicodeError, LookupError):
                continue
            for line_no, line in enumerate(code.splitlines(), 1):
                if line.lstrip().startswith(('//', '#', '*', '<!--')):
                    continue
                if any(pattern.search(line) for pattern in ROLE_GUARDS):
                    evidence.append({'path': name, 'line_start': line_no, 'line_end': line_no})
                    break
            if len(evidence) >= 3:
                break

    if evidence:
        first = evidence[0]
        return {
            'status': 'preliminary',
            'level': 'C',
            'basis': (
                f"已審查的 {first['path']}:{first['line_start']} 發現角色或權限管理程式碼，"
                '可作為《資通安全責任等級分級辦法》第六條 C 級技術條件的初步線索。'
                '無法僅由程式碼確認機關實際維運或排除第四、五條較高分級；'
                '此結果不是法定核定。'
            ),
            'evidence': evidence,
            'missing_information': list(MISSING_CONTEXT),
        }

    return {
        'status': 'undetermined',
        'level': '待確認',
        'basis': (
            '已審查的程式碼缺乏足以初判 A～E 級的直接證據；'
            '仍需確認機關業務範圍、實際維運責任及核定資料。'
            '缺少技術線索不代表 D／E 級，也不影響 70 項審查。'
            if source_root is not None else
            '未提供來源目錄，無法核對實際程式碼；'
            '仍需確認機關業務、維運責任及核定資料。'
        ),
        'evidence': [],
        'missing_information': list(MISSING_CONTEXT),
    }
