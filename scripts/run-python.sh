#!/bin/sh
# 以可用的 Python 執行指定腳本；僅檢測環境，不會自動安裝或改寫審查紀錄。
set -eu
SKILL_ROOT=$(CDPATH= cd -- "${0%/*}/.." && pwd)
CHECKER="$SKILL_ROOT/scripts/check_python_env.py"
FIRST_BIN=''
FIRST_ARG=''
SELECTED_BIN=''
SELECTED_ARG=''

probe() {
    if "$@" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
        if [ -z "$FIRST_BIN" ]; then
            FIRST_BIN=$1
            FIRST_ARG=${2:-}
        fi
        if "$@" "$CHECKER" --quiet >/dev/null 2>&1; then
            SELECTED_BIN=$1
            SELECTED_ARG=${2:-}
            return 0
        fi
    fi
    return 1
}

run_python() {
    if [ -n "$SELECTED_ARG" ]; then
        "$SELECTED_BIN" "$SELECTED_ARG" "$@"
    else
        "$SELECTED_BIN" "$@"
    fi
}

if [ -n "${SECURITY_CODE_REVIEW_PYTHON:-}" ]; then
    probe "$SECURITY_CODE_REVIEW_PYTHON" || :
else
    probe python || probe python3 || probe py -3 || :
fi

if [ -z "$SELECTED_BIN" ]; then
    if [ -n "$FIRST_BIN" ]; then
        if [ -n "$FIRST_ARG" ]; then
            "$FIRST_BIN" "$FIRST_ARG" "$CHECKER" >&2 || :
            printf '請先執行：%s %s -m pip install -r "%s/requirements.txt"\n' "$FIRST_BIN" "$FIRST_ARG" "$SKILL_ROOT" >&2
        else
            "$FIRST_BIN" "$CHECKER" >&2 || :
            printf '請先執行：%s -m pip install -r "%s/requirements.txt"\n' "$FIRST_BIN" "$SKILL_ROOT" >&2
        fi
    else
        printf 'ERROR: 此執行環境找不到 Python 3.10+。請安裝 Python 並確認 python、python3 或 py -3 可用。\n' >&2
    fi
    exit 2
fi

if [ "${1:-}" = '--check' ]; then
    run_python "$CHECKER"
    exit $?
fi
if [ "$#" -lt 1 ] || [ ! -f "$1" ]; then
    printf 'ERROR: 需指定已存在的 Python 腳本，或使用 --check。\n' >&2
    exit 2
fi
run_python "$@"
