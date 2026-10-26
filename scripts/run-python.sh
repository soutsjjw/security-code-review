#!/bin/sh
# Read-only Python discovery. --resolve allows an agent to pin one verified interpreter.
set -eu
SKILL_ROOT=$(CDPATH= cd -- "${0%/*}/.." && pwd)
CHECKER="$SKILL_ROOT/scripts/check_python_env.py"
FIRST_BIN=''
SELECTED_BIN=''
FOUND_ENTRY=''

probe() {
    [ -z "$SELECTED_BIN" ] || return 0
    candidate=$1
    if [ -f "$candidate" ] || command -v "$candidate" >/dev/null 2>&1; then
        FOUND_ENTRY=1
    fi
    if "$@" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
        if [ -z "$FIRST_BIN" ]; then FIRST_BIN=$1; fi
        if "$@" "$CHECKER" --quiet >/dev/null 2>&1; then
            SELECTED_BIN=$("$@" -c 'import sys; print(sys.executable)' 2>/dev/null)
            [ -n "$SELECTED_BIN" ] && return 0
        fi
    fi
    return 1
}

if [ -n "${SECURITY_CODE_REVIEW_PYTHON_PINNED:-}" ]; then
    if ! probe "$SECURITY_CODE_REVIEW_PYTHON_PINNED"; then
        printf 'ERROR [pinned_python_unavailable]: Pinned Python is unavailable, too old, or missing dependencies.\n' >&2
        if [ -n "$FIRST_BIN" ]; then "$FIRST_BIN" "$CHECKER" >&2 || :; fi
        exit 2
    fi
else
    if [ -n "${SECURITY_CODE_REVIEW_PYTHON:-}" ]; then
        probe "$SECURITY_CODE_REVIEW_PYTHON" || printf 'WARN [preferred_python_unavailable]: Trying other installed interpreters.\n' >&2
    fi
    if [ -z "$SELECTED_BIN" ] && [ -n "${VIRTUAL_ENV:-}" ]; then probe "$VIRTUAL_ENV/bin/python" || :; fi
    if [ -z "$SELECTED_BIN" ] && [ -n "${CONDA_PREFIX:-}" ]; then probe "$CONDA_PREFIX/bin/python" || :; fi
    if [ -z "$SELECTED_BIN" ]; then probe "$PWD/.venv/bin/python" || :; fi
    if [ -z "$SELECTED_BIN" ]; then probe "$SKILL_ROOT/.venv/bin/python" || :; fi
    if [ -z "$SELECTED_BIN" ]; then probe python || :; fi
    if [ -z "$SELECTED_BIN" ]; then probe python3 || :; fi
    if [ -z "$SELECTED_BIN" ]; then probe py -3 || :; fi
fi

if [ -z "$SELECTED_BIN" ]; then
    if [ -n "$FIRST_BIN" ]; then
        printf 'ERROR [python_dependencies_invalid]: Python 3.10+ exists but required packages are missing or incompatible.\n' >&2
        "$FIRST_BIN" "$CHECKER" >&2 || :
    elif [ -n "$FOUND_ENTRY" ]; then
        printf 'ERROR [python_not_executable]: Python was found but failed version or execution checks. Check sandbox permissions.\n' >&2
    else
        printf 'ERROR [python_not_visible]: No usable Python 3.10+ is visible from this shell, WSL, or sandbox.\n' >&2
    fi
    exit 2
fi
if [ "${1:-}" = '--resolve' ]; then
    printf '%s\n' "$SELECTED_BIN"
    exit 0
fi
if [ "${1:-}" = '--check' ]; then
    "$SELECTED_BIN" "$CHECKER"
    exit $?
fi
if [ "$#" -lt 1 ] || [ ! -f "$1" ]; then
    printf 'ERROR: Provide an existing Python script or --check/--resolve.\n' >&2
    exit 2
fi
exec "$SELECTED_BIN" "$@"
