#!/usr/bin/env bash
# Create or update the oracle virtualenv at <repo>/.venv (POSIX layout: .venv/bin/python).
#
# Installs the pinned packages from tools/requirements-dev.txt. Idempotent: when the venv
# already matches the requirements file it exits without touching the network, and a broken
# venv (for example after a Python upgrade) is recreated.
#
# Environment:
#   PYTHON   interpreter used to create the venv (default: python3, must be >= 3.11)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
venv="$repo_root/.venv"
requirements="$repo_root/tools/requirements-dev.txt"
stamp="$venv/.folioxide-requirements.sha256"
python="${PYTHON:-python3}"

if ! command -v "$python" >/dev/null 2>&1; then
    echo "setup-venv: '$python' not found; install Python >= 3.11 or set PYTHON=" >&2
    exit 2
fi
# pikepdf 10 needs Python >= 3.11.
if ! "$python" -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
    echo "setup-venv: $("$python" -V 2>&1) is too old; Python >= 3.11 is required" >&2
    exit 2
fi

# The stamp ties the venv to the exact requirements file and interpreter version.
fingerprint="$("$python" -I -c '
import hashlib, sys
h = hashlib.sha256(open(sys.argv[1], "rb").read())
h.update(sys.version.encode())
print(h.hexdigest())
' "$requirements")"

# A usable venv runs and was built from the same interpreter version as "$python".
want_version="$("$python" -I -c 'import sys; print(sys.version)')"
venv_ok() {
    [ -x "$venv/bin/python" ] \
        && [ "$("$venv/bin/python" -I -c 'import sys; print(sys.version)' 2>/dev/null)" = "$want_version" ]
}

if venv_ok && [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$fingerprint" ] \
    && "$venv/bin/python" -I -c 'import pyhanko, pypdf, pikepdf, asn1crypto, yaml' >/dev/null 2>&1; then
    echo "setup-venv: $venv is up to date"
    exit 0
fi

if venv_ok; then
    echo "setup-venv: updating $venv"
else
    echo "setup-venv: creating $venv with $("$python" -V 2>&1)"
    "$python" -m venv --clear "$venv"
fi

"$venv/bin/python" -I -m pip install --disable-pip-version-check --no-input --quiet \
    --require-virtualenv -r "$requirements"
"$venv/bin/python" -I -c 'import pyhanko, pypdf, pikepdf, asn1crypto, yaml'
printf '%s\n' "$fingerprint" > "$stamp"
echo "setup-venv: ready ($("$venv/bin/python" -V 2>&1); pyhanko, pypdf, pikepdf installed)"
