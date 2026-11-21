#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# See the License for the specific language governing permissions and
# limitations under the License.
#
# check-line-endings.sh: every tracked text file is stored with LF, and every
# text file a Windows checkout would get is LF too, except the Windows batch and
# PowerShell files that must be CRLF. A Windows clone with core.autocrlf=true
# follows .gitattributes, so checking the attributes here covers that clone.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0

# 1. Nothing is stored with CRLF in the index.
stored_crlf="$(git ls-files --eol | awk '$1 ~ /crlf/ {print $NF}')"
if [ -n "$stored_crlf" ]; then
    echo "[ERROR] files stored with CRLF line endings (store them with LF):" >&2
    printf '  %s\n' $stored_crlf >&2
    fail=1
fi

# 2. Every text file checks out as LF, except *.bat and *.ps1 which check out as CRLF.
wrong="$(git ls-files --eol | awk -F '\t' '$1 !~ /^i\/(-text|none) / {print $2}' \
    | git check-attr --stdin eol \
    | awk -F ': ' '{ want = ($1 ~ /\.(bat|ps1)$/) ? "crlf" : "lf"; if ($3 != want) print $1 " (eol=" $3 ", want " want ")" }')"
if [ -n "$wrong" ]; then
    echo "[ERROR] these files would not check out with the right line endings on Windows; fix .gitattributes:" >&2
    printf '%s\n' "$wrong" | sed 's/^/  /' >&2
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "line endings: every text file is LF in the index and on checkout (CRLF only for .bat and .ps1)"
