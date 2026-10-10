#!/bin/sh
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# apply-pip-overrides.sh: write a copy of an upstream pip requirements file with
# the security overrides from an overrides file swapped in (image build helper).
#
# Usage: apply-pip-overrides.sh <upstream-requirements.txt> <overrides.txt> > merged.txt
#
# Each overrides line reads `<name>==<version>  # replaces <name>==<old> (...)`.
# The upstream line pinning <name> is replaced by `<name>==<version>`. The build
# fails, naming the package, when the upstream file does not pin exactly `<old>`:
# the upstream pin moved, and an override written for the old pin could now be
# a downgrade. Names compare per PEP 503 (case-insensitive, `-`/`_`/`.` alike).

set -eu

if [ "$#" -ne 2 ] || [ ! -f "$1" ] || [ ! -f "$2" ]; then
    echo "usage: apply-pip-overrides.sh <upstream-requirements.txt> <overrides.txt>" >&2
    echo "  both files must exist (got: '${1:-}' '${2:-}')" >&2
    exit 2
fi

awk '
function norm(spec,   n) {
    n = tolower(spec)
    sub(/[=<>!~ ;\[].*/, "", n)
    gsub(/[-_.]+/, "-", n)
    return n
}
NR == FNR {
    if ($0 ~ /^[ \t]*(#|$)/) next
    name = norm($1)
    rep = $0
    if (!sub(/.*# replaces /, "", rep)) {
        printf "apply-pip-overrides: %s has no \"# replaces <name>==<version>\" note\n", $1 > "/dev/stderr"
        bad = 1
        next
    }
    over[name] = $1
    split(rep, parts, /[ \t]/)
    expect[name] = parts[1]
    next
}
/^[A-Za-z0-9]/ {
    name = norm($1)
    if (name in over) {
        if ($1 != expect[name]) {
            printf "apply-pip-overrides: upstream now pins %s, but the override for %s was written for %s.\n", $1, name, expect[name] > "/dev/stderr"
            printf "  Re-check the advisory and either update or delete that line in the overrides file.\n" > "/dev/stderr"
            bad = 1
        }
        seen[name] = 1
        next
    }
}
{ print }
END {
    for (name in over) {
        if (!(name in seen)) {
            printf "apply-pip-overrides: upstream requirements no longer pin %s; delete or re-check its override.\n", name > "/dev/stderr"
            bad = 1
        }
        print over[name]
    }
    exit bad
}
' "$2" "$1"
