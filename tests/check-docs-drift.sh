#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# check-docs-drift.sh — guard the guides against drifting away from the tool.
# A user copies commands out of the docs and runs them verbatim, so a renamed
# flag, environment variable or published image silently breaks the walkthrough
# while every existing test stays green. This gate compares what the docs claim
# against what the code actually defines. No Docker needed.
#
# Hard failures (exit 1):
#   - a --flag used on a scan-sbom.sh/.bat command line that the script's option
#     parser does not accept
#   - an SBOM_* environment variable mentioned in the docs but defined nowhere in
#     the code
#   - a ghcr.io/sktelecom/* image referenced in the docs that the code/workflows
#     never build or publish
# Warnings (non-fatal):
#   - an English page and its .ko.md mirror passing different scan-sbom.sh flags
#
# Maintainer notes under docs/internal/ are excluded — they are not user-followed.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
FAIL=0
WARN=0

# --- Authoritative definitions, extracted from the code ---------------------
# scan-sbom.sh option parser: every `--flag)` / `--a|--b)` case label.
CODE_FLAGS="$(grep -oE '^[[:space:]]*--[a-z|-]+\)' scripts/scan-sbom.sh \
    | grep -oE -- '--[a-z-]+' | sort -u)"
# SBOM_* vars referenced by the CLI, the entrypoint, the lib scripts and the
# Dockerfile build args.
CODE_ENV="$(grep -rhoE 'SBOM_[A-Z0-9]+(_[A-Z0-9]+)*' \
    scripts/scan-sbom.sh docker/entrypoint.sh docker/lib/*.sh docker/Dockerfile 2>/dev/null \
    | sort -u)"
# Published image names (the registry path stops before the :tag), plus the
# legacy aliases the docs intentionally keep pointing users at (same digest,
# former names — see the "legacy alias" comments in scripts/scan-sbom.sh).
CODE_IMG="$(
    { grep -rhoE 'ghcr\.io/sktelecom/[a-z0-9._-]+' scripts docker .github 2>/dev/null
      printf '%s\n' ghcr.io/sktelecom/sbom-generator
    } | sort -u
)"

# --- Docs in scope: user-facing guides only --------------------------------
DOCS=()
while IFS= read -r f; do DOCS+=("$f"); done \
    < <(find docs -name '*.md' -not -path 'docs/internal/*' | sort)
for f in README.md docker/README.md examples/*/README.md; do
    [ -f "$f" ] && DOCS+=("$f")
done

# Join backslash-continued shell lines into one logical line (awk for portability
# across GNU/BSD sed).
join_cont() {
    awk '{
        line = $0
        while (line ~ /\\$/) {
            sub(/\\$/, "", line)
            if ((getline nxt) > 0) line = line nxt; else break
        }
        print line
    }' "$1"
}
# Membership test against a newline-separated list.
in_list() { printf '%s\n' "$2" | grep -qxF -- "$1"; }
# Flags passed to scan-sbom.sh/.bat in a file. The command span is cut at the
# first `|` (pipe) or backtick, so flags from a piped command or from prose that
# merely mentions `--flag` after a closed `scan-sbom.sh` code span are ignored.
scan_flags() {
    join_cont "$1" \
        | grep -oE 'scan-sbom\.(sh|bat)[^|`]*' \
        | grep -oE -- '--[a-z][a-z-]+' | sort -u
}

# --- Check 1: CLI flag drift ------------------------------------------------
for f in "${DOCS[@]}"; do
    while IFS= read -r flag; do
        [ -z "$flag" ] && continue
        if ! in_list "$flag" "$CODE_FLAGS"; then
            echo "  DRIFT[flag]: $f passes '$flag' to scan-sbom.sh, which has no such option"
            FAIL=$((FAIL + 1))
        fi
    done < <(scan_flags "$f")
done

# --- Check 2: SBOM_* environment-variable drift -----------------------------
while IFS= read -r e; do
    [ -z "$e" ] && continue
    if ! in_list "$e" "$CODE_ENV"; then
        echo "  DRIFT[env]: docs reference '$e', not defined in the code"
        FAIL=$((FAIL + 1))
    fi
done < <(grep -rhoE 'SBOM_[A-Z0-9]+(_[A-Z0-9]+)*' "${DOCS[@]}" 2>/dev/null | sort -u)

# --- Check 3: published-image drift -----------------------------------------
while IFS= read -r img; do
    [ -z "$img" ] && continue
    if ! in_list "$img" "$CODE_IMG"; then
        echo "  DRIFT[image]: docs reference '$img', which the code/workflows never build"
        FAIL=$((FAIL + 1))
    fi
done < <(grep -rhoE 'ghcr\.io/sktelecom/[a-z0-9._-]+' "${DOCS[@]}" 2>/dev/null | sort -u)

# --- Check 4: English/Korean command parity (warning) -----------------------
for f in "${DOCS[@]}"; do
    case "$f" in *.ko.md) continue ;; esac
    ko="${f%.md}.ko.md"
    [ -f "$ko" ] || continue
    if [ "$(scan_flags "$f")" != "$(scan_flags "$ko")" ]; then
        echo "  WARN[i18n]: $f and ${ko##*/} use different scan-sbom.sh flag sets"
        WARN=$((WARN + 1))
    fi
done

echo ""
[ "$WARN" -gt 0 ] && echo "${WARN} i18n warning(s) (non-fatal)"
if [ "$FAIL" -eq 0 ]; then
    echo "OK: docs reference no unknown scan-sbom.sh flags, SBOM_* vars or images"
else
    echo "FAIL: ${FAIL} doc/tool drift(s) — fix the doc or the code so they agree"
    exit 1
fi
