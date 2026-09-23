#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-real-corpus.sh - scan public repositories pinned to a commit and report,
# for each one, how many components the scan identified and how many of them
# carry a purl and a license. The bundled examples are small and have no lock
# files, so this is the run that exercises real project layouts.
#
# The corpus is tests/corpus/real-corpus.tsv (name, ecosystem, repository, tag,
# commit, lockfile). Each repository is fetched at its pinned commit, scanned
# with `scan-sbom.sh --generate-only --fail-on empty-result`, and the source
# tree is checked for changes afterwards.
#
# Usage:
#   ./tests/test-real-corpus.sh
# Env:
#   ONLY="axios cobra"   restrict to some entries by name
#   ECOSYSTEMS="go rust" restrict to some ecosystems
#   WORK_DIR             clones and results (default: ~/.cache/bomlens-real-corpus;
#                        it must be under the home directory for Colima)
#   CORPUS_FILE          alternative corpus definition
#   SCAN_TIMEOUT         seconds allowed per repository (default 900)
#   SBOM_SCANNER_IMAGE   scanner image, passed through to scan-sbom.sh
#   BASELINE_FILE        results.tsv of an earlier run to compare with
#   DROP_POINTS          an ecosystem whose mean license coverage fell this many points
#                        against BASELINE_FILE fails the run (default 10)
#                        (tests/lib/corpus-compare.sh; it also applies the floors in
#                        tests/corpus/license-floor.tsv, with or without a baseline)
#   FAIL_ON_ARGS         judgement options for each scan (default: --fail-on empty-result).
#                        Set it to "" with a scanner image older than that option;
#                        an empty result is then recognised from the SBOM instead.
#
# Output: $WORK_DIR/results.tsv and a summary table on stdout (also appended to
# $GITHUB_STEP_SUMMARY when set).
#
# Each repository ends in one status:
#   ok            components found
#   empty         the scan identified no software (--fail-on empty-result, exit 4)
#   failed        the scan exited with another non-zero code, or wrote no readable SBOM
#   timeout       the scan did not finish within SCAN_TIMEOUT
#   undetermined  no quality result: the repository could not be fetched (network), or
#                 the scan could not judge (exit 5; usually a scanner image older than
#                 --fail-on, see FAIL_ON_ARGS)
# Exit code: 1 when any repository is empty, failed or timed out, or changed its source
# tree (build output that the repository ignores counts too); when license coverage
# regressed (against BASELINE_FILE or a floor); or when nothing at all could be
# measured. Otherwise 0. Without a running Docker engine the script skips (exit 0).
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
SCAN="$REPO/scripts/scan-sbom.sh"
CORPUS_FILE="${CORPUS_FILE:-$SCRIPT_DIR/corpus/real-corpus.tsv}"
WORK_DIR="${WORK_DIR:-$HOME/.cache/bomlens-real-corpus}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-900}"
FAIL_ON_ARGS="${FAIL_ON_ARGS---fail-on empty-result}"
RESULTS="$WORK_DIR/results.tsv"
export GIT_TERMINAL_PROMPT=0

for tool in git jq; do
    command -v "$tool" >/dev/null 2>&1 || { echo "[ERROR] $tool is required."; exit 1; }
done
[ -f "$CORPUS_FILE" ] || { echo "[ERROR] corpus file not found: $CORPUS_FILE"; exit 1; }
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "SKIP: docker unavailable"; exit 0
fi

# GNU timeout (Linux, Git Bash) or gtimeout (Homebrew coreutils); without either
# the scan runs unbounded. -k ends a scan that ignores the first signal.
TIMEOUT_CMD=""
command -v timeout >/dev/null 2>&1 && TIMEOUT_CMD="timeout"
[ -z "$TIMEOUT_CMD" ] && command -v gtimeout >/dev/null 2>&1 && TIMEOUT_CMD="gtimeout"

mkdir -p "$WORK_DIR/src" "$WORK_DIR/out" "$WORK_DIR/logs"
printf 'name\tecosystem\tlockfile\tstatus\texit\tcomponents\tpurl_pct\tlicense_pct\tseconds\ttree_clean\n' > "$RESULTS"

wanted() {  # wanted <name> <ecosystem>
    if [ -n "${ONLY:-}" ]; then case " $ONLY " in *" $1 "*) ;; *) return 1 ;; esac; fi
    if [ -n "${ECOSYSTEMS:-}" ]; then case " $ECOSYSTEMS " in *" $2 "*) ;; *) return 1 ;; esac; fi
    return 0
}

# Corpus values become paths and a git URL, so they are checked before use.
valid_entry() {  # valid_entry <name> <url> <commit>
    case "$1" in ''|*[!A-Za-z0-9._-]*|.|..) return 1 ;; esac
    case "$2" in https://*) ;; *) return 1 ;; esac
    case "$2" in *[[:space:]]*) return 1 ;; esac
    case "$3" in *[!0-9a-f]*) return 1 ;; esac
    [ "${#3}" -eq 40 ]
}

# Put the pinned commit in <dir>: reuse a clone that already is at it (reset and
# cleaned, ignored files included), otherwise fetch exactly that commit. A shallow
# fetch of a SHA works on GitHub; the tag is only a label for people. Git output
# goes to the entry's log. autocrlf is off so a Windows checkout reports no changes
# of its own.
fetch_pinned() {  # fetch_pinned <url> <commit> <dir> <log>
    if [ -d "$3/.git" ] && [ "$(git -C "$3" rev-parse HEAD 2>/dev/null)" = "$2" ]; then
        ( cd "$3" && git reset -q --hard && git clean -qfdx ) >> "$4" 2>&1 < /dev/null && return 0
    fi
    rm -rf "$3"
    [ -e "$3" ] && { echo "cannot remove $3" >> "$4"; return 2; }
    mkdir -p "$3"
    ( cd "$3" && git init -q && git config core.autocrlf false && git remote add origin "$1" \
        && git fetch -q --depth 1 origin "$2" && git checkout -q FETCH_HEAD ) >> "$4" 2>&1 < /dev/null
}

FAILED_ANY=0; SELECTED=0; MEASURED=0
# The corpus is read on fd 3 so nothing a child process does with stdin can eat it.
while IFS=$'\t' read -r -u 3 name eco url tag commit lock; do
    lock="${lock%$'\r'}"
    case "$name" in ''|'#'*) continue ;; esac
    wanted "$name" "$eco" || continue
    SELECTED=$((SELECTED + 1))
    echo ""
    echo "> $name ($eco, $tag)"
    if ! valid_entry "$name" "$url" "$commit"; then
        echo "  failed: invalid corpus entry (name, https URL or 40-character commit)"
        printf '%s\t%s\t%s\tfailed\t-\t-\t-\t-\t0\t-\n' "$(printf '%s' "$name" | tr -c 'A-Za-z0-9._-' '?')" "$eco" "$lock" >> "$RESULTS"
        FAILED_ANY=1; continue
    fi
    src="$WORK_DIR/src/$name"; out="$WORK_DIR/out/$name"; log="$WORK_DIR/logs/$name.log"
    : > "$log"
    rm -rf "$out"; mkdir -p "$out"

    fetch_pinned "$url" "$commit" "$src" "$log"; frc=$?
    if [ "$frc" -eq 2 ]; then
        echo "  failed: could not clear the previous clone (see $log)"
        printf '%s\t%s\t%s\tfailed\t-\t-\t-\t-\t0\t-\n' "$name" "$eco" "$lock" >> "$RESULTS"
        FAILED_ANY=1; continue
    elif [ "$frc" -ne 0 ]; then
        echo "  undetermined: could not fetch $url at $commit (see $log)"
        printf '%s\t%s\t%s\tundetermined\t-\t-\t-\t-\t0\t-\n' "$name" "$eco" "$lock" >> "$RESULTS"
        continue
    fi

    start=$(date +%s)
    # $FAIL_ON_ARGS is split on purpose: it holds whole options, not one word.
    # shellcheck disable=SC2086
    ( cd "$src" && ${TIMEOUT_CMD:+$TIMEOUT_CMD -k 60 "$SCAN_TIMEOUT"} bash "$SCAN" \
        --project "$name" --version "1.0" --generate-only $FAIL_ON_ARGS \
        --output-dir "$out" ) >> "$log" 2>&1 < /dev/null
    rc=$?
    secs=$(( $(date +%s) - start ))

    # The scan must not leave the checkout changed. Ignored files count: the
    # build output of these repositories is ignored by their own .gitignore.
    changed=$(cd "$src" && git status --porcelain --ignored 2>/dev/null)
    if [ -z "$changed" ]; then clean=yes; else
        clean=no
        echo "  the scan changed the source tree:"
        printf '%s\n' "$changed" | head -10 | sed 's/^/    /'
    fi

    bom=$(find "$out" -name "*_bom.json" -type f 2>/dev/null | head -1)
    comps="-"; purl="-"; lic="-"; bom_ok=""
    if [ -n "$bom" ]; then
        stats=$(jq -r '
            [ .components[]? | select(.type != "operating-system" and .type != "file") ] as $s
            | ($s | length) as $n
            | if $n == 0 then "0 - -" else
              ([ $s[] | select((.purl // "") != "") ] | length) as $p
              | ([ $s[] | select([ (.licenses // [])[]? | objects
                    | (.license.id // .license.name // .expression // "")
                    | select(type == "string" and . != "" and (ascii_upcase != "NOASSERTION") and (ascii_upcase != "NONE")) ]
                    | length > 0) ] | length) as $l
              | "\($n) \($p * 100 / $n | floor) \($l * 100 / $n | floor)" end' "$bom" 2>/dev/null) \
            && [ -n "$stats" ] && bom_ok=1
        [ -n "$bom_ok" ] && read -r comps purl lic <<< "$stats"
    fi

    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then status=timeout
    elif [ "$rc" -eq 4 ] || { [ "$rc" -eq 0 ] && [ "$comps" = 0 ]; }; then status=empty
    elif [ "$rc" -eq 5 ]; then
        status=undetermined
        echo "  the scan could not judge; with a scanner image older than --fail-on, set FAIL_ON_ARGS=\"\""
    elif [ "$rc" -ne 0 ] || [ -z "$bom_ok" ]; then status=failed
    else status=ok; fi
    case "$status" in undetermined) ;; *) MEASURED=$((MEASURED + 1)) ;; esac
    case "$status" in ok|undetermined) ;; *) FAILED_ANY=1 ;; esac
    [ "$clean" = yes ] || FAILED_ANY=1

    echo "  $status: exit=$rc components=$comps purl=${purl}% license=${lic}% tree_clean=$clean (${secs}s)"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$name" "$eco" "$lock" "$status" "$rc" "$comps" "$purl" "$lic" "$secs" "$clean" >> "$RESULTS"
done 3< "$CORPUS_FILE"

echo ""
echo "=================================================="
echo " Real-repository corpus"
echo "=================================================="
if [ "$SELECTED" -eq 0 ]; then echo "No corpus entry was selected."; exit 0; fi
if command -v column >/dev/null 2>&1; then column -t -s "$(printf '\t')" "$RESULTS"; else cat "$RESULTS"; fi
if [ "$MEASURED" -eq 0 ]; then
    echo "Nothing could be measured (every entry was undetermined)."
    FAILED_ANY=1
fi

echo ""
echo "License coverage judgement"
COMPARISON=$(bash "$SCRIPT_DIR/lib/corpus-compare.sh" "$RESULTS" "${BASELINE_FILE:-}" "${DROP_POINTS:-10}" "$SCRIPT_DIR/corpus/license-floor.tsv" 2>&1); crc=$?
printf '%s\n' "$COMPARISON"
case "$crc" in
    0) ;;
    1) FAILED_ANY=1 ;;
    *) echo "[ERROR] the license coverage judgement could not run (exit $crc)"; FAILED_ANY=1 ;;
esac

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "### Real-repository corpus"
        echo ""
        echo "| name | ecosystem | lock file | status | exit | components | purl % | license % | seconds | tree clean |"
        echo "|---|---|---|---|---|---|---|---|---|---|"
        tail -n +2 "$RESULTS" | awk -F'\t' '{ printf "|"; for (i = 1; i <= NF; i++) { f = $i; gsub(/\|/, "\\|", f); printf " %s |", f } printf "\n" }'
        if [ -n "$COMPARISON" ]; then
            echo ""
            echo "#### License coverage judgement"
            echo ""
            echo '```'
            printf '%s\n' "$COMPARISON"
            echo '```'
        fi
    } >> "$GITHUB_STEP_SUMMARY"
fi

exit "$FAILED_ANY"
