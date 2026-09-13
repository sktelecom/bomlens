#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
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
#   - a CycloneDX/specVersion literal that disagrees with the code's constants
#     (1.6 from docker/lib/cdx-version.sh; the AI/dataset 1.7 variant from the
#     CDX_SPEC_VERSION constant restated in identify-model-file.py and
#     scan-figshare.py, cross-checked against scan-aibom.sh's _1_7.json name)
#   - a specVersion/cyclonedx-json@ literal anywhere under docker/lib/,
#     docker/entrypoint.sh or scripts/scan-sbom.sh that does not read
#     CDX_SPEC_VERSION (the two AI/dataset 1.7 producers and the two
#     deliberately-different call sites below are the only exceptions)
#   - a version-pinned ghcr.io/sktelecom/*:x.y.z example for a release that was
#     never tagged
#   - a docker-run example passing an env var the entrypoint/server never read,
#     or missing its MODE's required inputs
#   - an English page and its .ko.md mirror whose <!-- runnable --> blocks
#     differ in their command lines (comments may translate)
# Warnings (non-fatal):
#   - an English page and its .ko.md mirror passing different scan-sbom.sh flags
#   - a pinned-tag example that is not the newest release (stale advice)
#
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
FAIL=0
WARN=0

# --- Authoritative definitions, extracted from the code ---------------------
# scan-sbom.sh option parser: every `--flag)` / `--a|--b)` case label.
CODE_FLAGS="$(grep -oE '^[[:space:]]*--[a-z|-]+\)' scripts/scan-sbom.sh \
    | grep -oE -- '--[a-z-]+' | sort -u)"
# SBOM_* vars referenced by the CLI, the entrypoint, the lib scripts, the
# Dockerfile build args, the web UI server/launchers (SBOM_OUTPUT_DIR lives
# there, not in the CLI) and the desktop container wrapper.
CODE_ENV="$(grep -rhoE 'SBOM_[A-Z0-9]+(_[A-Z0-9]+)*' \
    scripts/scan-sbom.sh scripts/scan-sbom.bat scripts/sbom-ui.bat scripts/check-setup.bat \
    scripts/bomlens.settings.example.txt docker/entrypoint.sh docker/lib/*.sh \
    docker/Dockerfile docker/web/server.py electron/lib/container.mjs 2>/dev/null \
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
    < <(find docs -name '*.md' | sort)
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

# --- Check 5: desktop installer download name -------------------------------
# electron-builder pins a versionless artifact name; the permanent
# releases/latest/download URL only resolves if the docs use that exact name.
# Any *.exe/*.dmg installer named in a guide must use that canonical base.
#
# Lines that scan a file are excluded. A guide now also names an installer as a
# thing to scan (`--target installer.exe`), which is somebody else's file and has
# no reason to carry our artifact name. Excluding by the scan flag keeps the check
# on the download references it was written for. `bash.exe` is excluded too: it
# is Git Bash's own binary (SBOM_BASH points at it), not something we publish.
# shellcheck disable=SC2016  # the ${ext} in the grep pattern is a literal
art="$(grep -oE 'artifactName:[[:space:]]*[A-Za-z0-9.${}-]+' electron/electron-builder.yml 2>/dev/null | head -1 | awk '{print $2}')"
art_base="${art%%.\$\{ext\}}"
if [ -n "$art_base" ] && [ "$art_base" != "$art" ]; then
    while IFS= read -r name; do
        [ -z "$name" ] && continue
        base="${name%.*}"; base="${base%-\*}"
        if [ "$base" != "$art_base" ]; then
            echo "  DRIFT[download]: docs name installer '$name', but electron-builder ships '${art_base}.{exe,dmg}'"
            FAIL=$((FAIL + 1))
        fi
    done < <(grep -rhv -- '--target' "${DOCS[@]}" 2>/dev/null \
             | grep -oE '[A-Za-z0-9][A-Za-z0-9._*-]*\.(exe|dmg)' \
             | grep -vxF 'bash.exe' | sort -u)
fi

# --- Check 6: Windows output folder -----------------------------------------
# sbom-ui.bat writes results to a fixed folder; the no-CLI guide tells the user
# where to look. They must agree.
outdir_leaf="$(grep -oE 'OUTDIR=%USERPROFILE%\\[A-Za-z0-9_-]+' scripts/sbom-ui.bat 2>/dev/null | head -1 | sed 's#.*\\##')"
if [ -n "$outdir_leaf" ] && [ -f docs/start/no-cli.md ] && ! grep -q "$outdir_leaf" docs/start/no-cli.md; then
    printf '  DRIFT[output]: sbom-ui.bat writes to %%USERPROFILE%%\\%s, not mentioned in docs/start/no-cli.md\n' "$outdir_leaf"
    FAIL=$((FAIL + 1))
fi

# --- Check 7: CycloneDX spec-version literals --------------------------------
# The docs promise concrete spec versions ("CycloneDX 1.6", ML-BOM "1.7",
# "specVersion": "1.6"). When the tooling bumps, every stale literal must fail
# here instead of quietly misinforming readers. Sources of truth in code:
# docker/lib/cdx-version.sh's CDX_SPEC_VERSION for the SBOM; the CDX_SPEC_VERSION
# constant restated in identify-model-file.py / scan-figshare.py for the
# AI/dataset ML-BOM, cross-checked against scan-aibom.sh's kept _1_7.json variant.
SPEC=""
if [ -f docker/lib/cdx-version.sh ]; then
    # shellcheck disable=SC1091
    SPEC="$(. docker/lib/cdx-version.sh && echo "$CDX_SPEC_VERSION")"
fi
MLSPEC="$(grep -oE '_[0-9]_[0-9]\.json' docker/lib/scan-aibom.sh | head -1 | grep -oE '[0-9]_[0-9]' | tr '_' '.')"
PY_MLSPEC_MODEL="$(grep -oE '^CDX_SPEC_VERSION = "[0-9.]+"' docker/lib/identify-model-file.py | head -1 | grep -oE '[0-9]+\.[0-9]+')"
PY_MLSPEC_FIGSHARE="$(grep -oE '^CDX_SPEC_VERSION = "[0-9.]+"' docker/lib/scan-figshare.py | head -1 | grep -oE '[0-9]+\.[0-9]+')"
if [ -z "$SPEC" ] || [ -z "$MLSPEC" ] || [ -z "$PY_MLSPEC_MODEL" ] || [ -z "$PY_MLSPEC_FIGSHARE" ]; then
    echo "  DRIFT[spec]: cannot extract spec versions from code (cdx-version.sh / scan-aibom.sh / identify-model-file.py / scan-figshare.py changed shape?)"
    FAIL=$((FAIL + 1))
elif [ "$PY_MLSPEC_MODEL" != "$MLSPEC" ] || [ "$PY_MLSPEC_FIGSHARE" != "$MLSPEC" ]; then
    echo "  DRIFT[spec]: AI/dataset CDX_SPEC_VERSION disagrees across producers (scan-aibom.sh: $MLSPEC, identify-model-file.py: $PY_MLSPEC_MODEL, scan-figshare.py: $PY_MLSPEC_FIGSHARE)"
    FAIL=$((FAIL + 1))
fi
# The non-AI Python producers restate the BASH constant's value (1.6), not the
# AI/dataset one -- nothing in Python can source cdx-version.sh, so each of
# these three files carries its own CDX_SPEC_VERSION line that must still
# agree with it, or a bash-side bump silently leaves these three behind.
PY_SPEC_FAIL=0
for pyf in docker/lib/identify-modelica.py docker/lib/parse-yocto-manifests.py docker/lib/parse-yocto-spdx.py; do
    pyspec="$(grep -oE '^CDX_SPEC_VERSION = "[0-9.]+"' "$pyf" 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+')"
    if [ -z "$pyspec" ]; then
        echo "  DRIFT[spec]: cannot extract CDX_SPEC_VERSION from $pyf (changed shape?)"
        FAIL=$((FAIL + 1)); PY_SPEC_FAIL=1
    elif [ -n "$SPEC" ] && [ "$pyspec" != "$SPEC" ]; then
        echo "  DRIFT[spec]: $pyf's CDX_SPEC_VERSION ($pyspec) disagrees with cdx-version.sh ($SPEC)"
        FAIL=$((FAIL + 1)); PY_SPEC_FAIL=1
    fi
done
if [ -z "$SPEC" ] || [ -z "$MLSPEC" ] || [ -z "$PY_MLSPEC_MODEL" ] || [ -z "$PY_MLSPEC_FIGSHARE" ] \
    || [ "$PY_MLSPEC_MODEL" != "$MLSPEC" ] || [ "$PY_MLSPEC_FIGSHARE" != "$MLSPEC" ] || [ "$PY_SPEC_FAIL" = 1 ]; then
    : # already reported above; skip the docs/code sweep below on bad input
else
    for f in "${DOCS[@]}"; do
        while IFS=: read -r ln line; do
            [ -z "$line" ] && continue
            while IFS= read -r v; do
                [ -z "$v" ] && continue
                if [ "$v" = "$SPEC" ]; then
                    continue
                elif [ "$v" = "$MLSPEC" ]; then
                    # The ML-BOM version is only correct in AI-model context.
                    if ! printf '%s' "$line" | grep -qiE 'ml-?bom|model|aibom|\bAI\b'; then
                        echo "  DRIFT[spec]: $f:$ln uses CycloneDX $v outside an AI/ML-BOM context (SBOM specVersion is $SPEC)"
                        FAIL=$((FAIL + 1))
                    fi
                else
                    echo "  DRIFT[spec]: $f:$ln claims CycloneDX $v; the code produces $SPEC (ML-BOM: $MLSPEC)"
                    FAIL=$((FAIL + 1))
                fi
            done < <(printf '%s' "$line" \
                | grep -oE "CycloneDX [0-9]+\.[0-9]+|\"?specVersion\"?[: ]+\"?[0-9]+\.[0-9]+\"?" \
                | grep -oE '[0-9]+\.[0-9]+')
        done < <(grep -nE "CycloneDX [0-9]+\.[0-9]+|specVersion.?.?[: ]+.?[0-9]+\.[0-9]+" "$f" 2>/dev/null)
    done

    # A stray literal here means a bash producer stopped reading
    # $CDX_SPEC_VERSION -- the same drift the docs loop above catches, but in
    # the code instead of a guide. Derived from who actually sources
    # cdx-version.sh (rather than hand-maintained) so a new sourcing call site
    # is covered automatically. docker/lib/cdx-version.sh itself (the
    # constant's definition) and scan-security.sh's Trivy-input-retry fallback
    # (a different literal, never sourced, so it is not in this list at all)
    # are the only exclusions; validate-sbom.sh IS included; see the regex
    # note below for why that does not false-positive on its own
    # `.specVersion != null` / `// ""`-style comparisons.
    CDX_PRODUCERS=()
    while IFS= read -r f; do
        CDX_PRODUCERS+=("$f")
    done < <(grep -rlE '\. "\$[A-Za-z_]+/(docker/lib/)?cdx-version\.sh"' docker/ scripts/ 2>/dev/null \
        | grep -v '^docker/lib/cdx-version\.sh$' | sort)
    if [ "${#CDX_PRODUCERS[@]}" -eq 0 ]; then
        echo "  DRIFT[spec]: no file sources docker/lib/cdx-version.sh (source-line pattern changed, or the file was orphaned?)"
        FAIL=$((FAIL + 1))
    fi
    for f in "${CDX_PRODUCERS[@]}"; do
        [ -f "$f" ] || continue
        while IFS=: read -r ln line; do
            [ -z "$line" ] && continue
            echo "  DRIFT[spec]: $f:$ln has a CycloneDX spec-version literal instead of reading \$CDX_SPEC_VERSION: $line"
            FAIL=$((FAIL + 1))
        done < <(grep -nE 'specVersion"?[[:space:]]*:[[:space:]]*"[0-9]+\.[0-9]+|cyclonedx-json@[0-9]+\.[0-9]+|--spec-version[[:space:]]+"?[0-9]+\.[0-9]+|--arg spec "[0-9]+\.[0-9]+"' "$f" 2>/dev/null)
    done

    # validate-sbom.sh's CYCLONEDX_SPEC_VERSIONS is an accepted-INPUT range for
    # --analyze, deliberately independent of $CDX_SPEC_VERSION (a submission
    # requirement, not what this pipeline itself produces) -- but if its upper
    # bound ever falls below $SPEC, this pipeline's own dependency-SBOM output
    # would fail the conformance check it runs against itself.
    RANGE_LINE="$(grep -oE 'CYCLONEDX_SPEC_VERSIONS="\$\{CYCLONEDX_SPEC_VERSIONS:-[0-9. ]+\}"' docker/lib/validate-sbom.sh | head -1)"
    RANGE_MAX="$(printf '%s' "$RANGE_LINE" | grep -oE '[0-9]+\.[0-9]+' | sort -V | tail -1)"
    if [ -z "$RANGE_MAX" ]; then
        echo "  DRIFT[spec]: cannot extract CYCLONEDX_SPEC_VERSIONS' range from docker/lib/validate-sbom.sh (changed shape?)"
        FAIL=$((FAIL + 1))
    elif [ -n "$SPEC" ] && [ "$(printf '%s\n%s\n' "$RANGE_MAX" "$SPEC" | sort -V | tail -1)" != "$RANGE_MAX" ]; then
        echo "  DRIFT[spec]: validate-sbom.sh's CYCLONEDX_SPEC_VERSIONS tops out at $RANGE_MAX, below what this pipeline produces ($SPEC) -- our own SBOMs would fail --analyze"
        FAIL=$((FAIL + 1))
    fi
fi

# --- Check 8: version-pinned image-tag examples -------------------------------
# cli.md shows pinning (SBOM_SCANNER_IMAGE=...:x.y.z). A pinned example for a
# release that never existed sends readers to a tag docker cannot pull; one that
# lags far behind teaches pinning to a stale version. Tags may be absent in a
# shallow CI checkout, so fetch them quietly first (offline runs just skip).
if [ -z "$(git tag -l 'v*' | head -1)" ]; then
    git fetch --tags --quiet 2>/dev/null || true
fi
RELEASE_TAGS="$(git tag -l 'v*' 2>/dev/null | sort -V)"
NEWEST_TAG="$(printf '%s\n' "$RELEASE_TAGS" | tail -1)"
if [ -z "$RELEASE_TAGS" ]; then
    echo "  WARN[pin]: no release tags available (shallow clone, offline) — pinned-tag check skipped"
    WARN=$((WARN + 1))
else
    while IFS= read -r pin; do
        [ -z "$pin" ] && continue
        ver="${pin##*:}"
        if ! printf '%s\n' "$RELEASE_TAGS" | grep -qxF "v$ver"; then
            echo "  DRIFT[pin]: docs pin '$pin', but release v$ver was never tagged"
            FAIL=$((FAIL + 1))
        elif [ "v$ver" != "$NEWEST_TAG" ]; then
            echo "  WARN[pin]: docs pin '$pin'; newest release is $NEWEST_TAG (stale example)"
            WARN=$((WARN + 1))
        fi
    done < <(grep -rhoE 'ghcr\.io/sktelecom/[a-z0-9._-]+:[0-9]+\.[0-9]+\.[0-9]+' "${DOCS[@]}" 2>/dev/null | sort -u)
fi

# --- Check 9: docker-run example env/mount contract ---------------------------
# docker-image.md (and example READMEs) show `docker run ... ghcr.io/sktelecom/*`
# invocations. Every -e VAR must be one the entrypoint/server actually reads
# (Check 2 only covers SBOM_*), and each MODE's block must carry that mode's
# required inputs (the entrypoint exits 1 without them).
CODE_RUNENV="$(grep -rhoE '\b[A-Z][A-Z0-9_]{2,}\b' \
    docker/entrypoint.sh docker/lib/*.sh docker/web/server.py scripts/scan-sbom.sh 2>/dev/null | sort -u)"
MODE_REQS="
IMAGE::TARGET_IMAGE /var/run/docker.sock
BINARY::TARGET_FILE
ROOTFS::TARGET_DIR
FIRMWARE::TARGET_FILE
ANALYZE::ANALYZE_SBOM
SOURCE:::/src
"
for f in "${DOCS[@]}"; do
    while IFS= read -r cmd; do
        [ -z "$cmd" ] && continue
        # A --entrypoint run invokes a bundled tool (cosign, syft, ...) directly;
        # its env belongs to that tool, not to the entrypoint contract.
        printf '%s' "$cmd" | grep -q -- '--entrypoint' && continue
        # Unknown env vars.
        while IFS= read -r var; do
            [ -z "$var" ] && continue
            if ! in_list "$var" "$CODE_RUNENV"; then
                echo "  DRIFT[docker-run]: $f passes -e $var, which the entrypoint/server never read"
                FAIL=$((FAIL + 1))
            fi
        done < <(printf '%s' "$cmd" | grep -oE '\-e +[A-Z][A-Z0-9_]*' | grep -oE '[A-Z][A-Z0-9_]*$' | sort -u)
        # Per-mode required inputs.
        mode="$(printf '%s' "$cmd" | grep -oE '\-e +MODE=[A-Z]+' | head -1 | grep -oE '[A-Z]+$')"
        [ -z "$mode" ] && continue
        reqs="$(printf '%s\n' "$MODE_REQS" | grep "^${mode}::" | sed "s/^${mode}:://")"
        for req in $reqs; do
            if ! printf '%s' "$cmd" | grep -qF "$req"; then
                echo "  DRIFT[docker-run]: $f runs MODE=$mode without '$req' (the entrypoint requires it)"
                FAIL=$((FAIL + 1))
            fi
        done
    done < <(join_cont "$f" | grep -E 'docker run .*ghcr\.io/sktelecom/')
done
# The env-var table in docker-image.md documents variables by name; each row
# must exist in code too (catches renames that skip the examples).
for f in docs/reference/docker-image.md docs/reference/docker-image.ko.md; do
    [ -f "$f" ] || continue
    while IFS= read -r var; do
        [ -z "$var" ] && continue
        if ! in_list "$var" "$CODE_RUNENV"; then
            echo "  DRIFT[docker-run]: $f's env table documents '$var', not read by the entrypoint/server"
            FAIL=$((FAIL + 1))
        fi
    done < <(grep -oE '^\| `[A-Z][A-Z0-9_]*`' "$f" | grep -oE '[A-Z][A-Z0-9_]*' | sort -u)
done

# --- Check 10: en/ko runnable-block parity (hard) -----------------------------
# The docs walkthrough executes only the English pages; a Korean reader must be
# guaranteed the exact same verified commands. Comment lines may translate, so
# compare the extracted blocks with comments and blank lines stripped.
runnable_cmds() {
    awk '
        /^[[:space:]]*<!-- runnable -->[[:space:]]*$/ { armed = 1; next }
        armed { armed = 0; if ($0 ~ /^```bash[[:space:]]*$/) infence = 1; next }
        infence && /^```[[:space:]]*$/ { infence = 0; next }
        infence { print }
    ' "$1" | grep -vE '^[[:space:]]*(#|$)'
}
for f in "${DOCS[@]}"; do
    case "$f" in *.ko.md) continue ;; esac
    grep -q '<!-- runnable -->' "$f" 2>/dev/null || continue
    ko="${f%.md}.ko.md"
    [ -f "$ko" ] || continue
    if ! diff <(runnable_cmds "$f") <(runnable_cmds "$ko") >/dev/null 2>&1; then
        echo "  DRIFT[i18n-runnable]: $f and ${ko##*/} have different runnable command lines"
        diff <(runnable_cmds "$f") <(runnable_cmds "$ko") | sed 's/^/      /' | head -8
        FAIL=$((FAIL + 1))
    fi
done

# --- Check 11: repo-relative paths named in the docs must exist -------------
# A guide routinely names a real file or directory for the reader to open, run
# or diff against — a tree listing, a `path/to/file` in prose, a script the
# reader is told to run. Every other check above compares the docs against a
# *derived* fact (a flag, an env var, an image name); nothing anywhere checked
# whether a path the docs simply assert exists actually does. That's how
# docs/contribute/testing.md kept telling readers to run
# `tests/cases/test-java.sh` for years after the layout it described was never
# built (see docs/contribute/testing.md drift history).
#
# Scope mirrors scripts/ko-style/lint.mjs's SCOPE (the published doc surface):
# docs/** (English and .ko.md), README.md, CONTRIBUTING(.ko).md,
# SECURITY(.ko).md, CODE_OF_CONDUCT(.ko).md, SUPPORT.md, and the READMEs under
# examples/, docker/, electron/. CHANGELOG.md and THIRD_PARTY_LICENSES*.md are
# excluded, same as lint.mjs: a changelog entry or license inventory quotes
# history, it isn't a walkthrough anyone follows path-by-path. docker/lib/notices
# is a byte-identical vendored copy (tests/check-notice-sync.sh owns it).
PATHDOCS=()
while IFS= read -r f; do PATHDOCS+=("$f"); done \
    < <(find docs examples docker electron -name '*.md' \
        ! -path 'docker/lib/notices/*' ! -path '*/node_modules/*' 2>/dev/null | sort)
for f in README.md CONTRIBUTING.md CONTRIBUTING.ko.md SECURITY.md SECURITY.ko.md \
         CODE_OF_CONDUCT.md CODE_OF_CONDUCT.ko.md SUPPORT.md; do
    [ -f "$f" ] && PATHDOCS+=("$f")
done

# A token "looks like" a repo-relative path if, once a leading `./` is
# stripped, it starts with one of the repo's actual top-level directories (or
# `.github/`) followed by `/`. That single condition does almost all of the
# false-positive rejection for free, with no denylist needed: it excludes
# absolute *container* paths (`/proc`, `/usr/local/lib/sbom/...`), API routes
# (`GET /capabilities`, `/scan-stream`), git/HF model ids (`owner/name`), DOIs,
# scan-output directory names (`GoExample_1.0.0/`), URLs, and flag examples
# like `--target *.zip/*.tar.gz` or `MODE=IMAGE/BINARY/ROOTFS`.
TOPDIRS='tests|scripts|docker|electron|examples|docs|overrides|\.github'

# A directory this repo's own .gitignore says is scratch/build output (the
# test workspace, a `dist/`, `.gradle/`, ...) legitimately doesn't exist in a
# checked-out tree — the docs are describing where a *run* leaves it, not a
# path in the repo. Read once from .gitignore's own directory patterns
# (lines ending in `/`, skipping comments/blanks/negations `!...`) rather than
# shelling out to `git check-ignore` per candidate: that command reports a
# false "ignored" for any nonexistent path ending in `/` on this git build
# (tested: git 2.55.0.windows.3), which would blind the whole check to every
# missing-directory reference instead of just the gitignored ones.
GITIGNORE_DIRS="$(grep -vE '^[[:space:]]*(#|!|$)' .gitignore 2>/dev/null \
    | grep -E '/$' | sed 's#/$##')"
is_ignored_dir() {
    local p="${1%/}"
    while IFS= read -r pat; do
        [ -z "$pat" ] && continue
        case "$p" in
            "$pat" | "$pat"/*) return 0 ;;
        esac
    done <<<"$GITIGNORE_DIRS"
    return 1
}

# A sentence can name a path specifically to say it *doesn't* exist ("There is
# no `tests/cases/` directory.") — the exact idiom docs/contribute/testing.md
# now uses to correct the bug this check exists to catch. Suppress a hit when
# the doc line it came from reads as that kind of negation, in either
# language; this is intentionally narrow (whole phrases, not bare "no") so it
# doesn't blanket-suppress unrelated hits that happen to share a line with an
# unrelated "no".
NEG_RE='there is no|there are no|no such|does(n'"'"'t| not) exist|no longer exist|was removed|has been removed|were removed|없습니다|디렉터리는 없|더 이상 존재하지|삭제되었습니다|제거되었습니다'

# Pull path-shaped tokens out of a doc, split on whitespace: inline
# `single-backtick spans` (a span can hold a whole command line like
# `./scripts/scan-sbom.sh --ui`, so it's split into words) and the raw
# contents of fenced code blocks (a directory tree, a runnable snippet, a
# config sample) — both are "backtick-delimited" in the markdown sense, one
# vs. three backticks. Plain prose outside both is out of scope: this check
# guards instructions a reader copies or a listing they compare against, not
# a sentence that merely mentions a folder name.
doc_path_tokens() {
    awk '
        /^[[:space:]]*```/ { infence = !infence; next }
        infence { print NR":"$0; next }
        {
            line = $0
            while (match(line, /`[^`]+`/)) {
                print NR":" substr(line, RSTART + 1, RLENGTH - 2)
                line = substr(line, RSTART + RLENGTH)
            }
        }
    ' "$1"
}

for f in "${PATHDOCS[@]}"; do
    while IFS= read -r rec; do
        [ -z "$rec" ] && continue
        ln="${rec%%:*}"
        content="${rec#*:}"
        read -ra toks <<<"$content"
        for raw in "${toks[@]}"; do
            [ -z "$raw" ] && continue
            tok="${raw#./}"
            # A placeholder (`<lang>`, `{language}`) or a glob (`*.txt`)
            # illustrates a *pattern*, not a path anyone can open — skip it.
            case "$tok" in
                *'<'*'>'* | *'{'*'}'* | *'*'*) continue ;;
            esac
            [[ $tok =~ ^(${TOPDIRS})/ ]] || continue
            # Keep only the leading run of real path characters. None of
            # `#anchor`, `:line[-line]`, trailing punctuation from a
            # shell/JSON/table context, or a Korean particle glued straight
            # onto the path with no space (`tests/test-workspace/도`, a
            # common construction the docs use — none of ".,;:)]#" or a
            # Hangul syllable are ever legal in one of this repo's paths, so
            # this one rule drops all of them at once. Pure bash (no
            # grep/sed subshell per token): this loop runs over every
            # code-span token in the whole doc tree, and process spawns are
            # the dominant cost on Windows/Git Bash.
            if [[ $tok =~ ^([A-Za-z0-9._/-]+) ]]; then
                tok="${BASH_REMATCH[1]}"
            else
                continue
            fi
            [ -e "$tok" ] && continue
            is_ignored_dir "$tok" && continue
            docline="$(sed -n "${ln}p" "$f" 2>/dev/null)"
            printf '%s' "$docline" | grep -qiE "$NEG_RE" && continue
            echo "  DRIFT[path]: $f:$ln references '$tok', which does not exist in the repo"
            FAIL=$((FAIL + 1))
        done
    done < <(doc_path_tokens "$f")
done

# --- Check 12: en/ko heading-structure parity (warning) ---------------------
# A translated page that quietly drops, adds or reorders a whole section is
# invisible to every check above — none of them look at anything but code
# blocks and paths. This diffs just the heading *shape* (how many "#" each
# heading line opens with, in order) so translated wording never trips it,
# but a missing/extra/reordered/re-leveled section does. Code-fence content
# is skipped so a "#" shell comment inside an example never counts as a
# heading. A warning, not a hard failure: unlike a runnable command (Check
# 10), a translator restructuring for readability is a legitimate reason for
# the shape to differ, not necessarily drift.
heading_levels() {
    awk '
        /^```/ { infence = !infence; next }
        infence { next }
        /^#{1,6}[[:space:]]/ { match($0, /^#+/); print RLENGTH }
    ' "$1"
}
for f in "${DOCS[@]}"; do
    case "$f" in *.ko.md) continue ;; esac
    ko="${f%.md}.ko.md"
    [ -f "$ko" ] || continue
    if [ "$(heading_levels "$f")" != "$(heading_levels "$ko")" ]; then
        echo "  WARN[i18n-structure]: $f and ${ko##*/} have different heading structure"
        diff <(heading_levels "$f") <(heading_levels "$ko") | sed 's/^/      /' | head -8
        WARN=$((WARN + 1))
    fi
done

echo ""
[ "$WARN" -gt 0 ] && echo "${WARN} i18n warning(s) (non-fatal)"
if [ "$FAIL" -eq 0 ]; then
    echo "OK: docs reference no unknown scan-sbom.sh flags, SBOM_* vars, images or missing paths"
else
    echo "FAIL: ${FAIL} doc/tool drift(s) — fix the doc or the code so they agree"
    exit 1
fi
