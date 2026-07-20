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
#   - a CycloneDX/specVersion literal that disagrees with the code's constants
#     (1.6 from convert-to-cdx.sh; the ML-BOM 1.7 variant from scan-aibom.sh)
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
# Maintainer notes under docs/maintainers/ are excluded — they are not user-followed.
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
    scripts/scan-sbom.sh scripts/sbom-ui.bat scripts/check-setup.bat \
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
    < <(find docs -name '*.md' -not -path 'docs/maintainers/*' | sort)
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
    done < <(grep -rhoE '[A-Za-z0-9][A-Za-z0-9._*-]*\.(exe|dmg)' "${DOCS[@]}" 2>/dev/null | sort -u)
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
# convert-to-cdx.sh writes the SBOM specVersion; scan-aibom.sh keeps the
# generator's _1_7.json variant for the ML-BOM.
SPEC="$(grep -oE 'specVersion: "[0-9.]+"' docker/lib/convert-to-cdx.sh | head -1 | grep -oE '[0-9]+\.[0-9]+')"
MLSPEC="$(grep -oE '_[0-9]_[0-9]\.json' docker/lib/scan-aibom.sh | head -1 | grep -oE '[0-9]_[0-9]' | tr '_' '.')"
if [ -z "$SPEC" ] || [ -z "$MLSPEC" ]; then
    echo "  DRIFT[spec]: cannot extract spec versions from code (convert-to-cdx.sh / scan-aibom.sh changed shape?)"
    FAIL=$((FAIL + 1))
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

echo ""
[ "$WARN" -gt 0 ] && echo "${WARN} i18n warning(s) (non-fatal)"
if [ "$FAIL" -eq 0 ]; then
    echo "OK: docs reference no unknown scan-sbom.sh flags, SBOM_* vars or images"
else
    echo "FAIL: ${FAIL} doc/tool drift(s) — fix the doc or the code so they agree"
    exit 1
fi
