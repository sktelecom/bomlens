#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# See the License for the specific language governing permissions and
# limitations under the License.
#
# check-doc-drift.sh — guard the onboarding-critical facts that live in code but
# are repeated in the docs, so a first-time user never follows a stale command.
#
# Sibling to check-doc-coverage.sh (which guards scan-mode coverage). Each check
# reads an authoritative source and asserts the docs still match it:
#   1. CLI flags  : scan-sbom.sh --help  ->  docs/reference/cli.md
#   2. Image tag  : scan-sbom.sh canonical image  ->  docs + .bat wrappers
#   3. Download   : electron-builder artifactName ->  download URLs in the docs
#   4. Output dir : sbom-ui.bat OUTDIR            ->  docs/start/no-cli.md
#
# Change the code and forget the doc, and this fails CI.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
fail=0

note_fail() { echo "  ❌ $1"; fail=1; }
note_ok()   { echo "  ✓ $1"; }

# ----------------------------------------------------------------------------
# 1) CLI flags: every long option in `scan-sbom.sh --help` must be documented
#    in docs/reference/cli.md. --help is parsed before any docker check, so this
#    runs without a daemon.
# ----------------------------------------------------------------------------
echo "1) CLI flags (scan-sbom.sh --help ↔ docs/reference/cli.md)"
CLI_DOC="docs/reference/cli.md"
[ -f "$CLI_DOC" ] || { echo "ERROR: $CLI_DOC not found"; exit 2; }

help_text="$(bash scripts/scan-sbom.sh --help 2>/dev/null || true)"
[ -n "$help_text" ] || { echo "ERROR: could not read scan-sbom.sh --help"; exit 2; }

# Authoritative flags = long options listed in the help body.
help_flags="$(printf '%s\n' "$help_text" | grep -oE -- '--[a-z][a-z-]+' | sort -u)"
doc_flags="$(grep -oE -- '--[a-z][a-z-]+' "$CLI_DOC" | sort -u)"

missing_flags=""
while IFS= read -r flag; do
  [ -n "$flag" ] || continue
  if ! printf '%s\n' "$doc_flags" | grep -qx -- "$flag"; then
    missing_flags="$missing_flags $flag"
  fi
done <<EOF
$help_flags
EOF

if [ -n "$missing_flags" ]; then
  note_fail "flags in --help but missing from $CLI_DOC:$missing_flags"
else
  note_ok "all --help flags documented in $CLI_DOC"
fi

# ----------------------------------------------------------------------------
# 2) Scanner image tag: the canonical registry path in scan-sbom.sh must be the
#    one the docs and the Windows wrappers tell users to pull.
# ----------------------------------------------------------------------------
echo "2) Scanner image (scan-sbom.sh ↔ docs + .bat)"
canonical_repo="$(grep -oE 'ghcr\.io/sktelecom/bomlens(:[a-z0-9.]+)?' scripts/scan-sbom.sh | head -1 | sed 's/:.*//')"
[ -n "$canonical_repo" ] || { echo "ERROR: could not read canonical image from scan-sbom.sh"; exit 2; }

for f in README.md docs/reference/cli.md scripts/sbom-ui.bat scripts/check-setup.bat; do
  [ -f "$f" ] || continue
  if grep -q "$canonical_repo" "$f"; then
    note_ok "$f references $canonical_repo"
  else
    note_fail "$f does not reference the canonical image $canonical_repo"
  fi
done

# ----------------------------------------------------------------------------
# 3) Desktop download: electron-builder pins a versionless artifact name, which
#    is what makes the permanent releases/latest/download URL work. A doc that
#    links a renamed/stale installer breaks the one-click download, so:
#      3a) every direct download URL must use the canonical base name, and
#      3b) no user-facing onboarding doc may reference an installer under a
#          different product name (e.g. a pre-rename SBOM-Generator-*.exe).
# ----------------------------------------------------------------------------
echo "3) Desktop download name (electron-builder.yml ↔ onboarding docs)"
# shellcheck disable=SC2016  # the ${ext} in the grep pattern is a literal, not a shell var
art="$(grep -oE 'artifactName:[[:space:]]*[A-Za-z0-9.${}-]+' electron/electron-builder.yml | head -1 | awk '{print $2}')"
# artifactName: BomLens-Setup.${ext}  ->  canonical base name "BomLens-Setup"
base="${art%%.\$\{ext\}}"
if [ -z "$base" ] || [ "$base" = "$art" ]; then
  echo "ERROR: could not parse artifactName from electron/electron-builder.yml (got '$art')"; exit 2
fi

# User-facing onboarding pages (internal/build notes are exempt).
ONBOARDING_DOCS=(README.md docs/index.md docs/index.ko.md \
  docs/start/first-scan.md docs/start/first-scan.ko.md \
  docs/start/no-cli.md docs/start/no-cli.ko.md)
present_docs=()
for d in "${ONBOARDING_DOCS[@]}"; do [ -f "$d" ] && present_docs+=("$d"); done

# 3a) direct download links must point at the canonical base name.
bad_links="$(grep -rhoE 'releases/latest/download/[A-Za-z0-9._-]+' "${present_docs[@]}" 2>/dev/null \
  | sed 's#.*/##' | sed -E 's/\.(exe|dmg|AppImage)$//' | sort -u | grep -vx "$base" || true)"
if [ -n "$bad_links" ]; then
  note_fail "download URL(s) not using canonical base '$base': $(echo "$bad_links" | tr '\n' ' ')"
else
  note_ok "all direct download URLs use the canonical base '$base'"
fi

# 3b) no installer filename under a different product name.
bad_names="$(grep -rhoE '[A-Za-z0-9][A-Za-z0-9._*-]*\.(exe|dmg)' "${present_docs[@]}" 2>/dev/null \
  | sed -E 's/\.(exe|dmg)$//' | sed -E 's/-\*$//' | sort -u | grep -vx "$base" || true)"
if [ -n "$bad_names" ]; then
  note_fail "non-canonical installer name(s) in onboarding docs (canonical is '$base'): $(echo "$bad_names" | tr '\n' ' ')"
else
  note_ok "no stale installer names in onboarding docs"
fi

# ----------------------------------------------------------------------------
# 4) Windows output dir: sbom-ui.bat writes results to a fixed folder; no-cli.md
#    tells the user where to look. They must agree.
# ----------------------------------------------------------------------------
echo "4) Windows output folder (sbom-ui.bat ↔ docs/start/no-cli.md)"
outdir_leaf="$(grep -oE 'OUTDIR=%USERPROFILE%\\[A-Za-z0-9_-]+' scripts/sbom-ui.bat | head -1 | sed 's#.*\\##')"
if [ -z "$outdir_leaf" ]; then
  note_fail "could not read OUTDIR from scripts/sbom-ui.bat"
elif grep -q "$outdir_leaf" docs/start/no-cli.md; then
  note_ok "no-cli.md mentions the output folder '$outdir_leaf'"
else
  note_fail "docs/start/no-cli.md does not mention the output folder '$outdir_leaf'"
fi

echo ""
if [ "$fail" -ne 0 ]; then
  echo "❌ doc drift detected — update the doc to match the code (or vice versa)."
  exit 1
fi
echo "✅ docs are in sync with the code (flags, image tag, download name, output dir)."
