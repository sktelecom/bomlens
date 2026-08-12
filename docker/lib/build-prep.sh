#!/bin/sh
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# build-prep.sh — run INSIDE a cdxgen image (mounted from host): augment the
# build so transitive deps surface, then invoke cdxgen.
#
#   Usage: sh build-prep.sh <SRC_DIR> <OUTPUT_FILE> [SPEC_VERSION]
#
# Why: cdxgen does not auto-resolve transitive deps for some ecosystems
# (notably Rust, Go). Generating the lockfile / downloading modules first lets
# cdxgen surface the full dependency graph. cdxgen's binary path differs between
# images (all-in-one /opt/bin/cdxgen vs language images /opt/cdxgen/bin/cdxgen.js),
# so we auto-detect it here.
#
# POSIX sh (cdxgen images ship /bin/sh). Best-effort: never fail on prep.
set +e

SRC="${1:-/app}"
OUT="${2:-$SRC/bom.json}"
SPEC="${3:-1.6}"
# Ensure HOME exists & is writable (maven/cargo/etc. caches) for any base user.
mkdir -p "${HOME:-/tmp/sbomhome}" 2>/dev/null || true
cd "$SRC" 2>/dev/null || exit 0

log() { echo "[build-prep] $*"; }

# ---------------------------------------------------------------------------
# Source-tree guard — hand the scanned project back exactly as we found it.
#
# The resolve steps below run IN the mounted source tree, because the build
# tools need the real sources: `go mod tidy` rewrites go.mod and creates go.sum,
# `cargo generate-lockfile` writes Cargo.lock, `bundle lock` writes Gemfile.lock,
# `swift package resolve` writes Package.resolved, and gradle/maven leave their
# build directories behind. Scanning a checkout therefore left the user's
# working tree dirty (go.mod gained ~30 lines of indirect requires, go.sum
# appeared). A scan must not change what it measures, and in CI the diff the
# scan itself created is worse still.
#
# So we snapshot the resolver-owned files before the run and put the tree back
# afterwards: snapshotted files are restored byte for byte, and files or build
# directories that were NOT there before are removed. Nothing outside these
# names is considered, and nothing that already existed is deleted, so a
# committed lockfile or a pre-existing build/ is never lost.
# BOMLENS_KEEP_BUILD_OUTPUT=1 opts out (leave the resolved tree in place, e.g.
# to inspect what a resolution produced).
# ---------------------------------------------------------------------------
GUARD_DIR=""

# Resolver-owned paths, relative to $SRC. maxdepth 4 covers multi-module trees
# (app/build, services/api/go.mod) without walking a whole monorepo; .git and
# node_modules are pruned because nothing we run resolves inside them.
guard_paths() {
    if [ "$1" = "f" ]; then
        find . -maxdepth 4 \( -name .git -o -name node_modules \) -prune -o -type f \
            \( -name go.mod -o -name go.sum -o -name Cargo.lock -o -name Gemfile.lock \
               -o -name Package.resolved -o -name package-lock.json \
               -o -name composer.lock \) -print 2>/dev/null | LC_ALL=C sort
    else
        find . -maxdepth 4 -name .git -prune -o -type d \
            \( -name .gradle -o -name .build -o -name build -o -name target \
               -o -name node_modules -o -name __pycache__ -o -name .venv \) \
            -print -prune 2>/dev/null | LC_ALL=C sort
    fi
}

guard_snapshot() {
    [ -z "${BOMLENS_KEEP_BUILD_OUTPUT:-}" ] || { log "source-tree guard off (BOMLENS_KEEP_BUILD_OUTPUT)"; return 0; }
    GUARD_DIR=$(mktemp -d 2>/dev/null) || { GUARD_DIR=""; return 0; }
    guard_paths f > "$GUARD_DIR/files.before" 2>/dev/null
    guard_paths d > "$GUARD_DIR/dirs.before" 2>/dev/null
    while IFS= read -r _f; do
        [ -n "$_f" ] || continue
        mkdir -p "$GUARD_DIR/tree/$(dirname "$_f")" 2>/dev/null
        cp -p "$_f" "$GUARD_DIR/tree/$_f" 2>/dev/null
    done < "$GUARD_DIR/files.before"
}

# Idempotent: clears GUARD_DIR first, so the explicit call and the trap that
# covers an abort (docker stop, cdxgen crash) cannot both run the restore.
guard_restore() {
    [ -n "$GUARD_DIR" ] || return 0
    _g="$GUARD_DIR"; GUARD_DIR=""
    cd "$SRC" 2>/dev/null || { rm -rf "$_g"; return 0; }
    _rst=0; _del=0
    while IFS= read -r _f; do
        [ -n "$_f" ] || continue
        [ -f "$_g/tree/$_f" ] || continue
        # Untouched file: leave it alone (keeps the log honest and the mtime
        # stable). Without cmp we simply copy back — same result, noisier count.
        if command -v cmp >/dev/null 2>&1 && cmp -s "$_g/tree/$_f" "$_f" 2>/dev/null; then
            continue
        fi
        cp -p "$_g/tree/$_f" "$_f" 2>/dev/null && _rst=$((_rst + 1))
    done < "$_g/files.before"
    guard_paths f > "$_g/files.after" 2>/dev/null
    while IFS= read -r _f; do
        [ -n "$_f" ] || continue
        # Never the SBOM itself: the web-UI path asks cdxgen to write it inside
        # the tree when the run folder is not on a shared mount.
        [ "$SRC/${_f#./}" = "$OUT" ] && continue
        grep -qxF "$_f" "$_g/files.before" 2>/dev/null && continue
        rm -f "$_f" 2>/dev/null && _del=$((_del + 1))
    done < "$_g/files.after"
    guard_paths d > "$_g/dirs.after" 2>/dev/null
    while IFS= read -r _d; do
        [ -n "$_d" ] || continue
        [ -d "$_d" ] || continue
        grep -qxF "$_d" "$_g/dirs.before" 2>/dev/null && continue
        rm -rf "$_d" 2>/dev/null && _del=$((_del + 1))
        # Drop the parents the run created on the way (gradle's app/build leaves
        # an empty app/ behind when the module dir itself is new). rmdir refuses
        # a non-empty directory, so a real module dir survives; the tree root (.)
        # is never a candidate.
        _p=$(dirname "$_d")
        [ "$_p" != "." ] && rmdir -p "$_p" 2>/dev/null
    done < "$_g/dirs.after"
    [ "$_rst" -gt 0 ] || [ "$_del" -gt 0 ] \
        && log "source tree restored ($_rst file(s) put back, $_del build artifact(s) removed)"
    rm -rf "$_g"
    return 0
}

guard_snapshot
trap 'guard_restore' EXIT
trap 'guard_restore; exit 130' INT
trap 'guard_restore; exit 143' TERM

# Rust — cdxgen does NOT auto-run cargo; lockfile is essential for transitive deps
if [ -f Cargo.toml ] && command -v cargo >/dev/null 2>&1; then
    log "cargo generate-lockfile"
    cargo generate-lockfile 2>/dev/null
fi

# Go — complete go.sum so cdxgen's default-readonly `go list -deps` resolves the
# full transitive graph. Plain `go mod download` leaves go.sum missing entries
# that readonly `go list` requires (it then fails and cdxgen falls back to parsing
# go.mod = direct deps only). `go mod tidy` populates go.sum fully; fall back to
# download if tidy can't run (e.g. no network to fix an inconsistent go.mod).
if [ -f go.mod ] && command -v go >/dev/null 2>&1; then
    log "go mod tidy"
    GOFLAGS="-mod=mod" go mod tidy 2>/dev/null || GOFLAGS="-mod=mod" go mod download 2>/dev/null
fi

# Ruby — ensure a lockfile exists (cdxgen ruby images usually auto-resolve,
# but a Gemfile.lock makes it deterministic)
if [ -f Gemfile ] && [ ! -f Gemfile.lock ] && command -v bundle >/dev/null 2>&1; then
    log "bundle lock"
    bundle lock 2>/dev/null || bundle install 2>/dev/null
fi

# Maven — no pre-resolve step. cdxgen invokes maven itself (dependency:tree /
# the cyclonedx plugin) to build the full transitive graph, so a separate
# `mvn dependency:resolve` here is redundant. It also failed noisily: the run is
# pinned to -Dmaven.repo.local=/tmp/sbomhome/.m2 (an empty repo), so maven could
# not resolve the dependency-plugin prefix and printed a NoPluginFoundForPrefix
# error to stdout on every Java scan. Dropping it removes that noise with no
# effect on the SBOM — cdxgen alone already resolves transitive deps (verified:
# the same scan yields 91 components with this step gone).
#
# Maven scope over-scan: cdxgen keeps EVERY resolved node, so a deployed app's
# SBOM also carries its test/provided toolchain (junit, lombok, ...) as if it
# shipped them. This is the Maven analogue of the Android/npm over-scan. cdxgen
# already tags each node with its resolved scope (compile/runtime -> "required",
# test -> "optional", provided/system -> "excluded"), so we post-filter the BOM
# to the deployable set using those tags near the end of this script — no second
# maven run needed (that would hit the empty-repo NoPluginFoundForPrefix above).
# Caveat: cdxgen maps both test scope and <optional>true</optional> to "optional",
# so a rare optional=true runtime dep is dropped too; BOMLENS_MAVEN_FULL_GRAPH=1
# opts out (keep the full graph, unchanged behavior).
MAVEN_SCOPE_FILTER=""
if [ -f pom.xml ] && [ -z "${BOMLENS_MAVEN_FULL_GRAPH:-}" ]; then
    MAVEN_SCOPE_FILTER=1
fi

# Gradle (java-gradle / Android) — resolve so cdxgen sees the full graph.
# For Android, ANDROID_HOME is set in the android-sdk image, enabling AGP.
#
# ANDROID_RELEASE_SET, when set below, points at a file of "group:artifact:version"
# lines (the deployable release runtime classpath). The post-cdxgen step near the
# end of this script filters the generated SBOM down to that set.
ANDROID_RELEASE_SET=""
if { [ -f build.gradle ] || [ -f build.gradle.kts ]; } && command -v gradle >/dev/null 2>&1; then
    if [ -x ./gradlew ]; then GRADLEW="./gradlew"; else GRADLEW="gradle"; fi

    # Android scope fix: cdxgen resolves EVERY Gradle configuration, so an AGP
    # project drags its build/test toolchain (androidTestUtil, Unified Test
    # Platform, lint, ddmlib, grpc/netty) into the SBOM as if it shipped in the
    # APK — and it also emits pre-resolution duplicate versions. Precision
    # collapses (~0.25 on a 3-dep app). We cannot fix this by passing
    # `--configuration <x>` to cdxgen: cdxgen runs the ROOT project's bare
    # `dependencies` task too, which has no release configuration, so a global
    # --configuration fails the whole build. Instead we resolve the deployable
    # release runtime classpath OURSELVES and post-filter cdxgen's full BOM to it.
    #
    # We DETECT the configuration name instead of hardcoding
    # "releaseRuntimeClasspath": build flavors rename it (e.g.
    # prodReleaseRuntimeClasspath). If nothing is found we leave the filter off
    # (full graph, unchanged behavior) so recall never regresses.
    # BOMLENS_ANDROID_FULL_GRAPH=1 opts out entirely (keep the build+test superset).
    if [ -n "${ANDROID_HOME:-}" ] && [ -z "${BOMLENS_ANDROID_FULL_GRAPH:-}" ]; then
        log "android: resolving deployable release runtime classpath"
        _relset=$(mktemp)
        _subs=$("$GRADLEW" --no-daemon -q --console=plain projects 2>/dev/null \
                | sed -n "s/.*Project '\(:[A-Za-z0-9:._-]*\)'.*/\1/p")
        # Include the root ("") as a fallback for single-module projects.
        for _s in $_subs ""; do
            _dep=$("$GRADLEW" --no-daemon -q --console=plain "${_s}:dependencies" 2>/dev/null)
            [ -n "$_dep" ] || continue
            # Pick the deployable release runtime config for this module: prefer the
            # plain releaseRuntimeClasspath, else the first flavored release variant
            # (alphabetical, e.g. freeReleaseRuntimeClasspath). Capture the candidates
            # first — piping straight into `{ grep -x … || cat; }` silently drops
            # everything when there is no exact match: grep drains stdin before it
            # exits non-zero, so `cat` then reads an already-empty pipe and the filter
            # falls back to the full build+test graph on flavored projects (reported
            # by the SCA benchmark team). Selecting from a saved variable avoids that.
            _cands=$(printf '%s\n' "$_dep" \
                     | sed -n 's/^\([A-Za-z][A-Za-z0-9]*RuntimeClasspath\) .*/\1/p' \
                     | grep -i release | grep -viE 'test|debug|lint' | sort -u)
            _cfg=$(printf '%s\n' "$_cands" | grep -x releaseRuntimeClasspath \
                   || printf '%s\n' "$_cands" | head -1)
            [ -n "$_cfg" ] || continue
            log "android: ${_s:-:} -> --configuration $_cfg"
            # Extract that config's subtree as resolved group:artifact:version.
            # Take the version after "->" when Gradle upgraded/downgraded it; skip
            # (c) constraints and (n) not-resolved markers.
            printf '%s\n' "$_dep" | awk -v cfg="$_cfg" '
                $0 ~ ("^" cfg " ") { insec=1; next }
                insec && /^[[:space:]]*$/ { insec=0 }
                insec {
                    line=$0
                    if (!match(line, /[+\\]--- /)) next
                    sub(/^.*[+\\]--- /, "", line)
                    if (line ~ /\(c\)|\(n\)/) next
                    resolved=""
                    if (match(line, /-> [^ ]+/)) resolved=substr(line, RSTART+3, RLENGTH-3)
                    split(line, a, " "); split(a[1], ga, ":")
                    g=ga[1]; art=ga[2]; ver=ga[3]; if (resolved!="") ver=resolved
                    gsub(/[()*]/, "", ver)
                    if (g!="" && art!="" && ver!="") print g":"art":"ver
                }' >> "$_relset"
        done
        if [ -s "$_relset" ]; then
            sort -u "$_relset" -o "$_relset"
            ANDROID_RELEASE_SET="$_relset"
            log "android: release runtime set = $(wc -l < "$_relset") components"
        else
            log "android: no release runtime configuration found; using full graph"
            rm -f "$_relset"
        fi
    else
        # java-gradle (or opted-out Android): resolve so cdxgen sees the full graph.
        log "gradle dependencies"
        "$GRADLEW" --no-daemon dependencies >/dev/null 2>&1 || true
    fi
fi

# Python — install into a venv so transitive deps are visible (requirements.txt
# without a lockfile)
if [ -f requirements.txt ] && command -v pip3 >/dev/null 2>&1; then
    log "pip install requirements"
    pip3 install -q -r requirements.txt 2>/dev/null \
      || pip3 install -q --break-system-packages -r requirements.txt 2>/dev/null
fi

# Swift / SPM — cdxgen reads Package.resolved for the resolved graph, and parses it
# offline (verified: both the v1 `object.pins` and v2 top-level `pins` formats). Only run
# `swift package resolve` when NO Package.resolved is committed: a committed lockfile is
# already the resolved truth, and re-resolving reaches the network, where a partial fetch
# leaves versions "unspecified" and drags in unrelated tooling. CocoaPods (Podfile.lock)
# needs no prep here — it is filled from the lockfile by syft in post-processing. NOTE:
# UIKit/Xcode-driven resolution needs macOS; on Linux only non-platform Swift deps resolve.
if [ -f Package.swift ] && command -v swift >/dev/null 2>&1; then
    if find . -name Package.resolved -type f 2>/dev/null | grep -q .; then
        log "swift: committed Package.resolved present; skipping network resolve"
    else
        log "swift package resolve (no committed Package.resolved)"
        swift package resolve >/dev/null 2>&1 || true
    fi
fi

# Node (npm) — cdxgen reads package.json's devDependencies and pulls the whole dev
# tree (jest/eslint/babel/prettier…) into the SBOM as if a deployed app shipped its
# build/test tooling. It is the npm analogue of the Android over-scan and inflates a
# 10-dependency app to ~470 components. cdxgen has no reliable prod-only mode here:
# --required-only drops the transitive graph (only ~8 direct deps survive). So we
# resolve the production dependency set OURSELVES — a lockfile-only npm resolve in a
# scratch copy (metadata only, no tarball downloads, source tree untouched) — and
# post-filter cdxgen's BOM to it near the end, mirroring the Android release-scope
# filter. BOMLENS_NODE_FULL_GRAPH=1 opts out (keep the dev+prod superset).
NODE_PROD_SET=""
if [ -f package.json ] && [ -z "${BOMLENS_NODE_FULL_GRAPH:-}" ] \
   && command -v npm >/dev/null 2>&1 && command -v node >/dev/null 2>&1; then
    log "node: resolving production dependency set"
    _npmtmp=$(mktemp -d)
    cp package.json "$_npmtmp/" 2>/dev/null
    # Copy a committed lockfile too so the prod resolve pins the same versions cdxgen sees.
    [ -f package-lock.json ] && cp package-lock.json "$_npmtmp/" 2>/dev/null
    _nodeset=$(mktemp)
    if ( cd "$_npmtmp" && npm install --omit=dev --package-lock-only --no-audit --no-fund --ignore-scripts >/dev/null 2>&1 ) \
       && [ -f "$_npmtmp/package-lock.json" ]; then
        # Emit name@version for every non-dev node_modules entry in the resolved lockfile.
        node -e '
          const fs=require("fs");
          let lock; try { lock=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); } catch(e){ process.exit(0); }
          const pkgs=lock.packages||{}, out=[];
          for (const [k,v] of Object.entries(pkgs)) {
            if (!k.startsWith("node_modules/")) continue;
            if (v.dev===true || !v.version) continue;
            out.push(k.replace(/^.*node_modules\//,"")+"@"+v.version);
          }
          process.stdout.write([...new Set(out)].join("\n"));
        ' "$_npmtmp/package-lock.json" > "$_nodeset" 2>/dev/null
    fi
    if [ -s "$_nodeset" ]; then
        NODE_PROD_SET="$_nodeset"
        log "node: production set = $(wc -l < "$_nodeset") components"
    else
        log "node: could not resolve production set; using full graph"
        rm -f "$_nodeset"
    fi
    rm -rf "$_npmtmp"
fi

# --- build the cdxgen argument list (shared across the per-image binary paths) ---
# Do NOT pass --project-name/--project-version. For npm cdxgen keeps the root purl
# (pkg:npm/<name>@<ver>) and rewires the dependency graph onto it, but for Maven and
# Gradle the override re-roots metadata.component to a generic pkg:application/<name>
# ref while the resolved-GAV root edges stay on the old pkg:maven/... ref. The new
# application root then carries an empty dependsOn, so every direct dependency is
# orphaned from the root and consumers reading the graph see them all as transitive.
# We don't need the flags for identity anyway: stamp-metadata.sh overwrites the root
# name/version post-hoc (and covers the syft fallback path), so dropping them lets
# cdxgen keep its ecosystem-correct, fully-linked root graph.
set -- -r --spec-version "$SPEC" -o "$OUT"
# CocoaPods: cdxgen's cataloger shells out to the `pod` CLI, which the swift image does
# not bundle. With a Podfile present it does not just skip — it throws
# (TypeError on an undefined `pod` stdout) and aborts the whole scan. Exclude the type so
# cdxgen resolves SPM only; BomLens fills CocoaPods from Podfile.lock via syft in
# post-processing (identify-cocoapods.sh).
if find . -name Podfile -type f 2>/dev/null | grep -q .; then
    set -- "$@" --exclude-type cocoapods
fi
set -- "$@" "$SRC"

# --- correct the BSD license-name aliases cdxgen resolves against ---
# cdxgen turns a license NAME into an SPDX id through two data files, and up to
# cdxgen 12.8.2 both handed the generic BSD names to 0BSD: data/lic-mapping.json
# listed "BSD", "BSD License", "BSD-like", "new BSD" and "new BSD License" under
# its 0BSD entry, and data/license-aliases.json repeated them as lookup keys
# ("bsd", "bsdlicense", "bsdlike", "newbsd", "bsdpublicdomain"). PyPI files every
# BSD variant under the single classifier "License :: OSI Approved :: BSD
# License" and Maven poms carry names like "New BSD License", so BSD-3-Clause
# components came out as 0BSD — a license with no conditions at all, standing in
# for one that requires the copyright notice and the license text to be shipped.
# A notice built from that is missing an obligation the component carries.
#
# Both files are read from disk when cdxgen runs, so correcting them first covers
# every ecosystem that resolves a license by name. It is also the only place the
# correction can be made: once the SBOM is written the name is gone and only the
# id 0BSD remains, which post-processing cannot tell apart from a component that
# really is 0BSD (tslib, liblzma). That is why normalize-sbom.sh still leaves a
# valid upstream id alone.
#
# "new BSD" moves to BSD-3-Clause, which is what the name means, in the exact
# spelling each file matches on. "BSD", "BSD License" and "BSD-like" are dropped
# without a new home: the clause count cannot be known from those strings, and
# asserting one is the mistake being corrected here. An unmatched name passes
# through as free text, so it reaches the SBOM as a license name rather than as a
# wrong id, and generate-notice.sh marks it as unverified.
#
# Best-effort and idempotent: a missing, read-only or already-corrected file is a
# no-op. cdxgen 12.8.3 ships the same correction, and running this against those
# tables leaves both files byte-identical, so it stays in place for the images
# that are still pinned to an earlier release (CDXGEN_ALLINONE in
# source-detect.sh) and for a caller that points CDXGEN_TAG at one.
fix_lic_mapping() {
    command -v node >/dev/null 2>&1 || return 0
    _lic_dir=""
    for _c in /opt/cdxgen/data /opt/bin/data \
              /usr/local/lib/node_modules/@cyclonedx/cdxgen/data; do
        [ -f "$_c/lic-mapping.json" ] && { _lic_dir="$_c"; break; }
    done
    if [ -z "$_lic_dir" ]; then
        _f=$(find /opt /usr/local/lib -maxdepth 8 -name lic-mapping.json -type f 2>/dev/null | head -1)
        [ -n "$_f" ] && _lic_dir=$(dirname "$_f")
    fi
    if [ -z "$_lic_dir" ]; then
        log "lic-mapping: not found in image; BSD names left as shipped"
        return 0
    fi
    # The images ship these read-only (444); we run as root, so take write
    # permission explicitly rather than relying on root overriding the mode.
    chmod u+w "$_lic_dir/lic-mapping.json" "$_lic_dir/license-aliases.json" 2>/dev/null
    _fix="$(mktemp).js"
    cat > "$_fix" <<'FIX_LIC_JS'
const fs = require("fs");
const dir = process.argv[2];
const dropped = [];

const read = f => {
  try { return JSON.parse(fs.readFileSync(dir + "/" + f, "utf8")); } catch (e) { return null; }
};
const write = (f, data) => fs.writeFileSync(dir + "/" + f, JSON.stringify(data, null, 2));
const isNewBsd = s => /^new[^a-z0-9]*bsd([^a-z0-9]*license)?$/i.test(s);

// lic-mapping.json: [{ exp: "0BSD", names: [...] }, ...]
const map = read("lic-mapping.json");
if (Array.isArray(map)) {
  const entry = exp => map.find(e => e && e.exp === exp && Array.isArray(e.names));
  const zero = entry("0BSD");
  const three = entry("BSD-3-Clause");
  if (zero) {
    const isZeroClause = n => /zero[\s-]*clause/i.test(n) || /^0BSD$/i.test(n);
    const gone = zero.names.filter(n => !isZeroClause(n));
    if (gone.length) {
      zero.names = zero.names.filter(isZeroClause);
      // cdxgen matches these names case-sensitively, so keep the exact spelling.
      if (three) {
        for (const n of gone) {
          if (isNewBsd(n) && !three.names.includes(n)) three.names.push(n);
        }
      }
      write("lic-mapping.json", map);
      dropped.push(...gone);
    }
  }
}

// license-aliases.json: { "<normalised name>": "<SPDX id>" }. Keys are lowercase
// and stripped of punctuation, so "BSD License" is looked up as "bsdlicense".
const aliases = read("license-aliases.json");
if (aliases && typeof aliases === "object" && !Array.isArray(aliases)) {
  const isZeroClause = k => /zeroclause/.test(k) || k === "0bsd" || k === "bsdzero";
  let touched = false;
  for (const [key, value] of Object.entries(aliases)) {
    if (value !== "0BSD" || isZeroClause(key)) continue;
    if (isNewBsd(key)) aliases[key] = "BSD-3-Clause";
    else delete aliases[key];
    dropped.push(key);
    touched = true;
  }
  if (touched) write("license-aliases.json", aliases);
}

if (!dropped.length) process.exit(0);            // already corrected upstream
process.stderr.write("[build-prep] lic-mapping: 0BSD no longer claims " +
  [...new Set(dropped)].map(d => JSON.stringify(d)).join(", ") + "\n");
FIX_LIC_JS
    node "$_fix" "$_lic_dir" || log "lic-mapping: correction skipped (non-fatal)"
    rm -f "$_fix"
}
fix_lic_mapping

# --- locate cdxgen (path differs per image) and generate the SBOM ---
if command -v cdxgen >/dev/null 2>&1; then
    log "cdxgen (PATH)"
    cdxgen "$@"
    rc=$?
elif [ -f /opt/cdxgen/bin/cdxgen.js ]; then
    log "cdxgen (/opt/cdxgen/bin/cdxgen.js)"
    node /opt/cdxgen/bin/cdxgen.js "$@"
    rc=$?
elif [ -f /opt/bin/cdxgen ]; then
    log "cdxgen (/opt/bin/cdxgen)"
    /opt/bin/cdxgen "$@"
    rc=$?
else
    echo "[build-prep] ERROR: cdxgen not found in image" >&2
    exit 1
fi

# Android release-scope filter: keep only components in the deployable release
# runtime classpath resolved earlier; drop the build/test toolchain and the
# pre-resolution duplicate versions cdxgen emits from the other configurations.
# Match on maven group:artifact:version; keep non-maven components and the app's
# own modules (root project group). Prune the dependency graph to the kept refs.
if [ "${rc:-1}" -eq 0 ] && [ -n "${ANDROID_RELEASE_SET:-}" ] && [ -s "$ANDROID_RELEASE_SET" ] \
   && [ -f "$OUT" ] && command -v node >/dev/null 2>&1; then
    log "android: filtering SBOM to release runtime scope"
    _flt=$(mktemp).js
    cat > "$_flt" <<'FILTER_JS'
const fs = require('fs');
const [bomPath, relPath] = process.argv.slice(2);
let bom;
try { bom = JSON.parse(fs.readFileSync(bomPath, 'utf8')); } catch (e) { process.exit(0); }
const rel = new Set(fs.readFileSync(relPath, 'utf8').split('\n').filter(Boolean));
if (!rel.size || !Array.isArray(bom.components)) process.exit(0);
const gav = p => {
  const m = /^pkg:maven\/([^/]+)\/([^@?]+)@([^?]+)/.exec(p || '');
  return m ? m[1] + ':' + m[2] + ':' + decodeURIComponent(m[3]) : null;
};
const mc = bom.metadata && bom.metadata.component;
const rootGroup = (/^pkg:maven\/([^/@?]+)/.exec((mc && mc.purl) || '') || [])[1];
const keep = c => {
  const p = c.purl || '';
  if (!p.startsWith('pkg:maven/')) return true;   // non-maven: leave alone
  const g = gav(p);
  if (!g) return true;                            // app root (single segment)
  if (rootGroup && g.split(':')[0] === rootGroup) return true; // first-party modules
  return rel.has(g);
};
const before = bom.components.length;
bom.components = bom.components.filter(keep);
const refOf = c => c['bom-ref'] || c.purl;
const keptRefs = new Set(bom.components.map(refOf));
if (mc) keptRefs.add(mc['bom-ref'] || mc.purl);
if (Array.isArray(bom.dependencies)) {
  bom.dependencies = bom.dependencies
    .filter(d => keptRefs.has(d.ref))
    .map(d => Array.isArray(d.dependsOn)
      ? Object.assign({}, d, { dependsOn: d.dependsOn.filter(r => keptRefs.has(r)) })
      : d);
}
fs.writeFileSync(bomPath, JSON.stringify(bom, null, 2));
process.stderr.write('[build-prep] android: kept ' + bom.components.length + ' of ' + before + ' components\n');
FILTER_JS
    node "$_flt" "$OUT" "$ANDROID_RELEASE_SET" || log "android: filter skipped (non-fatal)"
    rm -f "$_flt" "$ANDROID_RELEASE_SET"
fi

# Node production-scope filter: keep only npm components in the resolved production
# set; drop the devDependencies tree cdxgen pulls in from package.json. Keep non-npm
# components and the app root, and prune the dependency graph to the kept refs.
if [ "${rc:-1}" -eq 0 ] && [ -n "${NODE_PROD_SET:-}" ] && [ -s "$NODE_PROD_SET" ] \
   && [ -f "$OUT" ] && command -v node >/dev/null 2>&1; then
    log "node: filtering SBOM to production scope"
    _nflt=$(mktemp).js
    cat > "$_nflt" <<'NFILTER_JS'
const fs = require('fs');
const [bomPath, setPath] = process.argv.slice(2);
let bom;
try { bom = JSON.parse(fs.readFileSync(bomPath, 'utf8')); } catch (e) { process.exit(0); }
const prod = new Set(fs.readFileSync(setPath, 'utf8').split('\n').filter(Boolean));
if (!prod.size || !Array.isArray(bom.components)) process.exit(0);
const mc = bom.metadata && bom.metadata.component;
const rootRef = mc && (mc['bom-ref'] || mc.purl);
const nameOf = c => (c.group ? c.group + '/' + c.name : c.name);
const keep = c => {
  if (!(c.purl || '').startsWith('pkg:npm/')) return true;   // non-npm: leave alone
  return prod.has(nameOf(c) + '@' + (c.version || ''));
};
const before = bom.components.length;
bom.components = bom.components.filter(keep);
const refOf = c => c['bom-ref'] || c.purl;
const keptRefs = new Set(bom.components.map(refOf));
if (rootRef) keptRefs.add(rootRef);
if (Array.isArray(bom.dependencies)) {
  bom.dependencies = bom.dependencies
    .filter(d => keptRefs.has(d.ref))
    .map(d => Array.isArray(d.dependsOn)
      ? Object.assign({}, d, { dependsOn: d.dependsOn.filter(r => keptRefs.has(r)) })
      : d);
}
fs.writeFileSync(bomPath, JSON.stringify(bom, null, 2));
process.stderr.write('[build-prep] node: kept ' + bom.components.length + ' of ' + before + ' components\n');
NFILTER_JS
    node "$_nflt" "$OUT" "$NODE_PROD_SET" || log "node: filter skipped (non-fatal)"
    rm -f "$_nflt" "$NODE_PROD_SET"
fi

# Maven scope filter: cdxgen tags each maven component with its resolved scope
# (compile/runtime -> required, test -> optional, provided/system -> excluded).
# Drop the non-deployable ones, keeping non-maven components, the app root, and
# anything cdxgen left unscoped. Prune the dependency graph to the kept refs.
# Guard: only act when cdxgen actually populated scopes (at least one maven node
# marked "required") — the syft fallback path emits no scope, and dropping there
# would gut the BOM, so we leave it untouched and recall never regresses.
if [ "${rc:-1}" -eq 0 ] && [ -n "${MAVEN_SCOPE_FILTER:-}" ] \
   && [ -f "$OUT" ] && command -v node >/dev/null 2>&1; then
    log "maven: filtering SBOM to deployable scope"
    _mflt=$(mktemp).js
    cat > "$_mflt" <<'MFILTER_JS'
const fs = require('fs');
const [bomPath] = process.argv.slice(2);
let bom;
try { bom = JSON.parse(fs.readFileSync(bomPath, 'utf8')); } catch (e) { process.exit(0); }
if (!Array.isArray(bom.components)) process.exit(0);
const isMaven = c => (c.purl || '').startsWith('pkg:maven/');
const hasScopes = bom.components.some(c => isMaven(c) && c.scope === 'required');
if (!hasScopes) process.exit(0);   // scopes not populated (e.g. syft fallback): leave as-is
const keep = c => !isMaven(c) || (c.scope !== 'optional' && c.scope !== 'excluded');
const before = bom.components.length;
bom.components = bom.components.filter(keep);
const mc = bom.metadata && bom.metadata.component;
const refOf = c => c['bom-ref'] || c.purl;
const keptRefs = new Set(bom.components.map(refOf));
if (mc) keptRefs.add(mc['bom-ref'] || mc.purl);
if (Array.isArray(bom.dependencies)) {
  bom.dependencies = bom.dependencies
    .filter(d => keptRefs.has(d.ref))
    .map(d => Array.isArray(d.dependsOn)
      ? Object.assign({}, d, { dependsOn: d.dependsOn.filter(r => keptRefs.has(r)) })
      : d);
}
fs.writeFileSync(bomPath, JSON.stringify(bom, null, 2));
process.stderr.write('[build-prep] maven: kept ' + bom.components.length + ' of ' + before + ' components\n');
MFILTER_JS
    node "$_mflt" "$OUT" || log "maven: filter skipped (non-fatal)"
    rm -f "$_mflt"
fi

# Python license evidence: settle each PyPI component's license on what the
# installed distribution actually ships, rather than on the summary PyPI serves.
#
# cdxgen reads three PyPI fields — the trove classifier, `license` and
# `license_expression` — and keeps whatever each one maps to. The classifier is
# a family, not a license ("License :: OSI Approved :: BSD License" covers the
# 2-, 3- and 4-clause variants alike), and `license` increasingly holds the whole
# license text, which cdxgen scans for the first name it recognises: numpy and
# pandas came out Apache-2.0 that way, off a bundled-dependency notice inside a
# BSD-3-Clause file.
#
# The wheel carries better evidence, and pip has already unpacked it here: the
# dist-info directory holds the PEP 639 expression when the project declares one,
# the license files themselves, and a `License:` field that is a name rather than
# a text. We read those in that order and only overwrite a component's license
# when the evidence settles on exactly one answer — a file whose text matches
# several templates (a dual license, or a license file with bundled notices
# appended) leaves the component alone for a human to read, and so does a
# declared name too vague to place, like a bare "BSD". Whatever we do set is
# stamped with bomlens:licenseSource so the basis is visible in the SBOM.
if [ "${rc:-1}" -eq 0 ] && [ -f "$OUT" ] && command -v python3 >/dev/null 2>&1 \
   && grep -q '"pkg:pypi/' "$OUT" 2>/dev/null; then
    log "python: settling licenses on installed distribution metadata"
    _pylic="$(mktemp).py"
    cat > "$_pylic" <<'PY_LIC'
import json, os, re, sys
from importlib.metadata import distributions

bom_path = sys.argv[1]
try:
    with open(bom_path, encoding="utf-8") as fh:
        bom = json.load(fh)
except Exception:
    sys.exit(0)
components = bom.get("components")
if not isinstance(components, list):
    sys.exit(0)


def canon(name):
    """PEP 503 normalisation, so Pillow/pillow and foo_bar/foo-bar match."""
    return re.sub(r"[-_.]+", "-", (name or "").strip()).lower()


def classify_text(text):
    """Identify a license by its distinctive clause wording.

    Mirrors identify_license_text in docker/lib/spdx-normalize.jq: matched on
    clause phrases, never on the copyright header, and deliberately silent when
    a text matches more than one template.
    """
    x = re.sub(r"\s+", " ", text).lower()
    hits = []
    if "permission is hereby granted, free of charge" in x and "without restriction" in x:
        hits.append("MIT")
    if "permission to use, copy, modify, and/or distribute this software for any purpose" in x:
        hits.append("ISC")
    if "apache license" in x and "version 2.0" in x:
        hits.append("Apache-2.0")
    if ("redistributions of source code must retain" in x
            and "redistributions in binary form must reproduce" in x
            and "advertising materials" not in x):
        hits.append("BSD-3-Clause" if "neither the name" in x else "BSD-2-Clause")
    return hits[0] if len(hits) == 1 else None


def classify_name(declared):
    """Map a short declared license NAME to an SPDX id.

    A subset of normalize() in spdx-normalize.jq, holding to the same rule: a
    name that does not say which variant it is ("BSD", "BSD License") maps to
    nothing, because guessing the clause count is the error this whole pass
    exists to undo. Compound expressions and any GPL family name are left to the
    upstream value and to human review.
    """
    n = re.sub(r"[ ,._/-]+", " ", (declared or "").strip().lower()).strip()
    if not n or len(n) > 100:
        return None
    if " or " in n or " and " in n or "general public" in n:
        return None
    if re.search(r"apache.*2", n):
        return "Apache-2.0"
    if n == "mit" or "mit license" in n or "expat" in n:
        return "MIT"
    if re.search(r"bsd.*3|new bsd|revised bsd|modified bsd", n):
        return "BSD-3-Clause"
    if re.search(r"bsd.*2|simplified bsd|freebsd", n):
        return "BSD-2-Clause"
    if n in ("isc", "isc license"):
        return "ISC"
    return None


def read_text(path, limit=400000):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except Exception:
        return ""


def license_files(dist):
    """Paths of the license files an installed distribution ships."""
    files, seen = [], set()

    def add(path):
        path = str(path)
        if path not in seen and os.path.isfile(path):
            seen.add(path)
            files.append(path)

    is_license = lambda fn: re.match(r"(LICEN[CS]E|COPYING)", fn, re.I)
    # The .dist-info / .egg-info directory itself, when the implementation
    # exposes it: the license files sit next to the metadata, either directly or
    # under licenses/ (PEP 639).
    base = str(getattr(dist, "_path", "") or "")
    if base and os.path.isdir(base):
        for rel in (dist.metadata.get_all("License-File") or []):
            for root in (os.path.join(base, "licenses"), base):
                cand = os.path.join(root, rel)
                if os.path.isfile(cand):
                    add(cand)
                    break
        for root, _dirs, names in os.walk(base):
            for fn in sorted(names):
                if is_license(fn):
                    add(os.path.join(root, fn))
    # An egg-info distribution records no license file of its own, and a wheel
    # whose metadata directory we could not locate still lists its files.
    if not files:
        for entry in (dist.files or []):
            if is_license(os.path.basename(str(entry))):
                try:
                    add(dist.locate_file(entry))
                except Exception:
                    continue
    return files


def evidence(dist):
    """Collect (version, expression, declared name, license files) for a dist."""
    try:
        meta = dist.metadata
        # .get, not [...]: a missing header returns None today but is documented
        # to start raising, and most distributions declare none of these.
        name, version = meta.get("Name"), meta.get("Version")
    except Exception:
        return None
    if not name or not version:
        return None
    return {"name": name, "version": version,
            "expression": meta.get("License-Expression"),
            "declared": meta.get("License"),
            "files": license_files(dist)}


def decide(ev):
    if ev["expression"]:
        return ev["expression"], "installed license expression"
    ids = set()
    for path in ev["files"]:
        got = classify_text(read_text(path))
        if got:
            ids.add(got)
    if len(ids) == 1:
        return ids.pop(), "installed license text"
    if not ids and ev["declared"]:
        got = classify_name(ev["declared"])
        if got:
            return got, "installed license name"
    return None, None


# distributions() walks sys.path, so it finds what pip installed here and what
# the image already had, in either metadata layout. Reading the site-packages
# directories by hand missed both: a package the image ships can sit outside
# them, and an older install records .egg-info rather than .dist-info.
index = {}
for dist in distributions():
    ev = evidence(dist)
    if ev:
        index.setdefault((canon(ev["name"]), ev["version"]), ev)

if not index:
    sys.exit(0)

changed = 0
for comp in components:
    if not str(comp.get("purl") or "").startswith("pkg:pypi/"):
        continue
    ev = index.get((canon(comp.get("name")), comp.get("version")))
    if not ev:
        continue
    settled, basis = decide(ev)
    if not settled:
        continue
    if re.search(r"\s(OR|AND|WITH)\s", settled):
        entry = {"expression": settled}
    else:
        entry = {"license": {"id": settled}}
    if comp.get("licenses") == [entry]:
        continue                                # already exactly this
    comp["licenses"] = [entry]
    props = [p for p in comp.get("properties") or []
             if p.get("name") != "bomlens:licenseSource"]
    props.append({"name": "bomlens:licenseSource", "value": basis})
    comp["properties"] = props
    changed += 1

if changed:
    with open(bom_path, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=2)
    sys.stderr.write("[build-prep] python: settled %d component license(s) on installed evidence\n" % changed)
PY_LIC
    python3 "$_pylic" "$OUT" || log "python: license evidence pass skipped (non-fatal)"
    rm -f "$_pylic"
fi

# Put the scanned tree back before the ownership fix below, so anything we
# restored is chown'd too (the trap only covers an abnormal exit).
guard_restore

# Hand the build tree back to the host user. This image runs as root (-u 0:0),
# so the build steps above (npm install, cargo/go fetch, the bom write) leave
# root-owned files in the mounted source dir. On Linux the host user then cannot
# clean its own project folder or the git/zip ingestion temp dir. HOST_UID/GID
# arrive via `docker run -e`; best-effort, never fail the prep on this.
if [ -n "${HOST_UID:-}" ] && [ -n "${HOST_GID:-}" ]; then
    chown -R "${HOST_UID}:${HOST_GID}" "$SRC" 2>/dev/null || true
fi
exit "${rc:-0}"
