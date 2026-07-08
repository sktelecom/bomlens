#!/bin/sh
# Copyright 2026 SK Telecom Co., Ltd.
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

# Hand the build tree back to the host user. This image runs as root (-u 0:0),
# so the build steps above (npm install, cargo/go fetch, the bom write) leave
# root-owned files in the mounted source dir. On Linux the host user then cannot
# clean its own project folder or the git/zip ingestion temp dir. HOST_UID/GID
# arrive via `docker run -e`; best-effort, never fail the prep on this.
if [ -n "${HOST_UID:-}" ] && [ -n "${HOST_GID:-}" ]; then
    chown -R "${HOST_UID}:${HOST_GID}" "$SRC" 2>/dev/null || true
fi
exit "${rc:-0}"
