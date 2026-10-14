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
# 1.6 default: this file is bind-mounted alone into the cdxgen container
# (isolated from the rest of docker/lib/), so it cannot source
# docker/lib/cdx-version.sh -- kept in manual sync with CDX_SPEC_VERSION there.
# Both real callers (docker/entrypoint.sh, scripts/scan-sbom.sh) pass it
# explicitly as $3, so this default is a last resort, not the normal path.
SPEC="${3:-1.6}"
# Ensure HOME exists & is writable (maven/cargo/etc. caches) for any base user.
mkdir -p "${HOME:-/tmp/sbomhome}" 2>/dev/null || true
cd "$SRC" 2>/dev/null || exit 0

log() { echo "[build-prep] $*"; }

# The BOMLENS_* opt-out switches count as set only for 1 or true, as documented.
opted_out() { case "$1" in 1|true) return 0 ;; esac; return 1; }

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
# directories that were NOT there before are removed (composer's vendor/ and
# dotnet's obj/ and bin/ included). Nothing outside these names is considered,
# and nothing that already existed is deleted, so a committed lockfile or a
# pre-existing build/ is never lost. The names in play are versioned and recorded
# with the snapshot (names.version): a snapshot written by an older script never
# listed vendor/obj/bin or composer.json, so finishing it must not treat the
# user's own ones as new.
# BOMLENS_KEEP_BUILD_OUTPUT=1 opts out (leave the resolved tree in place, e.g.
# to inspect what a resolution produced).
# ---------------------------------------------------------------------------
GUARD_DIR=""

# Resolver-owned paths, relative to $SRC. maxdepth 4 covers multi-module trees
# (app/build, services/api/go.mod) without walking a whole monorepo; .git and
# node_modules are pruned because nothing we run resolves inside them.
# The name set grows over time: 1 = original, 2 adds vendor/obj/bin directories,
# 3 adds composer.json (rewritten during the PHP resolve), 4 adds *.egg-info
# directories (left by a Python source install), 5 adds requirements.txt
# (written for a Poetry project with no lock). guard_paths takes the
# version to list, so a snapshot is always compared with the names it was written
# under.
GUARD_NAMES_VERSION=5
guard_paths() {  # guard_paths f|d [version]
    _gv="${2:-$GUARD_NAMES_VERSION}"
    if [ "$1" = "f" ]; then
        if [ "$_gv" -ge 5 ]; then
            find . -maxdepth 4 \( -name .git -o -name node_modules -o -name vendor \) -prune -o -type f \
                \( -name go.mod -o -name go.sum -o -name Cargo.lock -o -name Gemfile.lock \
                   -o -name Package.resolved -o -name package-lock.json \
                   -o -name composer.lock -o -name composer.json -o -name requirements.txt \) -print 2>/dev/null | LC_ALL=C sort
        elif [ "$_gv" -ge 3 ]; then
            find . -maxdepth 4 \( -name .git -o -name node_modules -o -name vendor \) -prune -o -type f \
                \( -name go.mod -o -name go.sum -o -name Cargo.lock -o -name Gemfile.lock \
                   -o -name Package.resolved -o -name package-lock.json \
                   -o -name composer.lock -o -name composer.json \) -print 2>/dev/null | LC_ALL=C sort
        else
            find . -maxdepth 4 \( -name .git -o -name node_modules \) -prune -o -type f \
                \( -name go.mod -o -name go.sum -o -name Cargo.lock -o -name Gemfile.lock \
                   -o -name Package.resolved -o -name package-lock.json \
                   -o -name composer.lock \) -print 2>/dev/null | LC_ALL=C sort
        fi
    else
        # Directory names accumulate by version; "$@" carries them into one find.
        set -- -name .gradle -o -name .build -o -name build -o -name target \
               -o -name node_modules -o -name __pycache__ -o -name .venv
        [ "$_gv" -lt 2 ] || set -- "$@" -o -name vendor -o -name obj -o -name bin
        [ "$_gv" -lt 4 ] || set -- "$@" -o -name '*.egg-info'
        find . -maxdepth 4 -name .git -prune -o -type d \( "$@" \) \
            -print -prune 2>/dev/null | LC_ALL=C sort
    fi
}

guard_snapshot() {
    opted_out "${BOMLENS_KEEP_BUILD_OUTPUT:-}" && { log "source-tree guard off (BOMLENS_KEEP_BUILD_OUTPUT)"; return 0; }
    # Host-persistent guard state (BOMLENS_GUARD_ID, /bomlens-state -- see the
    # restore-only branch near the bottom of this file): when the caller wired
    # both up, this snapshot survives a SIGKILL that never lets guard_restore
    # run, so a later invocation can finish the restore. Falls back to the
    # normal ephemeral dir when either is absent (unset key, older caller,
    # no /bomlens-state mount) -- unchanged from before this existed.
    if [ -n "${BOMLENS_GUARD_ID:-}" ] && [ -d /bomlens-state ]; then
        GUARD_DIR="/bomlens-state/$BOMLENS_GUARD_ID"
        mkdir -p "$GUARD_DIR" 2>/dev/null || GUARD_DIR=""
    fi
    [ -n "$GUARD_DIR" ] || GUARD_DIR=$(mktemp -d 2>/dev/null) || { GUARD_DIR=""; return 0; }
    guard_paths f > "$GUARD_DIR/files.before" 2>/dev/null
    guard_paths d > "$GUARD_DIR/dirs.before" 2>/dev/null
    echo "$GUARD_NAMES_VERSION" > "$GUARD_DIR/names.version" 2>/dev/null
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
    # A snapshot written by an older script has no version file (1) and is
    # finished with the names it was written under.
    _gnv=$(cat "$_g/names.version" 2>/dev/null)
    case "$_gnv" in ''|*[!0-9]*) _gnv=1 ;; esac
    guard_paths f "$_gnv" > "$_g/files.after" 2>/dev/null
    while IFS= read -r _f; do
        [ -n "$_f" ] || continue
        # Never the SBOM itself: the web-UI path asks cdxgen to write it inside
        # the tree when the run folder is not on a shared mount.
        [ "$SRC/${_f#./}" = "$OUT" ] && continue
        grep -qxF "$_f" "$_g/files.before" 2>/dev/null && continue
        rm -f "$_f" 2>/dev/null && _del=$((_del + 1))
    done < "$_g/files.after"
    guard_paths d "$_gnv" > "$_g/dirs.after" 2>/dev/null
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

# ---------------------------------------------------------------------------
# Supervised execution — run a resolver command so an interrupt can actually
# stop it, instead of the interrupt being deferred until the command finishes
# on its own.
#
# A shell only runs a trap once it regains control; while it is blocked
# waiting on a foreground command, a caught signal does not preempt that wait
# (confirmed by measurement: `docker stop` with a 5-minute grace never let
# INT/TERM-based cleanup run against a plain foreground cdxgen invocation).
# Backgrounding the command and waiting on it explicitly changes that: the
# `wait` returns as soon as the signal arrives, so the trap can act right
# away — it just has to stop the command itself first.
#
# setsid gives the command its own process group (pgid == its own pid), so
# stopping it reaches the whole subtree it spawns (language tool -> package
# manager -> git clone, etc.) with one signal instead of depending on each
# level to forward it to the next. Confirmed present in every cdxgen image
# build-prep.sh runs in (debian-rust/golang124/ruby34/php84/dotnet9/swift,
# temurin-java21, python312, node20, the all-in-one image). Where it is
# missing, falls back to a /proc-based tree walk.
#
# _cg_pid / _cg_pgid track whatever is currently supervised, so stop_supervised
# and a trap can act on it without either needing to be passed the details.
_cg_pid=""
_cg_pgid=""
_have_setsid=0
command -v setsid >/dev/null 2>&1 && _have_setsid=1

_proc_kill_tree() {
    _pkt_root="$1"; _pkt_sig="$2"
    for _pkt_p in /proc/[0-9]*; do
        _pkt_pid=${_pkt_p#/proc/}
        [ -r "$_pkt_p/stat" ] || continue
        _pkt_ppid=$(awk '{print $4}' "$_pkt_p/stat" 2>/dev/null)
        [ "$_pkt_ppid" = "$_pkt_root" ] && _proc_kill_tree "$_pkt_pid" "$_pkt_sig"
    done
    kill "-$_pkt_sig" "$_pkt_root" 2>/dev/null
}

_supervised_alive() {
    if [ -n "$_cg_pgid" ]; then
        kill -0 "-$_cg_pgid" 2>/dev/null
    else
        kill -0 "$_cg_pid" 2>/dev/null
    fi
}

# Run CMD... in the background (its own process group via setsid when
# available) and block until it finishes, returning its exit code. Sets
# _cg_pid/_cg_pgid so stop_supervised (from a trap, or a caller's own
# deadline) can stop it.
run_supervised() {
    if [ "$_have_setsid" = 1 ]; then
        setsid "$@" &
        _cg_pid=$!
        _cg_pgid="$_cg_pid"
    else
        "$@" &
        _cg_pid=$!
        _cg_pgid=""
    fi
    wait "$_cg_pid"
    return $?
}

# Same as run_supervised, but returns 124 (matching the `timeout` command's
# convention) and stops the command itself if it is still running after
# TIMEOUT_SECONDS, instead of waiting for it indefinitely. Does not exit the
# script and does not touch GUARD_DIR — a caller times out one step and keeps
# going, distinct from the whole-script abort the INT/TERM traps below do.
run_supervised_timeout() {
    _rst_timeout="$1"; shift
    if [ "$_have_setsid" = 1 ]; then
        setsid "$@" &
        _cg_pid=$!
        _cg_pgid="$_cg_pid"
    else
        "$@" &
        _cg_pid=$!
        _cg_pgid=""
    fi
    _rst_n=0
    while kill -0 "$_cg_pid" 2>/dev/null; do
        if [ "$_rst_n" -ge "$_rst_timeout" ]; then
            stop_supervised
            return 124
        fi
        sleep 1
        _rst_n=$((_rst_n + 1))
    done
    wait "$_cg_pid"
    return $?
}

# Stop whatever run_supervised/run_supervised_timeout is currently tracking:
# TERM, wait for it to actually exit (not just accept that we asked), then
# KILL if it hasn't. Blocks (bounded) until the whole tree is confirmed gone,
# so a caller running guard_restore right after is not racing a resolver
# process still writing files. Idempotent; a no-op when nothing is tracked.
stop_supervised() {
    [ -n "$_cg_pid" ] || return 0
    if [ -n "$_cg_pgid" ]; then
        kill -TERM "-$_cg_pgid" 2>/dev/null
    else
        _proc_kill_tree "$_cg_pid" TERM
    fi
    _ss_n=0
    while [ "$_ss_n" -lt 50 ] && _supervised_alive; do
        sleep 0.2
        _ss_n=$((_ss_n + 1))
    done
    if _supervised_alive; then
        if [ -n "$_cg_pgid" ]; then
            kill -KILL "-$_cg_pgid" 2>/dev/null
        else
            _proc_kill_tree "$_cg_pid" KILL
        fi
        _ss_n=0
        while [ "$_ss_n" -lt 25 ] && _supervised_alive; do
            sleep 0.2
            _ss_n=$((_ss_n + 1))
        done
    fi
    _cg_pid=""; _cg_pgid=""
}

# Time limits for the resolution steps below, run through prep_step. A first
# Gradle resolve (empty cache) can legitimately take well over 15 minutes, and
# losing dependencies to a timeout is worse than a slow scan, so Gradle steps
# get a longer budget than the rest. BOMLENS_PREP_TIMEOUT overrides both.
PREP_TIMEOUT_DEFAULT="${BOMLENS_PREP_TIMEOUT:-900}"
PREP_TIMEOUT_GRADLE="${BOMLENS_PREP_TIMEOUT:-1800}"

# Run one resolution step (LABEL, a timeout in seconds, then the command and
# its args) under run_supervised_timeout, so it is stopped like the rest if the
# scan is interrupted. Failure or a timeout (rc 124) is logged with the
# command's own stderr (last 20 lines) and recorded in PREP_FAILED, a
# space-separated list of labels a caller stamps onto the SBOM once cdxgen has
# run. Every label this scan actually calls, success or failure, also lands in
# PREP_APPLIED regardless of outcome: a manifest this project does not have
# (e.g. no go.mod) never calls prep_step at all, so PREP_APPLIED is what tells
# a reader "this ecosystem's step ran here" apart from "it never applied" --
# PREP_FAILED alone cannot, since both look the same (absent) to it. Never
# aborts the script; returns the command's exit code.
PREP_FAILED=""
PREP_APPLIED=""
prep_step() {
    _ps_label="$1"; _ps_timeout="$2"; shift 2
    case " $PREP_APPLIED " in
        *" $_ps_label "*) ;;
        *) PREP_APPLIED="${PREP_APPLIED:+$PREP_APPLIED }$_ps_label" ;;
    esac
    _ps_err=$(mktemp)
    run_supervised_timeout "$_ps_timeout" "$@" 2>"$_ps_err"
    _ps_rc=$?
    if [ "$_ps_rc" -ne 0 ]; then
        if [ "$_ps_rc" -eq 124 ]; then
            echo "[build-prep] $_ps_label: timed out after ${_ps_timeout}s" >&2
        else
            echo "[build-prep] $_ps_label: failed (rc=$_ps_rc)" >&2
        fi
        if [ -s "$_ps_err" ]; then
            echo "[build-prep] $_ps_label said (last 20 lines):" >&2
            tail -20 "$_ps_err" | sed 's/^/[build-prep]   /' >&2
        fi
        case " $PREP_FAILED " in
            *" $_ps_label "*) ;;
            *) PREP_FAILED="${PREP_FAILED:+$PREP_FAILED }$_ps_label" ;;
        esac
    fi
    rm -f "$_ps_err"
    return "$_ps_rc"
}

# Record LABEL into PREP_APPLIED directly, with no command to run: for a
# manifest whose lock evidence is a file we only check for (a committed
# Gemfile.lock/Package.resolved/composer.lock/packages.lock.json), not a
# command whose failure prep_step would capture. Never touches PREP_FAILED --
# there is nothing here that can fail.
# Record a step as failed that does not run through prep_step (one that
# decides failure itself). Same list, recorded on the SBOM the same way.
mark_prep_failed() {
    case " $PREP_FAILED " in
        *" $1 "*) ;;
        *) PREP_FAILED="${PREP_FAILED:+$PREP_FAILED }$1" ;;
    esac
}

mark_prep_applied() {
    case " $PREP_APPLIED " in
        *" $1 "*) ;;
        *) PREP_APPLIED="${PREP_APPLIED:+$PREP_APPLIED }$1" ;;
    esac
}

# Cleanup-only invocation (BOMLENS_GUARD_RESTORE_ONLY=1): a prior run recorded
# its snapshot at /bomlens-state/$BOMLENS_GUARD_ID and never got to restore
# it -- SIGKILL, OOM, a host crash, anything that skips the traps below. The
# caller (scan-sbom.sh / entrypoint.sh) already confirmed that run's container
# is gone before asking us to finish what it started; this reuses
# guard_restore's own diff logic instead of reimplementing it host-side. No
# resolvers, no cdxgen -- filesystem cleanup only, and fast.
if opted_out "${BOMLENS_GUARD_RESTORE_ONLY:-}"; then
    if [ -n "${BOMLENS_GUARD_ID:-}" ] && [ -d "/bomlens-state/$BOMLENS_GUARD_ID" ]; then
        GUARD_DIR="/bomlens-state/$BOMLENS_GUARD_ID"
        guard_restore
    fi
    exit 0
fi

guard_snapshot
# _pg_dir: the Poetry dependency-graph run's scratch folder, while it exists.
trap 'stop_supervised; guard_restore; [ -z "${_pg_dir:-}" ] || rm -rf "$_pg_dir"' EXIT
trap 'stop_supervised; guard_restore; [ -z "${_pg_dir:-}" ] || rm -rf "$_pg_dir"; exit 130' INT
trap 'stop_supervised; guard_restore; [ -z "${_pg_dir:-}" ] || rm -rf "$_pg_dir"; exit 143' TERM

# Non-shipped trees: manifests under test, fixture, example, benchmark and demo
# folders, the GitHub Actions workflows and the Gradle wrapper jar are left out
# of the SBOM because none of it ships with the product. The lists below are
# copies of the ones in source-detect.sh (this file runs alone in the cdxgen
# container); tests/test-postprocess.sh checks they stay equal.
# NON_SHIPPED_PATHS are folder paths left out at any depth;
# NON_SHIPPED_PATH_FILE_RE names the files under them that are recorded in
# bomlens:excluded-manifests.
# BOMLENS_INCLUDE_NON_SHIPPED=1 (or true) keeps everything. Defined here,
# ahead of every ecosystem block below, because the lock-evidence check each
# one may run (mark_prep_applied / _lock_evidence_found) needs it too, not
# just the cdxgen --exclude flags built from it further down.
NON_SHIPPED_DIRS="test tests spec fixtures testdata __tests__ e2e example examples sample samples bench benches benchmark benchmarks demo demos playground"
NON_SHIPPED_MANIFEST_RE='(^|/)(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|requirements[^/]*\.txt|pyproject\.toml|poetry\.lock|uv\.lock|Pipfile|Pipfile\.lock|setup\.py|setup\.cfg|environment\.ya?ml|pom\.xml|build\.gradle(\.kts)?|settings\.gradle(\.kts)?|gradle\.lockfile|go\.mod|go\.sum|Cargo\.toml|Cargo\.lock|Gemfile|Gemfile\.lock|[^/]+\.gemspec|composer\.json|composer\.lock|[^/]+\.(cs|fs|vb)proj|packages\.config|packages\.lock\.json|Directory\.Packages\.props|Package\.swift|Package\.resolved|Podfile|Podfile\.lock|conanfile\.txt|conanfile\.py|vcpkg\.json|METADATA|PKG-INFO)$'
NON_SHIPPED_PATHS=".github/workflows gradle/wrapper"
NON_SHIPPED_PATH_FILE_RE='(^|/)(\.github/workflows/[^/]+\.ya?ml|gradle/wrapper/[^/]+\.jar)$'
EXCLUDE_NON_SHIPPED=1
if opted_out "${BOMLENS_INCLUDE_NON_SHIPPED:-}"; then
    EXCLUDE_NON_SHIPPED=""
    log "non-shipped trees kept (BOMLENS_INCLUDE_NON_SHIPPED)"
fi

# True when a lockfile named $1 exists anywhere under the scan root, outside
# .git/node_modules/vendor (a dependency's OWN lockfile is not evidence about
# THIS project) and the non-shipped test/fixture/example trees above (a
# lockfile bundled as a fixture for testing unrelated tooling is not evidence
# either -- and unpruned, this walks vendor/node_modules in full on every
# call, which is slow on a real monorepo). Used by the Swift/PHP/.NET lock-
# evidence checks below. Uses its own positional parameters, not "$@" (which
# for most of this script's later ecosystem blocks is cdxgen's own argument
# list being built) -- a function's `set --` only reassigns its own scope in
# POSIX sh, so this never leaks into the caller's "$@".
_lock_evidence_found() {
    _lef_name="$1"
    set -- -name .git -o -name node_modules -o -name vendor
    if [ -n "$EXCLUDE_NON_SHIPPED" ]; then
        for _lef_d in $NON_SHIPPED_DIRS; do set -- "$@" -o -name "$_lef_d"; done
    fi
    find . \( "$@" \) -prune -o -type f -name "$_lef_name" -print 2>/dev/null | grep -q .
}

# Rust — cdxgen does NOT auto-run cargo; lockfile is essential for transitive deps.
# A committed Cargo.lock is used as it is: `cargo generate-lockfile` resolves
# afresh and moves every crate to the newest compatible release, so the SBOM
# would list versions the project does not build with. Like a committed
# Gemfile.lock, it is recorded as lock evidence without being re-resolved.
if [ -f Cargo.toml ]; then
    if [ -f Cargo.lock ]; then
        mark_prep_applied cargo-lock-committed
    elif command -v cargo >/dev/null 2>&1; then
        log "cargo generate-lockfile (no committed Cargo.lock)"
        prep_step cargo-lockfile "$PREP_TIMEOUT_DEFAULT" cargo generate-lockfile
    fi
fi

# Go — complete go.sum so cdxgen's default-readonly `go list -deps` resolves the
# full transitive graph. Plain `go mod download` leaves go.sum missing entries
# that readonly `go list` requires (it then fails and cdxgen falls back to parsing
# go.mod = direct deps only). `go mod tidy` populates go.sum fully; fall back to
# download if tidy can't run (e.g. no network to fix an inconsistent go.mod).
#
# The cdxgen Go image pins GOTOOLCHAIN=local, so a go.mod that asks for a newer
# Go than the image carries fails every go command, cdxgen's `go list` included.
# Exported (not per-command) so cdxgen, started later from this shell, inherits
# it. `auto` fetches the requested toolchain through the module proxy, the same
# network path the module downloads already use. The caller passes the host's
# GOTOOLCHAIN as HOST_GOTOOLCHAIN: inside the image GOTOOLCHAIN is always set, so
# a user's own `local` could not be told apart from the image default.
if [ -f go.mod ] && command -v go >/dev/null 2>&1; then
    export GOTOOLCHAIN="${HOST_GOTOOLCHAIN:-auto}"
    if ! _gv=$(go version 2>&1); then
        echo "[build-prep] go: could not get the Go toolchain go.mod requires; dependency resolution will be incomplete." >&2
        echo "[build-prep] go: $(printf '%s\n' "$_gv" | tail -1)" >&2
        echo "[build-prep] go: allow access to proxy.golang.org (or your GOPROXY) from the Docker engine and re-scan." >&2
    fi
    log "go mod tidy"
    prep_step go-mod-tidy "$PREP_TIMEOUT_DEFAULT" sh -c 'GOFLAGS="-mod=mod" go mod tidy || GOFLAGS="-mod=mod" go mod download'
fi

# Ruby — ensure a lockfile exists (cdxgen ruby images usually auto-resolve,
# but a Gemfile.lock makes it deterministic). A Gemfile.lock already committed
# is itself positive lock evidence -- record it the same as a step we ran
# ourselves succeeding, without re-resolving over the network.
if [ -f Gemfile ]; then
    if [ -f Gemfile.lock ]; then
        mark_prep_applied bundle-lock
    elif command -v bundle >/dev/null 2>&1; then
        log "bundle lock"
        prep_step bundle-lock "$PREP_TIMEOUT_DEFAULT" sh -c 'bundle lock || bundle install'
    fi
fi

# PHP (Composer): resolve a lockfile when the root manifest has none.
# Unlike Ruby/Cargo/Go/Python above, cdxgen never resolves composer.json on
# its own: a root manifest with no committed composer.lock (a library-shaped
# package that does not commit one at all, confirmed against Symfony's
# HttpFoundation component) has nothing for cdxgen to read and the scan
# comes back with zero components, no different from a project that
# genuinely has no dependencies. --no-dev keeps the resolve at deployable
# scope, the same principle PHP_SCOPE_FILTER below applies when a lock is
# already there. composer.lock already committed at the root, or found
# nested under a monorepo component with none at the root, is unaffected --
# that positive lock evidence is recorded further down this file
# (composer-lock-committed), unchanged by this step.
if [ -f composer.json ] && [ ! -f composer.lock ] && command -v composer >/dev/null 2>&1; then
    log "composer update"
    # `--no-dev` only skips installing require-dev; composer still resolves it,
    # and a library whose dev tools require the library itself or PHP extensions
    # the image lacks fails to resolve at all, leaving no lock and an empty SBOM.
    # A library may also set config.lock=false, so composer writes no lock even
    # when it resolves. The deployable scope needs none of that, so resolve a
    # manifest without require-dev and config.lock, and ignore platform
    # requirements (nothing runs here; a project pinned to an older PHP than the
    # image still resolves, though a dependency version needing a newer PHP can
    # then be picked). BOMLENS_PHP_FULL_GRAPH keeps the full manifest. The
    # original is copied outside the tree, written back in place (so a symlinked
    # composer.json stays a link) right after the resolve, and is also covered
    # by the source-tree guard if the run is killed in between. php is always
    # there where composer is; jq covers a stub or an unusual image.
    _cj_orig=""; _cj_new=""
    if ! opted_out "${BOMLENS_PHP_FULL_GRAPH:-}"; then
        _cj_orig=$(mktemp 2>/dev/null) && _cj_new=$(mktemp 2>/dev/null) || { rm -f "$_cj_orig" "$_cj_new"; _cj_orig=""; }
    fi
    if [ -n "$_cj_orig" ] && cp -p composer.json "$_cj_orig" 2>/dev/null; then
        _cj_ok=""
        if command -v php >/dev/null 2>&1; then
            php -r '$j = json_decode(file_get_contents("composer.json")); if (!is_object($j)) exit(1); unset($j->{"require-dev"}); if (isset($j->config) && is_object($j->config)) unset($j->config->lock); echo json_encode($j, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);' > "$_cj_new" 2>/dev/null && _cj_ok=1
        elif command -v jq >/dev/null 2>&1; then
            jq 'del(."require-dev") | del(.config.lock)' composer.json > "$_cj_new" 2>/dev/null && _cj_ok=1
        fi
        if [ -n "$_cj_ok" ] && [ -s "$_cj_new" ] && cat "$_cj_new" > composer.json 2>/dev/null; then
            _cj_rewritten=1
        else
            _cj_rewritten=""
        fi
    fi
    prep_step composer-install "$PREP_TIMEOUT_DEFAULT" composer update --no-dev --no-scripts --no-interaction --ignore-platform-reqs
    [ -z "${_cj_rewritten:-}" ] || cat "$_cj_orig" > composer.json 2>/dev/null
    rm -f "${_cj_orig:-}" "${_cj_new:-}"
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
if [ -f pom.xml ] && ! opted_out "${BOMLENS_MAVEN_FULL_GRAPH:-}"; then
    MAVEN_SCOPE_FILTER=1
fi

# PHP/Composer scope over-scan: the same mechanism as the Maven filter above.
# cdxgen already tags each composer component's resolved scope (require ->
# required, require-dev -> optional), so no composer run or second resolve is
# needed here either, confirmed against the pinned cdxgen PHP image and not
# just assumed from cdxgen's own upstream behavior. BOMLENS_PHP_FULL_GRAPH=1
# opts out (keep the require+require-dev superset).
PHP_SCOPE_FILTER=""
if [ -f composer.json ] && ! opted_out "${BOMLENS_PHP_FULL_GRAPH:-}"; then
    PHP_SCOPE_FILTER=1
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
    # Gradle keeps its files under ~/.gradle, where ~ is the account's home
    # from the password file (/root), not HOME. With a read-only root it
    # cannot unpack its native library there and every Gradle build fails at
    # once (cdxgen too, with an empty SBOM). Then it uses $HOME/.gradle. A
    # writable ~/.gradle (the CLI mounts the host's Gradle cache there) is
    # kept.
    if [ -z "${GRADLE_USER_HOME:-}" ]; then
        _acct_home="$( (getent passwd "$(id -u)" 2>/dev/null || true) | cut -d: -f6)"
        [ -n "$_acct_home" ] || _acct_home=/root
        if ! { mkdir -p "$_acct_home/.gradle" 2>/dev/null && [ -w "$_acct_home/.gradle" ]; }; then
            export GRADLE_USER_HOME="${HOME:-/tmp}/.gradle"
            log "gradle: $_acct_home/.gradle cannot be written; using $GRADLE_USER_HOME"
        fi
    fi

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
    if [ -n "${ANDROID_HOME:-}" ] && ! opted_out "${BOMLENS_ANDROID_FULL_GRAPH:-}"; then
        log "android: resolving deployable release runtime classpath"
        _relset=$(mktemp)
        # Both Gradle calls below share one label: to a reader they are one
        # logical step (the release classpath resolve), whether it timed out
        # listing subprojects or resolving one module's dependencies.
        _subs=$(prep_step android-release-classpath "$PREP_TIMEOUT_GRADLE" "$GRADLEW" --no-daemon -q --console=plain projects \
                | sed -n "s/.*Project '\(:[A-Za-z0-9:._-]*\)'.*/\1/p")
        # Include the root ("") as a fallback for single-module projects.
        for _s in $_subs ""; do
            _dep=$(prep_step android-release-classpath "$PREP_TIMEOUT_GRADLE" "$GRADLEW" --no-daemon -q --console=plain "${_s}:dependencies")
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
        prep_step gradle-dependencies "$PREP_TIMEOUT_GRADLE" "$GRADLEW" --no-daemon dependencies >/dev/null
    fi
fi

# Python — install the requirements so transitive deps are visible
# (requirements.txt without a lockfile) and so the license-evidence pass near the
# end of this script has real dist-info metadata to read.
#
# `pip install -r` is all or nothing: a single pin that cannot be resolved or
# built aborts the run and installs NOTHING. With pip's stderr discarded that
# failure was also silent, and the damage reached well past the missing package:
# every other requirement's dist-info was absent too, so the license pass found
# no evidence for anything and cdxgen's PyPI-summary licenses stood unchallenged
# (numpy and pandas then carry the wrong license on a tree that scans fine
# without the bad pin). So: keep the bulk install as the fast path, surface pip's
# own error when it fails, then retry requirement by requirement so one
# unbuildable pin costs only its own evidence.
# Written to a temp file and run as its own script, not a shell function:
# prep_step backgrounds a step through setsid, which execs a real process and
# cannot see a function defined in build-prep.sh's own interpreter (setsid:
# failed to execute ...: No such file or directory, pip never ran, silently,
# because the failure still landed in PREP_FAILED). Same reason go-mod-tidy,
# bundle-lock and npm-production-set below run through sh rather than a
# function. A file rather than `sh -c "$(cat <<'EOF' ...)"`: some /bin/sh
# builds mis-parse a `case ... ;; esac` heredoc body nested inside a command
# substitution.
#
# Everything the script writes to stderr (pip's own output included, no longer
# routed through a side file) lands in prep_step's capture and its
# last-20-lines report on failure. The per-requirement "$_pf of $_pn failed"
# summary stays, since prep_step's generic message has no way to know that
# count.
_pip_script=$(mktemp 2>/dev/null) || _pip_script="${TMPDIR:-/tmp}/bomlens-pip-install.sh"
cat > "$_pip_script" <<'PIPSCRIPT'
PIP_BSP=""                       # PEP 668 needs --break-system-packages here

# One best-effort install attempt. A PEP 668 "externally managed" image
# refuses the plain call and needs --break-system-packages; that is the only
# failure worth retrying, and once seen it is remembered, so a requirement
# that simply cannot be built is attempted once rather than twice.
pip_try() {
    if [ -n "$PIP_BSP" ]; then
        pip3 install -q --break-system-packages "$@"
        return $?
    fi
    _ptry=$(mktemp 2>/dev/null) || _ptry="${TMPDIR:-/tmp}/bomlens-pip-try.err"
    pip3 install -q "$@" 2>"$_ptry"
    _prc=$?
    if [ "$_prc" -ne 0 ] && grep -q "externally-managed-environment" "$_ptry" 2>/dev/null; then
        rm -f "$_ptry"
        pip3 install -q --break-system-packages "$@" || return 1
        PIP_BSP=1
        return 0
    fi
    cat "$_ptry" >&2
    rm -f "$_ptry"
    return "$_prc"
}

if ! pip_try -r requirements.txt; then
    echo "[build-prep] pip: bulk install failed; retrying one requirement at a time" >&2
    _reqs=$(mktemp 2>/dev/null) || _reqs="${TMPDIR:-/tmp}/bomlens-reqs.txt"
    # Strip comments the way pip does: a whole-line '#', or a '#' that
    # follows whitespace. A bare '#' inside a token is left alone so a VCS
    # URL fragment (git+https://...#egg=name) survives.
    sed -e 's/^[[:space:]]*#.*$//' -e 's/[[:space:]][[:space:]]*#.*$//' \
        -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' requirements.txt > "$_reqs"
    _pn=0; _pf=0
    while IFS= read -r _req; do
        [ -n "$_req" ] || continue
        # Option lines (-r/-c/-e/--index-url/--hash/...) are not requirement
        # specifiers; installing them one by one is meaningless.
        case "$_req" in -*) continue ;; esac
        _pn=$((_pn + 1))
        pip_try "$_req" \
            || { _pf=$((_pf + 1)); echo "[build-prep] pip: could not install '$_req'" >&2; }
    done < "$_reqs"
    rm -f "$_reqs"
    if [ "$_pf" -gt 0 ]; then
        echo "[build-prep] pip: $_pf of $_pn requirement(s) failed to install" >&2
        exit 1
    fi
fi
exit 0
PIPSCRIPT

# Poetry with no lock file. cdxgen reads [tool.poetry.dependencies] only by
# running `poetry`, which the image does not have, so a Poetry project without
# poetry.lock came back with no components at all. The exact pins in that
# table (`requests = "2.31.0"` or "==2.31.0") are written to a requirements.txt
# that the step below and cdxgen both read; ranges, table forms (git, path,
# extras) and the python constraint are left out rather than guessed. Only when
# there is no poetry.lock and no requirements.txt; the source-tree guard removes
# the file again after the scan.
if [ -f pyproject.toml ] && [ ! -f poetry.lock ] && [ ! -f requirements.txt ] \
   && command -v python3 >/dev/null 2>&1; then
    _poetry_n=$(python3 - <<'PYEOF' 2>/dev/null
import re, sys
try:
    import tomllib
except ImportError:
    print("notoml")
    sys.exit(0)
try:
    with open("pyproject.toml", "rb") as fh:
        data = tomllib.load(fh)
except (OSError, ValueError):
    sys.exit(0)
tool = data.get("tool") if isinstance(data.get("tool"), dict) else {}
poetry = tool.get("poetry") if isinstance(tool.get("poetry"), dict) else {}
deps = poetry.get("dependencies") if isinstance(poetry.get("dependencies"), dict) else {}
lines, skipped = [], 0
for name, spec in deps.items():
    if name.lower() == "python":
        continue
    version = spec.strip() if isinstance(spec, str) else ""
    if version.startswith("=="):
        version = version[2:].strip()
    elif version.startswith("="):
        version = version[1:].strip()
    if re.fullmatch(r"[0-9][0-9A-Za-z.\-+!]*", version):
        lines.append(f"{name}=={version}")
    else:
        skipped += 1
if lines:
    with open("requirements.txt", "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
print(f"{len(lines)} {skipped}")
PYEOF
)
    case "$_poetry_n" in
        notoml)
            log "poetry: no poetry.lock, and this image's python3 cannot read pyproject.toml (no tomllib); dependencies not resolved" ;;
        [0-9]*)
            _poetry_pins="${_poetry_n% *}"; _poetry_skip="${_poetry_n#* }"
            if [ "$_poetry_pins" -gt 0 ] 2>/dev/null; then
                log "poetry: no poetry.lock; $_poetry_pins exact pin(s) from [tool.poetry.dependencies] written to requirements.txt, $_poetry_skip range or table dependenc(ies) not resolved"
                mark_prep_applied poetry-requirements
                [ "$_poetry_skip" -gt 0 ] 2>/dev/null && mark_prep_applied poetry-requirements-partial
                POETRY_REQUIREMENTS_WRITTEN=1
            elif [ "$_poetry_skip" -gt 0 ] 2>/dev/null; then
                log "poetry: no poetry.lock and no exact pins; $_poetry_skip range or table dependenc(ies) not resolved"
            fi ;;
    esac
fi

if [ -f requirements.txt ] && command -v pip3 >/dev/null 2>&1; then
    log "pip install requirements"
    prep_step pip-install "$PREP_TIMEOUT_DEFAULT" sh "$_pip_script"
fi
rm -f "$_pip_script"

# Swift / SPM — cdxgen reads Package.resolved for the resolved graph, and parses it
# offline (verified: both the v1 `object.pins` and v2 top-level `pins` formats). Only run
# `swift package resolve` when NO Package.resolved is committed: a committed lockfile is
# already the resolved truth, and re-resolving reaches the network, where a partial fetch
# leaves versions "unspecified" and drags in unrelated tooling. CocoaPods (Podfile.lock)
# needs no prep here — it is filled from the lockfile by syft in post-processing. NOTE:
# UIKit/Xcode-driven resolution needs macOS; on Linux only non-platform Swift deps resolve.
if [ -f Package.swift ] && command -v swift >/dev/null 2>&1; then
    if _lock_evidence_found Package.resolved; then
        log "swift: committed Package.resolved present; skipping network resolve"
        # A committed Package.resolved is itself positive lock evidence, the
        # same as running the resolve ourselves and it succeeding.
        mark_prep_applied swift-package-resolve
    else
        log "swift package resolve (no committed Package.resolved)"
        prep_step swift-package-resolve "$PREP_TIMEOUT_DEFAULT" swift package resolve >/dev/null
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
# A workspace root with no package-lock.json (yarn, pnpm or bun workspaces):
# only the root package.json reaches the scratch resolve, so the members'
# production dependencies would be missing from the set and filtered out.
# Keep the full graph there.
_node_ws_nolock=""
if [ -f package.json ] && [ ! -f package-lock.json ] \
   && { [ -f pnpm-workspace.yaml ] || { command -v node >/dev/null 2>&1 \
        && node -e 'const p=JSON.parse(require("fs").readFileSync("package.json","utf8")); process.exit(p.workspaces ? 0 : 1)' 2>/dev/null; }; }; then
    _node_ws_nolock=1
    log "node: workspace root with no package-lock.json; keeping the full graph (production filter not applied)"
fi
if [ -f package.json ] && [ -z "$_node_ws_nolock" ] && ! opted_out "${BOMLENS_NODE_FULL_GRAPH:-}" \
   && command -v npm >/dev/null 2>&1 && command -v node >/dev/null 2>&1; then
    log "node: resolving production dependency set"
    _npmtmp=$(mktemp -d)
    cp package.json "$_npmtmp/" 2>/dev/null
    # Copy a committed lockfile too so the prod resolve pins the same versions cdxgen sees.
    [ -f package-lock.json ] && cp package-lock.json "$_npmtmp/" 2>/dev/null
    # Without one (a yarn, pnpm or bun project), npm resolves package.json's
    # ranges to the newest releases while cdxgen reads the project's own lock,
    # so the versions differ and a version match would drop the production
    # packages themselves (measured: lodash 4.17.20 from yarn.lock, 4.17.21 from
    # npm, "kept 0 of 1"). The set is then compared by name only. An
    # npm-shrinkwrap.json alone counts the same: it is not copied, so npm's
    # versions would not be its versions. Name matching has known limits: a
    # dev tool sharing a name with a production package is kept, and a package
    # only an older locked version needs can be dropped.
    _node_by_name=""
    [ -f package-lock.json ] || _node_by_name=1
    _nodeset=$(mktemp)
    if prep_step npm-production-set "$PREP_TIMEOUT_DEFAULT" sh -c "cd \"$_npmtmp\" && npm install --omit=dev --package-lock-only --no-audit --no-fund --ignore-scripts" >/dev/null \
       && [ -f "$_npmtmp/package-lock.json" ]; then
        # Emit name@version for every non-dev node_modules entry in the resolved lockfile.
        node -e '
          const fs=require("fs");
          let lock; try { lock=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); } catch(e){ process.exit(0); }
          const pkgs=lock.packages||{}, out=[];
          for (const [k,v] of Object.entries(pkgs)) {
            if (!k.startsWith("node_modules/")) continue;
            if (v.dev===true || !v.version) continue;
            const name=k.replace(/^.*node_modules\//,"");
            out.push(process.argv[2]==="name" ? name : name+"@"+v.version);
          }
          const set=[...new Set(out)];
          process.stdout.write(set.join("\n")+(set.length?"\n":""));
        ' "$_npmtmp/package-lock.json" "${_node_by_name:+name}" > "$_nodeset" 2>/dev/null
    fi
    if [ -s "$_nodeset" ]; then
        NODE_PROD_SET="$_nodeset"
        log "node: production set = $(wc -l < "$_nodeset" | tr -d ' ') components${_node_by_name:+ (matched by name: no package-lock.json)}"
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
# conda: cdxgen has no conda cataloger and does not know environment.yml at
# all (confirmed: neither `--type conda` against the file nor against a
# synthesized conda-meta/ install directory produces anything -- this image
# has no conda/mamba binary for it to shell out to). Left alone, cdxgen's
# python auto-detection reads whatever OTHER python manifest happens to sit
# in the same tree (setup.py, requirements.txt, ...) instead, which can be
# actively wrong rather than merely incomplete: measured on a real project,
# an unpinned setup.py install_requires resolved to that day's PyPI latest,
# with zero overlap against what environment.yml actually pins (see
# identify-conda.py's own header for the full account). Parse environment.yml
# here, before cdxgen runs, and only silence cdxgen's python cataloger when
# our own parse actually produced something to use instead -- a parse that
# comes back empty (no environment.yml, or one that does not match the shape
# identify-conda.py knows) leaves cdxgen's python step running exactly as
# before, since an inaccurate python-derived SBOM still beats an empty one.
CONDA_ENV_FILE=""
[ -f "environment.yml" ] && CONDA_ENV_FILE="environment.yml"
[ -z "$CONDA_ENV_FILE" ] && [ -f "environment.yaml" ] && CONDA_ENV_FILE="environment.yaml"
if [ -n "$CONDA_ENV_FILE" ] && command -v python3 >/dev/null 2>&1; then
    CONDA_SBOM="${OUT%_bom.json}_conda.cdx.json"
    # Written at the version cdxgen is asked for below.
    if CYCLONEDX_SPEC_VERSION="$SPEC" python3 /tmp/identify-conda.py "$SRC" "$CONDA_SBOM" "${PROJECT_VERSION:-unknown}"; then
        CONDA_N=$(node -e '
            try { const d = require(process.argv[1]); process.stdout.write(String((d.components||[]).length)); }
            catch (e) { process.stdout.write("0"); }
        ' "$CONDA_SBOM" 2>/dev/null || echo 0)
        if [ "${CONDA_N:-0}" -gt 0 ]; then
            log "conda: $CONDA_ENV_FILE parsed ($CONDA_N components); excluding cdxgen's python cataloger"
            set -- "$@" --exclude-type python
        else
            log "conda: $CONDA_ENV_FILE present but not parsed; leaving cdxgen's python cataloger as-is"
        fi
    fi
fi
# Non-shipped trees: leave out manifests under test, fixture, example,
# benchmark and demo folders, the GitHub Actions workflows and the Gradle
# wrapper -- none of it ships with the product. NON_SHIPPED_DIRS/EXCLUDE_NON_SHIPPED are defined
# near the top of this file (ahead of every ecosystem block, including the
# lock-evidence checks that also read them); this is just where they get
# turned into cdxgen's own --exclude flags.
if [ -n "$EXCLUDE_NON_SHIPPED" ]; then
    for _d in $NON_SHIPPED_DIRS; do set -- "$@" --exclude "**/$_d/**"; done
    for _d in $NON_SHIPPED_PATHS; do set -- "$@" --exclude "**/$_d/**"; done
fi
set -- "$@" "$SRC"

# PHP (Composer) / .NET - cdxgen resolves both directly with no pre-resolve step,
# and neither leaves any signal telling a real resolve apart from a degraded
# one. The only positive lock evidence available for them is a committed
# lockfile, checked the same way as Swift's Package.resolved check above (both
# use _lock_evidence_found, defined near the top of this file): a recursive,
# pruned existence check, not a command that can fail. Recursive, not
# root-only: a PHP monorepo (e.g. one lockfile per component under src/, no
# lockfile at the root) still has cdxgen's `-r` scan resolving everything from
# those nested lockfiles (measured), so a root-only check would call a
# fully-resolved monorepo unknown for no reason.
_lock_evidence_found composer.lock && mark_prep_applied composer-lock-committed
_lock_evidence_found packages.lock.json && mark_prep_applied dotnet-lock-committed

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
              /usr/local/lib/node_modules/@cdxgen/cdxgen/data \
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
    run_supervised cdxgen "$@"
    rc=$?
elif [ -f /opt/cdxgen/bin/cdxgen.js ]; then
    log "cdxgen (/opt/cdxgen/bin/cdxgen.js)"
    run_supervised node /opt/cdxgen/bin/cdxgen.js "$@"
    rc=$?
elif [ -f /opt/bin/cdxgen ]; then
    log "cdxgen (/opt/bin/cdxgen)"
    run_supervised /opt/bin/cdxgen "$@"
    rc=$?
else
    echo "[build-prep] ERROR: cdxgen not found in image" >&2
    exit 1
fi

# Poetry with no lock file, second half. With pyproject.toml present cdxgen
# takes the Poetry route (`poetry install`, which this image lacks) and never
# reads the requirements.txt written above for the dependency tree: the pins
# came through as components, with no link from the project root and none of
# their own dependencies. cdxgen reads a requirements.txt on its own fully
# (root link and dependencies), so it is run once more on a scratch folder
# holding only that file, and its dependency graph is added to the SBOM:
# components it found that the SBOM lacks, their dependencies, and the root's
# links to the pins. The source tree is not touched. Recorded as poetry-graph;
# when that run fails or finds nothing (no network, for one) the SBOM stays as
# the first run left it and poetry-graph is recorded as failed, so the graph is
# not declared complete. Not when conda took over the python cataloger above.
if [ -n "${POETRY_REQUIREMENTS_WRITTEN:-}" ] && [ "${CONDA_N:-0}" -eq 0 ] 2>/dev/null \
   && [ "${rc:-1}" -eq 0 ] && [ -f "$OUT" ] \
   && [ -f requirements.txt ] && command -v node >/dev/null 2>&1; then
    mark_prep_applied poetry-graph
    _pg_ok=""
    _pg_dir=$(mktemp -d 2>/dev/null) || _pg_dir=""
    if [ -z "$_pg_dir" ] || ! mkdir -p "$_pg_dir/project" || ! cp requirements.txt "$_pg_dir/project/"; then
        log "poetry: dependency graph not resolved (could not prepare a scratch folder)"
    else
        if command -v cdxgen >/dev/null 2>&1; then _pg_cmd="cdxgen"
        elif [ -f /opt/cdxgen/bin/cdxgen.js ]; then _pg_cmd="node /opt/cdxgen/bin/cdxgen.js"
        else _pg_cmd="/opt/bin/cdxgen"
        fi
        log "poetry: resolving the dependency graph of the exact pins (cdxgen on requirements.txt alone)"
        # shellcheck disable=SC2086  # _pg_cmd is a command and its script path
        run_supervised_timeout "$PREP_TIMEOUT_DEFAULT" $_pg_cmd -r -t python --spec-version "$SPEC" \
            -o "$_pg_dir/graph.json" "$_pg_dir/project" > "$_pg_dir/log" 2>&1
        _pg_rc=$?
        if [ "$_pg_rc" -eq 0 ] && [ -s "$_pg_dir/graph.json" ]; then
            node - "$OUT" "$_pg_dir/graph.json" "$(basename "$_pg_dir")" <<'POETRY_GRAPH_JS'
const fs = require("fs");
const [outPath, graphPath, scratchName] = process.argv.slice(2);
let main, graph;
try { main = JSON.parse(fs.readFileSync(outPath, "utf8")); }
catch (e) { process.stderr.write("[build-prep] poetry: could not read the SBOM: " + e.message + "\n"); process.exit(1); }
try { graph = JSON.parse(fs.readFileSync(graphPath, "utf8")); }
catch (e) { process.stderr.write("[build-prep] poetry: could not read the second run's SBOM: " + e.message + "\n"); process.exit(1); }
const mainRoot = main.metadata && main.metadata.component && main.metadata.component["bom-ref"];
const graphRoot = graph.metadata && graph.metadata.component && graph.metadata.component["bom-ref"];
const rootEntry = (graph.dependencies || []).find(d => d.ref === graphRoot);
const graphRefs = new Set((graph.components || []).map(c => c["bom-ref"]).filter(Boolean));
const rootLinks = (rootEntry ? (rootEntry.dependsOn || []) : []).filter(r => graphRefs.has(r));
if (!mainRoot || !rootLinks.length) {
  process.stderr.write("[build-prep] poetry: the second run found no dependency graph; SBOM left as it was\n");
  process.exit(2);
}
// File locations name the scratch copy of requirements.txt, written absolute
// or relative; the file sits at the top of the source tree, which is what
// the first run writes too.
const scratchPath = new RegExp("[^\"]*" + scratchName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "/project/", "g");
const clean = c => JSON.parse(JSON.stringify(c).replace(scratchPath, ""));
// bom-refs anywhere in the SBOM, nested components included.
const have = new Set();
const walk = list => { for (const c of list || []) { if (c["bom-ref"]) have.add(c["bom-ref"]); walk(c.components); } };
main.components = main.components || [];
walk(main.components);
let added = 0;
for (const c of graph.components || []) {
  if (!c["bom-ref"] || have.has(c["bom-ref"])) continue;
  main.components.push(clean(c));
  have.add(c["bom-ref"]);
  added++;
}
main.dependencies = main.dependencies || [];
const byRef = new Map(main.dependencies.map(d => [d.ref, d]));
let edges = 0;
const link = (ref, targets) => {
  targets = targets.filter(t => have.has(t));
  let d = byRef.get(ref);
  if (!d) { d = { ref, dependsOn: [] }; main.dependencies.push(d); byRef.set(ref, d); }
  const before = (d.dependsOn || []).length;
  d.dependsOn = [...new Set([...(d.dependsOn || []), ...targets])].sort();
  edges += d.dependsOn.length - before;
};
for (const d of graph.dependencies || []) {
  if (d.ref === graphRoot || !have.has(d.ref)) continue;
  link(d.ref, d.dependsOn || []);
}
link(mainRoot, rootLinks);
// Written next to the SBOM and moved over it, so a failed write cannot leave
// it cut short.
try {
  fs.writeFileSync(outPath + ".poetry-graph.tmp", JSON.stringify(main, null, 2));
  fs.renameSync(outPath + ".poetry-graph.tmp", outPath);
} catch (e) {
  process.stderr.write("[build-prep] poetry: could not write the SBOM: " + e.message + "\n");
  process.exit(1);
}
process.stderr.write("[build-prep] poetry: dependency graph added (" + added + " component(s), " + edges + " new edge(s))\n");
POETRY_GRAPH_JS
            [ $? -eq 0 ] && _pg_ok=1
            rm -f "$OUT.poetry-graph.tmp"
        else
            log "poetry: dependency graph not resolved (cdxgen on requirements.txt exited $_pg_rc); the pins stay without their dependencies"
        fi
        # Why the second run gave nothing (offline, cdxgen exits 0 with an
        # empty graph): the end of its own log.
        [ -n "$_pg_ok" ] || tail -5 "$_pg_dir/log" 2>/dev/null | sed 's/^/[build-prep]   /' >&2
    fi
    [ -n "$_pg_ok" ] || mark_prep_failed poetry-graph
    [ -z "$_pg_dir" ] || rm -rf "$_pg_dir"
    _pg_dir=""
fi

# cdxgen's pyproject.toml route reads its own virtual environment when it
# cannot install the project, and writes a package it could not name there
# as pkg:pypi/unknown@latest, linked from the root. It is no package of the
# project: a real one has a version. Dropped with every link to it, after the
# Poetry graph above so that cannot bring it back, and the count kept on the
# SBOM (bomlens:unnamed-packages-dropped) so the result manifest says that
# something cdxgen saw could not be named.
if [ "${rc:-1}" -eq 0 ] && [ -f "$OUT" ] && command -v node >/dev/null 2>&1 \
   && grep -q '"pkg:pypi/unknown@latest"' "$OUT" 2>/dev/null; then
    node - "$OUT" <<'PYPI_UNKNOWN_JS' || log "python: could not drop pkg:pypi/unknown@latest (non-fatal)"
const fs = require("fs");
const p = process.argv[2];
const bom = JSON.parse(fs.readFileSync(p, "utf8"));
const ref = "pkg:pypi/unknown@latest";
const root = (bom.metadata && bom.metadata.component) || {};
// A project cdxgen itself could only call that is left alone.
if (root.purl === ref || root["bom-ref"] === ref) process.exit(0);
const gone = new Set([ref]);
let dropped = 0;
const keep = list => (list || []).filter(c => {
  if (c.purl === ref || c["bom-ref"] === ref) {
    if (c["bom-ref"]) gone.add(c["bom-ref"]);
    dropped++;
    return false;
  }
  if (c.components) c.components = keep(c.components);
  return true;
});
bom.components = keep(bom.components);
let links = 0;
bom.dependencies = (bom.dependencies || []).filter(d => !gone.has(d.ref) || (links++, false))
  .map(d => {
    const on = (d.dependsOn || []).filter(x => !gone.has(x));
    links += (d.dependsOn || []).length - on.length;
    return { ...d, dependsOn: on };
  });
if (dropped === 0 && links === 0) process.exit(0);
if (dropped > 0) {
  bom.metadata = bom.metadata || {};
  bom.metadata.properties = (bom.metadata.properties || []).filter(x => x.name !== "bomlens:unnamed-packages-dropped");
  bom.metadata.properties.push({ name: "bomlens:unnamed-packages-dropped", value: String(dropped) });
}
fs.writeFileSync(p + ".unknown.tmp", JSON.stringify(bom, null, 2));
fs.renameSync(p + ".unknown.tmp", p);
process.stderr.write("[build-prep] python: dropped pkg:pypi/unknown@latest (" + dropped + " component(s), " + links + " link(s)), a package cdxgen could not name in its own environment\n");
PYPI_UNKNOWN_JS
    rm -f "$OUT.unknown.tmp"
fi

# Rust licenses. cdxgen reads only Cargo.lock for a Rust project, and a lock file
# carries no license, so nearly every crate came through without one. `cargo
# metadata` downloads the crates and reports each one's declared license, so the
# gap is filled from that: a component with no license takes the license its crate
# declares in its own Cargo.toml (a workspace member or path crate included, whose
# manifest is local). A license the SBOM already has is never replaced, a crate
# that declares none stays empty, and every value set is stamped
# bomlens:licenseSource. Cargo's older "MIT/Apache-2.0" spelling is written as an
# SPDX expression, and a value that is not one (or names an id that is not on the
# SPDX list) is kept as a plain license name. With no route to the registry `cargo
# metadata` fails: the step is recorded as failed on the SBOM below, and the
# licenses stay as cdxgen left them. It runs before that recording so a failure
# reaches the SBOM. FETCH_LICENSE=false (the switch that turns off network license
# lookups, also set by --byte-stable) skips it; so does BOMLENS_NO_CARGO_LICENSE=1
# (or true). Unlike the workspace-member filter further down, which uses
# --no-deps --offline to avoid it, this needs the crates' sources, so it costs a
# download (about 8 seconds for 150 crates).
if opted_out "${BOMLENS_NO_CARGO_LICENSE:-}"; then
    log "cargo: license pass off (BOMLENS_NO_CARGO_LICENSE)"
elif [ "${FETCH_LICENSE:-true}" = "false" ]; then
    log "cargo: license pass off (FETCH_LICENSE=false)"
elif [ "${rc:-1}" -eq 0 ] && [ -f Cargo.toml ] && [ -f "$OUT" ] \
     && command -v node >/dev/null 2>&1 && command -v cargo >/dev/null 2>&1 \
     && grep -q '"pkg:cargo/' "$OUT" 2>/dev/null; then
    log "cargo: reading the licenses crates declare (cargo metadata)"
    _clmeta=$(mktemp)
    if prep_step cargo-license-metadata "$PREP_TIMEOUT_DEFAULT" sh -c 'cargo metadata --format-version 1 > "$1"' _ "$_clmeta" \
       && [ -s "$_clmeta" ]; then
        _clspdx=""
        for _c in /opt/cdxgen/data /opt/bin/data \
                  /usr/local/lib/node_modules/@cdxgen/cdxgen/data \
                  /usr/local/lib/node_modules/@cyclonedx/cdxgen/data; do
            [ -f "$_c/spdx-licenses.json" ] && { _clspdx="$_c/spdx-licenses.json"; break; }
        done
        _cljs=$(mktemp)
        cat > "$_cljs" <<'CARGO_LIC'
const fs = require('fs');
const [bomPath, metaPath] = process.argv.slice(2);
let bom, meta;
try { bom = JSON.parse(fs.readFileSync(bomPath, 'utf8')); } catch (e) { process.exit(0); }
try { meta = JSON.parse(fs.readFileSync(metaPath, 'utf8')); } catch (e) { process.exit(0); }
if (!Array.isArray(bom.components) || !Array.isArray(meta.packages)) process.exit(0);

// The SPDX ids (and exceptions) cdxgen ships. Without the list nothing can be
// vouched for as an id, so every value is kept as a plain license name.
let known = new Set();
try {
  const list = JSON.parse(fs.readFileSync(process.env.BOMLENS_SPDX_LIST || '', 'utf8'));
  if (Array.isArray(list)) known = new Set(list);
} catch (e) { /* no list */ }

// name@version -> the license the crate declares (path and workspace crates too).
const declared = new Map();
for (const p of meta.packages) {
  if (p.name && p.version && typeof p.license === 'string' && p.license.trim()) {
    declared.set(p.name + '@' + p.version, p.license.trim());
  }
}

// Cargo's older spelling separates alternatives with a slash: "MIT/Apache-2.0".
// Free text that merely contains a slash (a URL) is left alone.
const ID = '[A-Za-z0-9.+-]+';
function spdx(text) {
  const t = text.replace(/\s+/g, ' ');
  return new RegExp('^' + ID + '( ?/ ?' + ID + ')+$').test(t) ? t.replace(/ ?\/ ?/g, ' OR ') : t;
}
// An SPDX expression alternates ids and OR/AND/WITH, every id on the SPDX list.
function tokens(t) {
  const tok = t.replace(/[()]/g, ' ').trim().split(/\s+/);
  const ok = tok.length % 2 === 1 && tok.every((w, i) => i % 2 === 1
    ? /^(OR|AND|WITH)$/.test(w) : known.has(w.replace(/\+$/, '')));
  return ok ? tok : null;
}
// A flat OR (or AND) list is written in a fixed order, so the same pair of
// licenses is one entry in the NOTICE whichever way a crate spells it.
function ordered(t, tok) {
  if (/[()]/.test(t)) return t;
  const ops = new Set(tok.filter((w, i) => i % 2 === 1));
  if (ops.size !== 1 || ops.has('WITH')) return t;
  const words = tok.filter((w, i) => i % 2 === 0).sort();
  return words.join(' ' + [...ops][0] + ' ');
}
function licenseEntry(text) {
  const t = spdx(text);
  const tok = tokens(t);
  if (!tok) return { license: { name: t } };
  if (tok.length === 1) return known.has(tok[0]) ? { license: { id: tok[0] } } : { expression: tok[0] };
  return { expression: ordered(t, tok) };
}
// Any evidence at all (an id, name, expression, url or text) means the component
// already has a license and is left alone; a malformed field is left alone too.
const hasLicense = c => c.licenses !== undefined && (!Array.isArray(c.licenses)
  || c.licenses.some(e => e && (e.expression
    || (e.license && (e.license.id || e.license.name || e.license.url || e.license.text)))));

let changed = 0;
for (const c of bom.components) {
  if (!String(c.purl || '').startsWith('pkg:cargo/') || hasLicense(c)) continue;
  const text = declared.get(c.name + '@' + c.version);
  if (!text) continue;
  c.licenses = [licenseEntry(text)];
  c.properties = (c.properties || []).filter(p => p.name !== 'bomlens:licenseSource')
    .concat([{ name: 'bomlens:licenseSource', value: 'cargo metadata' }]);
  changed++;
}
if (changed) {
  fs.writeFileSync(bomPath, JSON.stringify(bom, null, 2));
  process.stderr.write('[build-prep] cargo: filled ' + changed + ' component license(s) from the crates\' own manifests\n');
}
CARGO_LIC
        BOMLENS_SPDX_LIST="$_clspdx" node "$_cljs" "$OUT" "$_clmeta" || log "cargo: license pass skipped (non-fatal)"
        rm -f "$_cljs"
    else
        log "cargo: could not read crate licenses (cargo metadata failed, is the registry reachable?); licenses left as the generator resolved them"
    fi
    rm -f "$_clmeta"
fi

# Record each prep_step that failed or timed out (PREP_FAILED, space-separated
# labels) on the SBOM, one bomlens:pipeline-step-failed property per label,
# the same shape docker/lib/pipeline-step.sh's mark_pipeline_warning writes.
# This file is bind-mounted alone (see the header comment), so the property is
# appended inline with node rather than sourcing that script.
if [ "${rc:-1}" -eq 0 ] && [ -n "$PREP_FAILED" ] && [ -f "$OUT" ] && command -v node >/dev/null 2>&1; then
    _pf=$(mktemp).js
    cat > "$_pf" <<'PREPFAIL_JS'
const fs = require('fs');
const [bomPath, labels] = process.argv.slice(2);
let bom;
try { bom = JSON.parse(fs.readFileSync(bomPath, 'utf8')); } catch (e) { process.exit(0); }
bom.metadata = bom.metadata || {};
const props = bom.metadata.properties || [];
const list = labels.split(' ').filter(Boolean);
for (const label of list) {
  props.push({ name: 'bomlens:pipeline-step-failed', value: label });
}
bom.metadata.properties = props;
fs.writeFileSync(bomPath, JSON.stringify(bom, null, 2));
process.stderr.write('[build-prep] recorded ' + list.length + ' failed preprocessing step(s) on the SBOM: ' + list.join(', ') + '\n');
PREPFAIL_JS
    node "$_pf" "$OUT" "$PREP_FAILED" || log "prep-failed: recording skipped (non-fatal)"
    rm -f "$_pf"
fi

# Record every prep_step this scan actually called (PREP_APPLIED, space-separated
# labels, success or failure) on the SBOM, one bomlens:prep-step-applied property
# per label -- the "this ecosystem's lock step ran here" signal a reader combines
# with the absence of the matching bomlens:pipeline-step-failed label above to
# tell "resolved" apart from "never applicable" when compositions.aggregate is
# later decided from this SBOM's properties.
if [ "${rc:-1}" -eq 0 ] && [ -n "$PREP_APPLIED" ] && [ -f "$OUT" ] && command -v node >/dev/null 2>&1; then
    _pa=$(mktemp).js
    cat > "$_pa" <<'PREPAPPLIED_JS'
const fs = require('fs');
const [bomPath, labels] = process.argv.slice(2);
let bom;
try { bom = JSON.parse(fs.readFileSync(bomPath, 'utf8')); } catch (e) { process.exit(0); }
bom.metadata = bom.metadata || {};
const props = bom.metadata.properties || [];
const list = labels.split(' ').filter(Boolean);
for (const label of list) {
  props.push({ name: 'bomlens:prep-step-applied', value: label });
}
bom.metadata.properties = props;
fs.writeFileSync(bomPath, JSON.stringify(bom, null, 2));
process.stderr.write('[build-prep] recorded ' + list.length + ' applied preprocessing step(s) on the SBOM: ' + list.join(', ') + '\n');
PREPAPPLIED_JS
    node "$_pa" "$OUT" "$PREP_APPLIED" || log "prep-applied: recording skipped (non-fatal)"
    rm -f "$_pa"
fi

# Install-directory filter. cdxgen 13.3.x and later (the nightly-rebuilt v13
# images since 2026-10-05) report every directory holding a LICENSE or COPYING
# file as an unversioned pkg:generic component (cdx:vendored:path), and every
# CMake subproject as another (cdx:cmake:subprojectDir). Under a package
# manager's install directory (node_modules/, Composer's or Go's vendor/,
# SwiftPM's .build/, CocoaPods' Pods/, a Python virtualenv ...) each of those is
# a package the ecosystem's own cataloger already reported with its name and
# version, so it only doubled the list (examples/nodejs went from 120 to 554
# components). Drop those, and their dependency entries. A directory in the
# project's own tree (third_party/zlib, a C project's vendor/ with no package
# manager behind it) is real vendored code and stays. BomLens's own vendored
# identification runs later and marks its results bomlens:layer=vendored, so it
# is not affected by this.
if [ "${rc:-1}" -eq 0 ] && [ -f "$OUT" ] && command -v node >/dev/null 2>&1; then
    _idb=$(mktemp)
    _idf="$_idb.js"
    cat > "$_idf" <<'INSTDIR_JS'
const fs = require('fs');
const path = require('path');
const [bomPath, root] = process.argv.slice(2);
let bom;
try { bom = JSON.parse(fs.readFileSync(bomPath, 'utf8')); } catch (e) { process.exit(0); }
if (!Array.isArray(bom.components)) process.exit(0);
// Directory names that only ever hold what a package manager installed.
const ALWAYS = new Set(['node_modules', 'bower_components', 'jspm_packages', '.build',
  'Pods', 'Carthage', '.venv', 'site-packages', 'dist-packages', '__pypackages__',
  '.tox', '.gradle', '.m2']);
const exists = p => { try { fs.statSync(p); return true; } catch (e) { return false; } };
// vendor/ is an install directory only when a package manager owns it:
// Composer (composer.json next to it, or its autoloader inside), Go
// (vendor/modules.txt) or Bundler (vendor/bundle).
const managedVendor = (parent, next) => {
  const base = path.join(root || '.', ...parent);
  return next === 'bundle'
    || exists(path.join(base, 'composer.json')) || exists(path.join(base, 'composer.lock'))
    || exists(path.join(base, 'vendor', 'autoload.php'))
    || exists(path.join(base, 'vendor', 'composer', 'installed.json'))
    || exists(path.join(base, 'vendor', 'modules.txt'));
};
const underInstallDir = v => {
  const seg = String(v || '').replace(/\\/g, '/').replace(/^\.\//, '').split('/').filter(Boolean);
  for (let i = 0; i < seg.length; i++) {
    if (ALWAYS.has(seg[i])) return true;
    if (seg[i] === 'vendor' && managedVendor(seg.slice(0, i), seg[i + 1])) return true;
  }
  return false;
};
const drop = c => (c.properties || []).some(p =>
  (p.name === 'cdx:vendored:path' || p.name === 'cdx:cmake:subprojectDir') && underInstallDir(p.value));
const before = bom.components.length;
const dropped = new Set();
bom.components = bom.components.filter(c => {
  if (!drop(c)) return true;
  if (c['bom-ref']) dropped.add(c['bom-ref']);
  if (c.purl) dropped.add(c.purl);
  return false;
});
if (bom.components.length === before) process.exit(0);
const refOf = c => c['bom-ref'] || c.purl;
const kept = new Set(bom.components.map(refOf));
const gone = r => dropped.has(r) && !kept.has(r);
if (Array.isArray(bom.dependencies)) {
  bom.dependencies = bom.dependencies
    .filter(d => !gone(d.ref))
    .map(d => Array.isArray(d.dependsOn)
      ? Object.assign({}, d, { dependsOn: d.dependsOn.filter(r => !gone(r)) })
      : d);
}
fs.writeFileSync(bomPath, JSON.stringify(bom, null, 2));
process.stderr.write('[build-prep] dropped ' + (before - bom.components.length)
  + ' license-file/subproject component(s) found inside package-manager install directories\n');
INSTDIR_JS
    node "$_idf" "$OUT" "$SRC" || log "install-dir filter skipped (non-fatal)"
    rm -f "$_idb" "$_idf"
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
// A set written by name only (no package-lock.json to pin versions) holds no
// '@' after the first character; match those by name.
const byName = [...prod].every(e => e.lastIndexOf('@') <= 0);
const keep = c => {
  if (!(c.purl || '').startsWith('pkg:npm/')) return true;   // non-npm: leave alone
  return byName ? prod.has(nameOf(c)) : prod.has(nameOf(c) + '@' + (c.version || ''));
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

# npm workspace-member filter: the file-level exclusion above (the --exclude
# globs built from NON_SHIPPED_DIRS) does not reach an npm workspace member
# registered in package-lock.json, since cdxgen reads that file directly. A
# member whose own directory sits under an excluded tree is dropped, along
# with a dependency only that member reaches (any way at all -- dependencies,
# devDependencies and optionalDependencies alike), unless a kept member
# reaches it too. BOMLENS_INCLUDE_NON_SHIPPED=1 (the same switch the
# file-level exclusion above uses) opts out.
#
# Reads package-lock.json's own "packages" map directly: a workspace member
# is any key that is not the root ("") and does not contain "node_modules/"
# -- the same distinction Cargo.lock draws between a path member (no
# `source`) and a registry crate (`source` present), just expressed in
# npm's own lockfile shape. Resolving one package's dependency name to the
# entry it actually gets replays npm's own directory-nesting resolution
# (walk up from the requiring package's own key, node_modules at a time,
# same as Node's own runtime `require` resolution) rather than trusting a
# declared semver range, and follows a workspace member's own `"link":
# true` node_modules entry through to its real packages/... key. A name
# that resolves nowhere is common and expected here (an optional or
# platform-specific dependency simply not installed) and is just not
# traversed further, unlike Cargo.lock, where every declared dependency
# item is a byte someone else's tooling wrote and MUST resolve, so a miss
# there means the parse itself is wrong.
if [ "${rc:-1}" -eq 0 ] && [ -f package.json ] && [ -f package-lock.json ] \
   && [ -n "$EXCLUDE_NON_SHIPPED" ] \
   && [ -f "$OUT" ] && command -v node >/dev/null 2>&1; then
    _nwmf=$(mktemp).js
    cat > "$_nwmf" <<'NWMF_JS'
const fs = require('fs');
const path = require('path');
const [bomPath, lockPath, dirsStr] = process.argv.slice(2);
let bom;
try { bom = JSON.parse(fs.readFileSync(bomPath, 'utf8')); } catch (e) { process.exit(0); }
if (!Array.isArray(bom.components) || !Array.isArray(bom.dependencies)) process.exit(0);

const LOCK_MAX_BYTES = 16 * 1024 * 1024;
const BUDGET_MS = 3000;
let lockText;
try {
  const st = fs.statSync(lockPath);
  if (st.size > LOCK_MAX_BYTES) process.exit(0);
  lockText = fs.readFileSync(lockPath, 'utf8');
} catch (e) { process.exit(0); }
let lock;
try { lock = JSON.parse(lockText); } catch (e) { process.exit(0); }
if (lock.lockfileVersion !== 2 && lock.lockfileVersion !== 3) process.exit(0);
const packages = lock.packages;
if (!packages || typeof packages !== 'object') process.exit(0);

const deadline = Date.now() + BUDGET_MS;
let steps = 0;
function overBudget() { return (++steps & 0xfff) === 0 && Date.now() > deadline; }

const NON_SHIPPED_DIRS = new Set((dirsStr || '').split(/\s+/).filter(Boolean));
const keys = Object.keys(packages);
const isMember = k => k !== '' && !k.includes('node_modules/');
const memberKeys = keys.filter(isMember);
if (memberKeys.length === 0) process.exit(0);

function underExcludedTree(key) {
  return key.split('/').some(seg => NON_SHIPPED_DIRS.has(seg));
}
const excludedMembers = memberKeys.filter(underExcludedTree);
if (excludedMembers.length === 0) process.exit(0);
const keptMembers = memberKeys.filter(k => !underExcludedTree(k));
if (keptMembers.length === 0) process.exit(0);

// Resolve a link entry (a workspace member's own node_modules alias) through
// to the real packages/... key it points at.
function resolveLink(key) {
  let cur = key;
  let hops = 0;
  while (packages[cur] && packages[cur].link && typeof packages[cur].resolved === 'string') {
    if (++hops > 20) return null;   // a link cycle: cannot determine
    cur = packages[cur].resolved;
  }
  return packages[cur] ? cur : null;
}

// Every "node_modules/<name>" suffix anywhere in the lockfile, regardless of
// which directory it hangs off of -- whether a declared dependency has any
// installation trace at all, not just one reachable via the walk-up below.
const installedNames = new Set();
for (const k of keys) {
  const i = k.lastIndexOf('node_modules/');
  if (i !== -1) installedNames.add(k.slice(i + 'node_modules/'.length));
}

function isOptionalDecl(entry, name) {
  if (entry.optionalDependencies && Object.prototype.hasOwnProperty.call(entry.optionalDependencies, name)) return true;
  const pm = entry.peerDependenciesMeta;
  return !!(pm && pm[name] && pm[name].optional === true);
}

function depNamesOf(entry) {
  return Object.keys(Object.assign({},
    entry.dependencies, entry.devDependencies, entry.optionalDependencies, entry.peerDependencies));
}

function resolveDep(fromKey, name) {
  let dir = fromKey;
  for (;;) {
    const candidate = dir === '' ? 'node_modules/' + name : dir + '/node_modules/' + name;
    if (packages[candidate]) return resolveLink(candidate);
    if (dir === '') return null;
    const idx = dir.lastIndexOf('/');
    dir = idx === -1 ? '' : dir.slice(0, idx);
  }
}

// adj holds only the edges that resolved. unresolved holds, per key, the
// declared names that did not -- except an optional (or optional peer) one
// with no installation trace anywhere, which is simply not installed and
// carries no risk either way. A name that failed to resolve is not dropped
// silently: whichever BFS below actually walks through the key that
// declared it decides what that means for the filter (see the comment on
// the kept-side walk).
const adj = new Map();
const unresolved = new Map();
for (const k of keys) {
  if (overBudget()) process.exit(0);
  const entry = packages[k];
  if (!entry || (entry.link && typeof entry.resolved === 'string')) continue;   // links carry no deps of their own
  const targets = [];
  const missing = [];
  for (const name of depNamesOf(entry)) {
    const t = resolveDep(k, name);
    if (t) { targets.push(t); continue; }
    if (isOptionalDecl(entry, name) && !installedNames.has(name)) continue;   // never installed anywhere: not a gap
    missing.push(name);
  }
  adj.set(k, targets);
  if (missing.length) unresolved.set(k, missing);
}

function bfs(starts) {
  const seen = new Set(starts);
  const queue = starts.slice();
  while (queue.length) {
    if (overBudget()) return null;
    const cur = queue.shift();
    for (const next of (adj.get(cur) || [])) if (!seen.has(next)) { seen.add(next); queue.push(next); }
  }
  return seen;
}
const reachedFromKeep = bfs(keptMembers);
const reachedFromExclude = bfs(excludedMembers);
if (!reachedFromKeep || !reachedFromExclude) process.exit(0);

// A name a kept-reachable package declares but this pass could not resolve
// (something other than an optional dependency never installed at all) is
// not a "this drops" signal and not a "this stays" signal either -- it is a
// missing edge in OUR OWN view of a graph that plainly does reach further,
// since something in the kept tree asked for it. Treat every component
// under that name, wherever it sits, as reachable from a kept root: dropping
// it would risk cutting a component a kept member genuinely uses. An
// unresolved name met walking the excluded side is not given the same
// treatment -- skipping it there only leaves something in the SBOM that
// might not have needed to stay, the safe direction. Too many protected
// names at once means this pass cannot really tell what is going on, so it
// stands down entirely rather than lean on a growing exception list.
const PROTECTED_NAME_LIMIT = 50;
const protectedNames = new Set();
for (const k of reachedFromKeep) {
  for (const name of (unresolved.get(k) || [])) protectedNames.add(name);
}
if (protectedNames.size > PROTECTED_NAME_LIMIT) process.exit(0);

const dropKeys = new Set(excludedMembers);
for (const k of reachedFromExclude) if (!reachedFromKeep.has(k)) dropKeys.add(k);
if (dropKeys.size === 0) process.exit(0);

// purl matching carries name@version, not the installed path, so collapse to
// name@version pairs the same conservative way the Cargo filter does: a pair
// reached from a kept root under ANY of its installed locations counts as
// kept.
function nvOf(k) {
  const entry = packages[k];
  if (!entry) return null;
  const name = entry.name || k.slice(k.lastIndexOf('node_modules/') + 'node_modules/'.length);
  return entry.version ? name + '@' + entry.version : null;
}
const keptNV = new Set([...reachedFromKeep].map(nvOf).filter(Boolean));
const dropNV = new Set();
for (const k of dropKeys) {
  const entry = packages[k];
  if (entry && entry.name && protectedNames.has(entry.name)) continue;   // a kept root's own unresolved edge named this
  const nv = nvOf(k);
  if (nv && !keptNV.has(nv)) dropNV.add(nv);
}
if (dropNV.size === 0) process.exit(0);

const refOf = c => c['bom-ref'] || c.purl;
const nvOfPurl = purl => {
  const m = /^pkg:npm\/([^@]+)@([^?]+)/.exec(purl || '');
  return m ? decodeURIComponent(m[1]) + '@' + decodeURIComponent(m[2]) : null;
};
const droppedPurls = [];
const keep = c => {
  const nv = nvOfPurl(c.purl);
  if (!nv || !dropNV.has(nv)) return true;
  droppedPurls.push(c.purl);
  return false;
};
const before = bom.components.length;
bom.components = bom.components.filter(keep);
if (droppedPurls.length === 0) process.exit(0);

const mc = bom.metadata && bom.metadata.component;
const keptRefs = new Set(bom.components.map(refOf));
if (mc) keptRefs.add(mc['bom-ref'] || mc.purl);
bom.dependencies = bom.dependencies
  .filter(d => keptRefs.has(d.ref))
  .map(d => Array.isArray(d.dependsOn) ? Object.assign({}, d, { dependsOn: d.dependsOn.filter(r => keptRefs.has(r)) }) : d);

function mergeCapped(existing, additions, limit) {
  let shown = [];
  let priorTotal = 0;
  if (existing) {
    const m = /^(.*?)(?: \(\+(\d+) more\))?$/.exec(existing);
    shown = m[1] ? m[1].split(', ').filter(Boolean) : [];
    priorTotal = shown.length + (m[2] ? parseInt(m[2], 10) : 0);
  }
  const merged = shown.concat(additions);
  const total = priorTotal + additions.length;
  let val = merged.slice(0, limit).join(', ');
  const hidden = total - Math.min(limit, merged.length);
  if (hidden > 0) val += ' (+' + hidden + ' more)';
  return val;
}
const LIMIT = 50;
bom.metadata = bom.metadata || {};
const existingProps = bom.metadata.properties || [];
const priorMembers = (existingProps.find(p => p.name === 'bomlens:excluded-members') || {}).value || null;
const priorComponents = (existingProps.find(p => p.name === 'bomlens:excluded-components') || {}).value || null;
const memberList = excludedMembers.map(k => {
  const entry = packages[k];
  const name = (entry && entry.name) || k.split('/').pop();
  return 'npm:' + k + ' (' + name + ')';
});
const props = existingProps.filter(p => p.name !== 'bomlens:excluded-members' && p.name !== 'bomlens:excluded-components');
props.push({ name: 'bomlens:excluded-members', value: mergeCapped(priorMembers, memberList, LIMIT) });
props.push({ name: 'bomlens:excluded-components', value: mergeCapped(priorComponents, droppedPurls, LIMIT) });
bom.metadata.properties = props;

fs.writeFileSync(bomPath, JSON.stringify(bom, null, 2));
process.stderr.write('[build-prep] npm: excluded ' + excludedMembers.length + ' workspace member(s), dropped ' + (before - bom.components.length) + ' of ' + before + ' components\n');
NWMF_JS
    node "$_nwmf" "$OUT" package-lock.json "$NON_SHIPPED_DIRS" || log "npm: workspace-member filter skipped (non-fatal)"
    rm -f "$_nwmf"
fi

# Scope filter (Maven, PHP/Composer): cdxgen tags each component's resolved
# scope itself (Maven: compile/runtime -> required, test -> optional,
# provided/system -> excluded; Composer: require -> required, require-dev ->
# optional). Both ecosystems reduce to the same post-filter: drop the
# non-deployable nodes under the ecosystem's own purl prefix, keeping every
# other component, the app root, and anything cdxgen left unscoped, then prune
# the dependency graph to what remains. Guard: only act when cdxgen actually
# populated scopes (at least one node of that purl prefix marked "required")
# -- the syft fallback path emits no scope, and dropping there would gut the
# BOM, so we leave it untouched and recall never regresses.
run_scope_filter() {
    _sf_purl_prefix="$1"
    _sf_label="$2"
    [ "${rc:-1}" -eq 0 ] || return 0
    [ -f "$OUT" ] || return 0
    command -v node >/dev/null 2>&1 || return 0
    log "$_sf_label: filtering SBOM to deployable scope"
    _sflt=$(mktemp).js
    cat > "$_sflt" <<'SFILTER_JS'
const fs = require('fs');
const [bomPath, purlPrefix] = process.argv.slice(2);
let bom;
try { bom = JSON.parse(fs.readFileSync(bomPath, 'utf8')); } catch (e) { process.exit(0); }
if (!Array.isArray(bom.components)) process.exit(0);
const isTarget = c => (c.purl || '').startsWith(purlPrefix);
const hasScopes = bom.components.some(c => isTarget(c) && c.scope === 'required');
if (!hasScopes) process.exit(0);   // scopes not populated (e.g. syft fallback): leave as-is
const keep = c => !isTarget(c) || (c.scope !== 'optional' && c.scope !== 'excluded');
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
process.stderr.write('[build-prep] ' + purlPrefix + ': kept ' + bom.components.length + ' of ' + before + ' components\n');
SFILTER_JS
    node "$_sflt" "$OUT" "$_sf_purl_prefix" || log "$_sf_label: filter skipped (non-fatal)"
    rm -f "$_sflt"
}
if [ -n "${MAVEN_SCOPE_FILTER:-}" ]; then
    run_scope_filter "pkg:maven/" "maven"
fi
if [ -n "${PHP_SCOPE_FILTER:-}" ]; then
    run_scope_filter "pkg:composer/" "php"
fi

# Development-marker filter: cdxgen marks a development-only component with a
# property of its own ecosystem (npm, pnpm, yarn and bun:
# cdx:npm:package:development=true; uv and Poetry dependency groups:
# cdx:pyproject:group=<group>; Cargo dev-dependencies: cdx:cargo:scope=dev;
# sbt, Crystal and Gleam: their development markers), and the filters above do
# not read those for pnpm workspaces, uv.lock or Poetry. cdxgen marks no Bundler
# group, so for a Gemfile at the scan root the gems declared only in its
# development and test groups are read here (GEMDEV_JS) and count as marked.
# A marker that repeats counts only when every value is a development one. A
# Python package named in the production dependencies of a pyproject.toml is
# not marked, and when those files cannot be read, or a requirements file,
# setup.py, setup.cfg or Pipfile sits outside the non-shipped folders, no
# Python marker is used.
# A marked component, and what only marked components reach, is dropped only
# when nothing else reaches it: the walk starts from the root and from every
# component outside that set, and skips only the edges from the root into a
# marked component (npm markers: from a workspace member too, since cdxgen
# 13.3.0 computes them over the whole workspace, so a package any member's
# production dependencies reach is not marked). An edge from a member into a
# component with any other marker is followed, so what a Cargo or uv workspace
# member lists, its dev-dependencies and dependency groups included, stays.
# The dropped components are recorded in
# bomlens:excluded-components. Guard: the root must be in the dependency graph,
# otherwise nothing is dropped. BOMLENS_INCLUDE_DEV_DEPENDENCIES=1 turns the
# whole filter off; BOMLENS_NODE_FULL_GRAPH=1 keeps the npm-marked components.
if opted_out "${BOMLENS_INCLUDE_DEV_DEPENDENCIES:-}"; then
    log "dev-marker: development dependencies kept (BOMLENS_INCLUDE_DEV_DEPENDENCIES)"
elif [ "${rc:-1}" -eq 0 ] && [ -f "$OUT" ] && command -v node >/dev/null 2>&1; then
    _dvnpm=1
    opted_out "${BOMLENS_NODE_FULL_GRAPH:-}" && _dvnpm=""
    _dvgems=$(mktemp)
    if [ -f Gemfile ]; then
        _gdjs=$(mktemp).js
        cat > "$_gdjs" <<'GEMDEV_JS'
// Reads the gems a Gemfile declares only in its development and test groups.
// A conservative line reader, not Ruby: anything it does not recognise (a
// condition, gemspec, eval_gemfile, a declaration over several lines, a group
// option it cannot read) means nothing is reported. With a Gemfile.lock, every
// name in its DEPENDENCIES must be one the reader saw. The Gemfile must be the
// one Bundler manifest in the tree: another Gemfile or Gemfile.lock below it,
// or a gemspec anywhere, may declare the same gems for production.
const fs = require('fs');
const path = require('path');
const [gemfile, lockfile] = process.argv.slice(2);
const DEV = new Set(['development', 'test']);
const give_up = why => {
  process.stderr.write('[build-prep] ruby: Gemfile groups not read (' + why + '); no gem dropped as development-only\n');
  process.exit(0);
};
const top = path.dirname(gemfile);
// 8 folders deep (a deeper folder means nothing is reported); installed gems,
// packages and virtual environments are not manifests of this project.
const OTHERS_SKIP = new Set(['vendor', 'node_modules', '.git', '.venv', 'venv']);
const others = (dir, depth) => {
  let ents;
  try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return null; }
  for (const e of ents) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (OTHERS_SKIP.has(e.name)) continue;
      if (depth >= 8) give_up(path.relative(top, p) + ' is deeper than 8 folders and was not searched');
      const hit = others(p, depth + 1);
      if (hit) return hit;
    } else if (/\.gemspec$/.test(e.name) || (depth > 0 && (e.name === 'Gemfile' || e.name === 'Gemfile.lock'))) {
      return path.relative(top, p);
    }
  }
  return null;
};
const other = others(top, 0);
if (other) give_up(other + ' found');
let src;
try { src = fs.readFileSync(gemfile, 'utf8'); } catch (e) { process.exit(0); }
const one = /^\s*(?::([A-Za-z_]\w*)|"([^"\\#]*)"|'([^'\\]*)')\s*$/;
const list = s => {
  s = s.trim();
  if (s.startsWith('[')) { if (!s.endsWith(']')) return null; s = s.slice(1, -1); }
  const out = [];
  for (const part of s.split(',')) { const m = one.exec(part); if (!m) return null; out.push(m[1] || m[2] || m[3]); }
  return out.length ? out : null;
};
const stack = [];
const gems = new Map();
const lines = src.split(/\r?\n/);
for (let i = 0; i < lines.length; i++) {
  const line = lines[i].replace(/^\s*#.*$/, '').replace(/\s+#.*$/, '').trim();
  const at = 'line ' + (i + 1);
  if (!line) continue;
  let m;
  if (line === 'end') { if (!stack.length) give_up(at); stack.pop(); continue; }
  if ((m = /^group\s*\(?\s*(.+?)\s*\)?\s+do(\s*\|[^|]*\|)?$/.exec(line))) {
    const g = list(m[1]); if (!g) give_up(at); stack.push(g); continue;
  }
  if (/^(platforms?|source|git|github|path)\b[^{}]*\sdo(\s*\|[^|]*\|)?$/.test(line)) { stack.push([]); continue; }
  if (/^(source|ruby|git_source|plugin)\b/.test(line)) {
    if ((line.match(/\{/g) || []).length !== (line.match(/\}/g) || []).length || /\sdo\b/.test(line)) give_up(at);
    continue;
  }
  if ((m = /^gem\s*\(?\s*(["'])([A-Za-z0-9_.-]+)\1(.*)$/.exec(line))) {
    const rest = m[3];
    if (/[,\\]\s*$/.test(rest) || /\sdo\b|\{/.test(rest)) give_up(at);
    let own = [];
    if (/group/.test(rest)) {
      const o = /(?:\bgroups?:|:groups?\s*=>)\s*(\[[^\]]*\]|:\w+|"[^"]*"|'[^']*')/.exec(rest);
      if (!o) give_up(at);
      own = list(o[1]); if (!own) give_up(at);
    }
    const groups = new Set([].concat(...stack, own));
    if (!groups.size) groups.add('default');
    const name = m[2].toLowerCase();
    const seen = gems.get(name) || new Set();
    for (const g of groups) seen.add(String(g));
    gems.set(name, seen);
    continue;
  }
  give_up(at);
}
if (stack.length) give_up('unclosed block');
if (lockfile && fs.existsSync(lockfile)) {
  let inDeps = false;
  for (const l of fs.readFileSync(lockfile, 'utf8').split(/\r?\n/)) {
    if (/^\S/.test(l)) { inDeps = l.trim() === 'DEPENDENCIES'; continue; }
    if (!inDeps) continue;
    const d = /^ {2}([^\s!(]+)/.exec(l);
    if (d && !gems.has(d[1].toLowerCase())) give_up('Gemfile.lock lists ' + d[1]);
  }
}
const dev = [...gems].filter(([, g]) => [...g].every(x => DEV.has(x))).map(([n]) => n).sort();
if (dev.length) process.stdout.write(dev.join('\n') + '\n');
GEMDEV_JS
        node "$_gdjs" Gemfile Gemfile.lock > "$_dvgems" || : > "$_dvgems"
        rm -f "$_gdjs"
        [ -s "$_dvgems" ] && log "ruby: development/test-only gems in Gemfile: $(tr '\n' ' ' < "$_dvgems")"
    fi
    _dvflt=$(mktemp).js
    cat > "$_dvflt" <<'DEVFILTER_JS'
const fs = require('fs');
const path = require('path');
const [bomPath, npmMarkers, gemListPath, nonShippedDirs] = process.argv.slice(2);
const nonShipped = new Set((nonShippedDirs || '').toLowerCase().split(/\s+/).filter(Boolean));
const say = s => process.stderr.write('[build-prep] dev-marker: ' + s + '\n');
let bom;
try { bom = JSON.parse(fs.readFileSync(bomPath, 'utf8')); } catch (e) { process.exit(0); }
if (!Array.isArray(bom.components) || !Array.isArray(bom.dependencies)) process.exit(0);
const mc = bom.metadata && bom.metadata.component;
const rootRef = mc && (mc['bom-ref'] || mc.purl);
const edges = new Map(bom.dependencies.map(d => [d.ref, Array.isArray(d.dependsOn) ? d.dependsOn : []]));
if (!rootRef || !edges.has(rootRef)) process.exit(0);
let devGems = new Set();
try { devGems = new Set(fs.readFileSync(gemListPath, 'utf8').split('\n').filter(Boolean)); } catch (e) { /* no Gemfile */ }
const purlName = (c, type) => {
  const m = new RegExp('^pkg:' + type + '/([^@?#]+)').exec(c.purl || '');
  try { return m ? decodeURIComponent(m[1]).toLowerCase() : ''; } catch (e) { return ''; }
};
const prop = (c, n) => (c.properties || []).filter(p => p.name === n).map(p => String(p.value));
// A marker can repeat with different values (a crate that is both a dependency
// and a dev-dependency); it counts only when every value is a development one.
const every = (c, n, isDev) => { const v = prop(c, n); return v.length > 0 && v.every(isDev); };

// cdx:pyproject:group says a package is listed in a dependency group, not that
// it is used only there. The production dependencies of every pyproject.toml
// under the root ([project] dependencies and optional-dependencies,
// [tool.poetry.dependencies]) are read with a small reader, not a TOML parser:
// when the root has no pyproject.toml or a file is one it cannot follow, no
// Python marker is used. The walk goes 8 folders deep (a deeper folder outside
// the non-shipped ones means no Python marker is used) and skips vendor,
// node_modules, .git and virtual environments.
const pep503 = s => s.toLowerCase().replace(/[-_.]+/g, '-');
// A requirements file, setup.py, setup.cfg or Pipfile outside the non-shipped
// folders may declare production dependencies this reader does not see, so
// one of them also means no Python marker is used.
const OTHER_PY = /^(requirements[^/]*\.txt|setup\.py|setup\.cfg|Pipfile)$/;
const readPyProd = () => {
  const SKIP = new Set(['node_modules', '.git', '.venv', 'venv', 'vendor', '.tox', '.nox', '__pypackages__', 'site-packages']);
  if (!fs.existsSync('pyproject.toml')) { say('python: no pyproject.toml at the scan root; no Python package dropped as development-only'); return null; }
  const files = [];
  let other = null;
  let deep = null;
  const walk = (dir, depth, shipped) => {
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
    for (const e of ents) {
      if (e.isDirectory()) {
        if (SKIP.has(e.name)) continue;
        const sub = shipped && !nonShipped.has(e.name.toLowerCase());
        if (depth < 8) walk(path.join(dir, e.name), depth + 1, sub);
        else if (sub && !deep) deep = path.join(dir, e.name);
      } else if (e.isFile() && e.name === 'pyproject.toml') files.push(path.join(dir, e.name));
      else if (e.isFile() && shipped && !other && OTHER_PY.test(e.name)) other = path.join(dir, e.name);
    }
  };
  walk('.', 0, true);
  if (deep) { say('python: ' + deep.replace(/^\.\//, '') + ' is deeper than 8 folders and was not searched; no Python package dropped as development-only'); return null; }
  if (other) { say('python: ' + other.replace(/^\.\//, '') + ' may declare production dependencies; no Python package dropped as development-only'); return null; }
  if (files.length > 1000) { say('python: too many pyproject.toml files; no Python package dropped as development-only'); return null; }
  const names = new Set();
  for (const f of files) {
    let text;
    try { text = fs.readFileSync(f, 'utf8'); } catch (e) { return null; }
    const got = pyprojectNames(text);
    if (!got) { say('python: ' + f.replace(/^\.\//, '') + ' not read; no Python package dropped as development-only'); return null; }
    for (const n of got) names.add(n);
  }
  return names;
};
// Key path: dotted segments, bare or quoted.
const keyPath = s => {
  const out = [];
  let rest = s.trim();
  while (rest.length) {
    const m = /^(?:"([^"\\]*)"|'([^']*)'|([A-Za-z0-9_-]+))\s*(?:\.\s*|$)/.exec(rest);
    if (!m) return null;
    out.push(m[1] !== undefined ? m[1] : m[2] !== undefined ? m[2] : m[3]);
    rest = rest.slice(m[0].length);
  }
  return out.length ? out : null;
};
// Reads one value from text[i...]: returns its source and where it ends, or
// null for a value the reader does not follow. Strings, arrays and inline
// tables may span lines; comments outside strings are dropped.
const readValue = (text, i) => {
  let out = '';
  let depth = 0;
  while (i < text.length) {
    const ch = text[i];
    if (text.startsWith('"""', i) || text.startsWith("'''", i)) {
      const q = text.substr(i, 3);
      const end = text.indexOf(q, i + 3);
      if (end < 0) return null;
      out += '""';
      i = end + 3;
      while (text[i] === q[0]) i++;
      continue;
    }
    if (ch === '"' || ch === "'") {
      let j = i + 1;
      while (j < text.length && text[j] !== ch && text[j] !== '\n') j += (ch === '"' && text[j] === '\\') ? 2 : 1;
      if (text[j] !== ch) return null;
      out += text.slice(i, j + 1);
      i = j + 1;
      continue;
    }
    if (ch === '#') { while (i < text.length && text[i] !== '\n') i++; continue; }
    if (ch === '[' || ch === '{') depth++;
    if (ch === ']' || ch === '}') { depth--; if (depth < 0) return null; }
    if (ch === '\n' && depth === 0) break;
    out += ch;
    i++;
  }
  if (depth !== 0) return null;
  return { src: out.trim(), end: i };
};
const stringArray = src => {
  if (!/^\[[\s\S]*\]$/.test(src)) return null;
  let rest = src.slice(1, -1);
  const out = [];
  for (;;) {
    rest = rest.replace(/^\s+/, '');
    if (!rest.length) return out;
    const m = /^(?:"((?:[^"\\\n]|\\.)*)"|'([^'\n]*)')\s*(,|$)/.exec(rest);
    if (!m) return null;
    out.push(m[1] !== undefined ? m[1] : m[2]);
    rest = rest.slice(m[0].length);
  }
};
const pyprojectNames = text => {
  const names = new Set();
  let table = [];
  let i = 0;
  const addReq = s => {
    const m = /^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:[\[(;<>=!~@ ]|$)/.exec(s);
    if (!m) return false;
    names.add(pep503(m[1]));
    return true;
  };
  while (i < text.length) {
    const nl = text.indexOf('\n', i);
    const raw = text.slice(i, nl < 0 ? text.length : nl);
    const line = raw.trim();
    if (!line || line.startsWith('#')) { i = nl < 0 ? text.length : nl + 1; continue; }
    let m;
    if ((m = /^\[\[([^\]]*)\]\]\s*(?:#.*)?$/.exec(line))) {
      table = keyPath(m[1]); if (!table) return null; table = ['[]'].concat(table);
      i = nl < 0 ? text.length : nl + 1; continue;
    }
    if ((m = /^\[([^\]]*)\]\s*(?:#.*)?$/.exec(line))) {
      table = keyPath(m[1]); if (!table) return null;
      i = nl < 0 ? text.length : nl + 1; continue;
    }
    const eq = /^((?:"[^"\\]*"|'[^']*'|[A-Za-z0-9_.\s-])+?)\s*=\s*/.exec(raw.replace(/^\s+/, ''));
    if (!eq) return null;
    const key = keyPath(eq[1]);
    if (!key) return null;
    const v = readValue(text, i + (raw.length - raw.replace(/^\s+/, '').length) + eq[0].length);
    if (!v) return null;
    const full = table.concat(key).join('\u0000');
    const at = p => full === p.join('\u0000');
    const under = p => full.startsWith(p.join('\u0000') + '\u0000') && full.split('\u0000').length === p.length + 1;
    if (at(['project', 'dependencies']) || under(['project', 'optional-dependencies'])) {
      const arr = stringArray(v.src);
      if (!arr) return null;
      for (const s of arr) if (!addReq(s)) return null;
    } else if (at(['project', 'dynamic'])) {
      const arr = stringArray(v.src);
      if (!arr || arr.includes('dependencies') || arr.includes('optional-dependencies')) return null;
    } else if (full.startsWith(['tool', 'poetry', 'dependencies', ''].join('\u0000'))) {
      const k = full.split('\u0000')[3];
      if (k.toLowerCase() !== 'python') names.add(pep503(k));
    } else if (at(['project']) || at(['tool']) || at(['tool', 'poetry']) || at(['tool', 'poetry', 'dependencies'])
        || at(['project', 'optional-dependencies'])) {
      return null; // a whole table written inline
    }
    i = v.end < text.length ? v.end + 1 : text.length;
  }
  return names;
};
const pyMarked = bom.components.some(c => prop(c, 'cdx:pyproject:group').length);
const pyProd = pyMarked ? readPyProd() : null;

const npmDev = c => npmMarkers === '1' && every(c, 'cdx:npm:package:development', v => v === 'true');
const otherDev = c =>
  (pyProd !== null && every(c, 'cdx:pyproject:group', g => g !== 'main') && !pyProd.has(pep503(purlName(c, 'pypi'))))
  || every(c, 'cdx:cargo:scope', v => v === 'dev')
  || every(c, 'cdx:sbt:package:development', v => v === 'true')
  || every(c, 'cdx:crystal:scope', v => v === 'development')
  || every(c, 'cdx:gleam:scope', v => v === 'development')
  || (devGems.size > 0 && devGems.has(purlName(c, 'gem')));
const refOf = c => c['bom-ref'] || c.purl;
const byRef = new Map(bom.components.map(c => [refOf(c), c]));
const npmMarked = new Set(bom.components.filter(npmDev).map(refOf));
const marked = new Set(bom.components.filter(c => npmDev(c) || otherDev(c)).map(refOf));
if (marked.size === 0) process.exit(0);
// The root, a workspace member cdxgen lists only in the graph, and a member it
// lists as an application component declare dependencies; anything else is a
// package depending on another.
const isProject = r => {
  if (r === rootRef) return true;
  const c = byRef.get(r);
  return !c || c.type === 'application'
    || (c.properties || []).some(p => p.name === 'internal:is_workspace' && p.value === 'true');
};
// The development side: the marked components and what they reach. An npm
// package is judged by its own marker only (cdxgen sets it from what the
// production dependencies reach), and so is a crate with a non-dev scope.
const devSide = new Set(marked);
const pending = [...marked];
while (pending.length) {
  for (const m of edges.get(pending.shift()) || []) {
    const c = byRef.get(m);
    if (devSide.has(m) || !c || isProject(m) || /^pkg:npm\//.test(c.purl || '')
      || prop(c, 'cdx:cargo:scope').some(v => v !== 'dev')) continue;
    devSide.add(m);
    pending.push(m);
  }
}
// What reaches it from outside that side keeps it.
const skip = (n, m) => marked.has(m) && (n === rootRef || (npmMarked.has(m) && isProject(n)));
const seeds = [rootRef];
for (const r of new Set([...edges.keys(), ...byRef.keys()])) if (r !== rootRef && !devSide.has(r)) seeds.push(r);
const reached = new Set(seeds);
const queue = [...seeds];
while (queue.length) {
  const n = queue.shift();
  for (const m of edges.get(n) || []) {
    if (reached.has(m) || skip(n, m)) continue;
    reached.add(m);
    queue.push(m);
  }
}
const drop = new Set([...devSide].filter(r => !reached.has(r) && byRef.has(r)));
if (drop.size === 0) process.exit(0);
const before = bom.components.length;
const droppedPurls = bom.components.filter(c => drop.has(refOf(c))).map(c => c.purl || refOf(c));
bom.components = bom.components.filter(c => !drop.has(refOf(c)));
bom.dependencies = bom.dependencies
  .filter(d => !drop.has(d.ref))
  .map(d => Array.isArray(d.dependsOn)
    ? Object.assign({}, d, { dependsOn: d.dependsOn.filter(r => !drop.has(r)) })
    : d);
function mergeCapped(existing, additions, limit) {
  let shown = [];
  let priorTotal = 0;
  if (existing) {
    const m = /^(.*?)(?: \(\+(\d+) more\))?$/.exec(existing);
    shown = m[1] ? m[1].split(', ').filter(Boolean) : [];
    priorTotal = shown.length + (m[2] ? parseInt(m[2], 10) : 0);
  }
  const merged = shown.concat(additions);
  const total = priorTotal + additions.length;
  let val = merged.slice(0, limit).join(', ');
  const hidden = total - Math.min(limit, merged.length);
  if (hidden > 0) val += ' (+' + hidden + ' more)';
  return val;
}
bom.metadata = bom.metadata || {};
const existingProps = bom.metadata.properties || [];
const priorComponents = (existingProps.find(p => p.name === 'bomlens:excluded-components') || {}).value || null;
bom.metadata.properties = existingProps.filter(p => p.name !== 'bomlens:excluded-components')
  .concat([{ name: 'bomlens:excluded-components', value: mergeCapped(priorComponents, droppedPurls, 50) }]);
fs.writeFileSync(bomPath, JSON.stringify(bom, null, 2));
say('dropped ' + drop.size + ' development-only component(s), kept ' + bom.components.length + ' of ' + before);
DEVFILTER_JS
    _dvns=""
    [ -n "${EXCLUDE_NON_SHIPPED:-}" ] && _dvns="${NON_SHIPPED_DIRS:-}"
    node "$_dvflt" "$OUT" "${_dvnpm:-0}" "$_dvgems" "$_dvns" || log "dev-marker: filter skipped (non-fatal)"
    rm -f "$_dvflt" "$_dvgems"
fi

# Non-shipped path filter: the --exclude globs keep cdxgen from reading the
# NON_SHIPPED_PATHS folders, and this drops a component that still names only
# such a location, in internal:SrcFile or its identity evidence (cdxgen 13
# reports gradle/wrapper/gradle-wrapper.jar as a file component that way). A
# component with any other location stays.
if [ "${rc:-1}" -eq 0 ] && [ -n "$EXCLUDE_NON_SHIPPED" ] && [ -f "$OUT" ] && command -v node >/dev/null 2>&1; then
    _nspflt=$(mktemp).js
    cat > "$_nspflt" <<'NSPATH_JS'
const fs = require('fs');
const [bomPath, paths] = process.argv.slice(2);
let bom;
try { bom = JSON.parse(fs.readFileSync(bomPath, 'utf8')); } catch (e) { process.exit(0); }
if (!Array.isArray(bom.components)) process.exit(0);
const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const list = paths.split(/\s+/).filter(Boolean);
if (!list.length) process.exit(0);
const re = new RegExp('(^|/)(' + list.map(esc).join('|') + ')/', 'i');
const locations = c => {
  const out = (c.properties || [])
    .filter(p => p.name === 'internal:SrcFile' || p.name === 'SrcFile')
    .map(p => String(p.value));
  const ev = c.evidence && c.evidence.identity;
  for (const id of Array.isArray(ev) ? ev : (ev ? [ev] : [])) {
    if (id.concludedValue) out.push(String(id.concludedValue));
    for (const m of id.methods || []) if (m.value) out.push(String(m.value));
  }
  return out;
};
const dropped = [];
bom.components = bom.components.filter(c => {
  const locs = locations(c);
  if (locs.length && locs.every(l => re.test(l))) { dropped.push(c['bom-ref'] || c.purl); return false; }
  return true;
});
if (!dropped.length) process.exit(0);
const drop = new Set(dropped);
if (Array.isArray(bom.dependencies)) {
  bom.dependencies = bom.dependencies
    .filter(d => !drop.has(d.ref))
    .map(d => Array.isArray(d.dependsOn)
      ? Object.assign({}, d, { dependsOn: d.dependsOn.filter(r => !drop.has(r)) })
      : d);
}
fs.writeFileSync(bomPath, JSON.stringify(bom, null, 2));
process.stderr.write('[build-prep] non-shipped: dropped ' + dropped.length + ' component(s) found only under ' + list.join(', ') + '\n');
NSPATH_JS
    node "$_nspflt" "$OUT" "$NON_SHIPPED_PATHS" || log "non-shipped: path filter skipped (non-fatal)"
    rm -f "$_nspflt"
fi

# Maven non-deployed-module filter: the scope filter above keeps a component the
# moment ANY reactor module needs it at compile/runtime scope, but cdxgen tags
# scope once per component for the whole reactor -- it does not know that the
# one module reaching a dependency at that scope is itself never deployed (a
# test-support or demo module some projects keep in the same reactor, distinct
# from a source-tree TEST FOLDER, which the source-scan exclusion earlier in
# this file already leaves out of cdxgen's input entirely). Find those modules
# from the pom tree itself (maven-deploy-plugin's effective `skip`, walking
# parent/relativePath and resolving `${property}` references with no `mvn`
# invocation), then drop only what is reachable from one of
# them and NOT reachable from any module that does deploy. A component no
# reactor module's dependency graph reaches at all is left alone (cdxgen may
# simply not have recorded that edge, not that nothing needs it), and a kept
# module cdxgen gave no dependency-graph entry to at all makes the whole graph
# untrustworthy for this pass, so the filter stands down rather than guess.
# BOMLENS_MAVEN_FULL_GRAPH=1 (the same switch as the scope filter above) opts
# out, since both exist to answer the same "give me the full reactor graph"
# request.
#
# Runs under this same file's own `command -v node` (this file already runs
# node for the scope filter above and several other passes), inside the
# cdxgen sibling container -- the CLI's stage-1 container and the web UI's
# entrypoint.sh-launched sibling both run from a cdxgen image, and cdxgen
# itself is a Node.js CLI, so node is present at both the places this file
# runs from by construction, not by a separate check.
if [ "${rc:-1}" -eq 0 ] && [ -f pom.xml ] && ! opted_out "${BOMLENS_MAVEN_FULL_GRAPH:-}" \
   && [ -f "$OUT" ] && command -v node >/dev/null 2>&1; then
    _mndf=$(mktemp).js
    cat > "$_mndf" <<'MNDF_JS'
const fs = require('fs');
const path = require('path');
const [bomPath] = process.argv.slice(2);
let bom;
try { bom = JSON.parse(fs.readFileSync(bomPath, 'utf8')); } catch (e) { process.exit(0); }
if (!Array.isArray(bom.components) || !Array.isArray(bom.dependencies)) process.exit(0);

// Minimal recursive-descent XML parser (no deps): elements, nested elements,
// direct text, comments, <?xml?>, self-closing tags, CDATA (skipped whole --
// nothing this script reads lives inside one; an antrun plugin's
// <replacevalue> can legitimately hold Java source with its own < and >, a
// real construct real pom.xml files use). Does not handle entities beyond the
// five XML builtins -- pom.xml needs no more for the fields this reads
// (parent/relativePath, modules, properties, plugin config).
//
// The tag matcher uses a sticky regex against a fixed lastIndex rather than
// `src.slice(i)`: slicing copies everything from i to the end of the file on
// EVERY tag, which is O(n) per tag and O(n^2) over a whole real pom.xml (a
// large multi-module reactor's shared parent pom, read once per descendant
// walking its chain, made this seconds-to-minutes rather than milliseconds).
// The close-tag check uses `startsWith` at a position for the same reason.
// A construct this parser does not recognize (as CDATA is handled, this is
// now only something stranger still, like a stray processing instruction)
// must never leave `i` unmoved -- that would spin forever rather than just
// skip one node, so progress is asserted explicitly, at both the recursive
// and the top level.
// Belt and suspenders beyond CDATA handling and the progress checks below: a
// pom.xml this parser has some OTHER, still-unknown way to mishandle must
// never be able to hang the whole scan or exhaust memory on it. A byte cap
// (real pom.xml files are a few KB to a couple hundred KB; the reactor's own
// files here top out under 60KB) and a wall-clock budget checked periodically
// during parsing (real parses finish in low single-digit milliseconds) turn
// "unknown parser bug on someone's pom.xml" into "this module's skip status
// could not be determined", which safely resolves to false -- not a hang.
const POM_MAX_BYTES = 2 * 1024 * 1024;
const POM_PARSE_BUDGET_MS = 2000;
const TAG_RE = /<([A-Za-z_][\w.:-]*)((?:\s+[^>]*?)?)(\/?)>/y;
function parseXml(src) {
  if (src.length > POM_MAX_BYTES) return null;
  src = src.replace(/<\?[\s\S]*?\?>/g, '').replace(/<!--[\s\S]*?-->/g, '');
  let i = 0;
  const n = src.length;
  const deadline = Date.now() + POM_PARSE_BUDGET_MS;
  let steps = 0;
  function overBudget() { return (++steps & 0xfff) === 0 && Date.now() > deadline; }
  function skipWs() { while (i < n && /\s/.test(src[i])) i++; }
  function parseNode() {
    skipWs();
    if (src[i] !== '<') return null;
    TAG_RE.lastIndex = i;
    const m = TAG_RE.exec(src);
    if (!m || m.index !== i) return null;
    i = TAG_RE.lastIndex;
    const tag = m[1];
    const node = { tag, children: [], text: '' };
    if (m[3] === '/') return node;
    const closeTag = '</' + tag + '>';
    while (i < n) {
      if (overBudget()) throw new Error('parse budget exceeded');
      skipWs();
      if (src.startsWith(closeTag, i)) { i += closeTag.length; return node; }
      if (src[i] === '<') {
        if (src.startsWith('</', i)) { const end = src.indexOf('>', i); i = end < 0 ? n : end + 1; return node; }
        if (src.startsWith('<![CDATA[', i)) {
          const end = src.indexOf(']]>', i);
          i = end < 0 ? n : end + 3;
          continue;
        }
        const beforeChild = i;
        const child = parseNode();
        if (child) node.children.push(child);
        if (i === beforeChild) { const end = src.indexOf('>', i); i = end < 0 ? n : end + 1; }
      } else {
        const next = src.indexOf('<', i);
        node.text += next < 0 ? src.slice(i) : src.slice(i, next);
        i = next < 0 ? n : next;
      }
    }
    return node;
  }
  try {
    const roots = [];
    while (i < n) {
      if (overBudget()) throw new Error('parse budget exceeded');
      skipWs();
      if (i >= n) break;
      const before = i;
      const node = parseNode();
      if (node) roots.push(node);
      if (i === before) break;
    }
    return roots.find(r => r.tag === 'project') || null;
  } catch (e) {
    return null;
  }
}
const decodeEntities = s => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&apos;/g, "'");
const directChild = (node, tag) => node ? (node.children.find(c => c.tag === tag) || null) : null;
const directChildren = (node, tag) => node ? node.children.filter(c => c.tag === tag) : [];
const directText = node => node ? decodeEntities(node.text).trim() : '';

// pom loading + parent-chain walk (nearest first). A missing or unresolvable
// parent (remote-only relativePath, a cycle) stops the chain there -- the
// caller then finds no more signal and resolves to "not skipped".
function loadChain(moduleDir, seen) {
  seen = seen || new Set();
  const pomPath = path.join(moduleDir, 'pom.xml');
  const real = path.resolve(pomPath);
  if (seen.has(real)) return [];
  seen.add(real);
  let text;
  try { text = fs.readFileSync(pomPath, 'utf8'); } catch (e) { return []; }
  const project = parseXml(text);
  if (!project) return [];
  const chain = [{ dir: moduleDir, project }];
  const parent = directChild(project, 'parent');
  if (parent) {
    const relPathNode = directChild(parent, 'relativePath');
    const relPath = relPathNode ? directText(relPathNode) : '../pom.xml';
    if (relPath !== '') chain.push(...loadChain(path.dirname(path.join(moduleDir, relPath)), seen));
  }
  return chain;
}
function findProperty(project, name) {
  const props = directChild(project, 'properties');
  const node = props ? directChild(props, name) : null;
  return node ? directText(node) : undefined;
}
// Never descends into <profiles> -- a profile's activation cannot be known
// offline, so config that lives only there is invisible here and falls
// through to "not skipped".
function findPluginSkip(project, underPluginManagement) {
  const build = directChild(project, 'build');
  if (!build) return undefined;
  const pluginsHolder = underPluginManagement ? directChild(build, 'pluginManagement') : build;
  const plugins = pluginsHolder ? directChild(pluginsHolder, 'plugins') : null;
  if (!plugins) return undefined;
  for (const plugin of directChildren(plugins, 'plugin')) {
    const artifactId = directChild(plugin, 'artifactId');
    if (!artifactId || directText(artifactId) !== 'maven-deploy-plugin') continue;
    const config = directChild(plugin, 'configuration');
    const skip = config ? directChild(config, 'skip') : null;
    if (skip) return directText(skip);
  }
  return undefined;
}
function resolveValue(raw, chain) {
  raw = (raw || '').trim();
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  const m = /^\$\{([^}]+)\}$/.exec(raw);
  if (!m) return false;
  for (const { project } of chain) {
    const v = findProperty(project, m[1]);
    if (v !== undefined) return v.trim() === 'true';
  }
  return false;
}
// Effective maven-deploy-plugin skip for one module: direct <plugins> config
// (nearest pom in the chain wins) first, then <pluginManagement> (still
// applies -- deploy is bound to the default lifecycle regardless of an
// explicit <plugins> entry), then the standard maven.deploy.skip property
// alone. Anything this cannot resolve comes back false: under-excluding is
// the safe direction, not over-excluding.
function resolveSkip(moduleDir) {
  const chain = loadChain(moduleDir);
  if (chain.length === 0) return false;
  for (const { project } of chain) { const v = findPluginSkip(project, false); if (v !== undefined) return resolveValue(v, chain); }
  for (const { project } of chain) { const v = findPluginSkip(project, true); if (v !== undefined) return resolveValue(v, chain); }
  for (const { project } of chain) { const v = findProperty(project, 'maven.deploy.skip'); if (v !== undefined) return v.trim() === 'true'; }
  return false;
}
function gaOfProject(project) {
  const artifactId = directChild(project, 'artifactId');
  let groupId = directChild(project, 'groupId');
  if (!groupId) { const parent = directChild(project, 'parent'); groupId = parent ? directChild(parent, 'groupId') : null; }
  return (groupId ? directText(groupId) : '?') + ':' + (artifactId ? directText(artifactId) : '?');
}
function enumerateModules(rootDir) {
  const out = [];
  function walk(dir) {
    let text;
    try { text = fs.readFileSync(path.join(dir, 'pom.xml'), 'utf8'); } catch (e) { return; }
    const project = parseXml(text);
    if (!project) return;
    out.push({ dir, project });
    const modulesNode = directChild(project, 'modules');
    if (!modulesNode) return;
    for (const modNode of directChildren(modulesNode, 'module')) {
      const rel = directText(modNode);
      if (rel) walk(path.join(dir, rel));
    }
  }
  walk(rootDir);
  return out;
}

// 1. which reactor modules are never deployed
const modules = enumerateModules('.');
const excludedGAs = new Set();
for (const { dir, project } of modules) { if (resolveSkip(dir)) excludedGAs.add(gaOfProject(project)); }
if (excludedGAs.size === 0) process.exit(0);

// 2. map reactor modules onto the SBOM's own maven components
const gaOfPurl = purl => { const m = /^pkg:maven\/([^/]+)\/([^@?]+)/.exec(purl || ''); return m ? decodeURIComponent(m[1]) + ':' + decodeURIComponent(m[2]) : null; };
const refOf = c => c['bom-ref'] || c.purl;
const allModuleGAs = new Set(modules.map(m => gaOfProject(m.project)));
const moduleRefByGA = new Map();
for (const c of bom.components) { const g = gaOfPurl(c.purl); if (g && allModuleGAs.has(g)) moduleRefByGA.set(g, refOf(c)); }
const mc = bom.metadata && bom.metadata.component;
const mcRef = mc ? refOf(mc) : null;
if (mc) { const g = gaOfPurl(mc.purl); if (g && allModuleGAs.has(g)) moduleRefByGA.set(g, mcRef); }
if (moduleRefByGA.size === 0) process.exit(0);

const adj = new Map();
for (const d of bom.dependencies) adj.set(d.ref, d.dependsOn || []);

// metadata.component's own dependsOn should name the reactor's modules; if it
// does not (an aggregate root cdxgen did not wire that way), fall back to
// every module this pom tree's own <modules> lists found in the SBOM.
const moduleRefSet = new Set(moduleRefByGA.values());
const mcModuleDeps = (mcRef ? (adj.get(mcRef) || []) : []).filter(r => moduleRefSet.has(r));
const reactorRefs = mcModuleDeps.length > 0 ? new Set(mcModuleDeps) : moduleRefSet;

const keepRoots = [];
const excludeRoots = [];
for (const [g, ref] of moduleRefByGA) {
  if (!reactorRefs.has(ref)) continue;
  (excludedGAs.has(g) ? excludeRoots : keepRoots).push(ref);
}
if (keepRoots.length === 0 || excludeRoots.length === 0) process.exit(0);

const incomplete = keepRoots.filter(r => !adj.has(r));
if (incomplete.length > 0) {
  process.stderr.write('[build-prep] maven: dependency graph incomplete for a kept module; skipping the non-deployed-module filter\n');
  process.exit(0);
}

function bfs(starts) {
  const seen = new Set(starts);
  const queue = starts.slice();
  while (queue.length) {
    const cur = queue.shift();
    for (const next of (adj.get(cur) || [])) if (!seen.has(next)) { seen.add(next); queue.push(next); }
  }
  return seen;
}
const reachedFromKeep = bfs(keepRoots);
const reachedFromExclude = bfs(excludeRoots);
const dropRefs = new Set(excludeRoots);
for (const r of reachedFromExclude) if (!reachedFromKeep.has(r)) dropRefs.add(r);
if (mcRef) dropRefs.delete(mcRef);
if (dropRefs.size === 0) process.exit(0);

// 3. apply, mirroring the scope filter's own graph-pruning style
const droppedPurls = bom.components.filter(c => dropRefs.has(refOf(c))).map(c => c.purl || refOf(c));
const before = bom.components.length;
bom.components = bom.components.filter(c => !dropRefs.has(refOf(c)));
const keptRefs = new Set(bom.components.map(refOf));
if (mcRef) keptRefs.add(mcRef);
bom.dependencies = bom.dependencies
  .filter(d => keptRefs.has(d.ref))
  .map(d => Array.isArray(d.dependsOn) ? Object.assign({}, d, { dependsOn: d.dependsOn.filter(r => keptRefs.has(r)) }) : d);

// 4. record what was excluded, same shape as bomlens:excluded-paths/-manifests
const LIMIT = 50;
bom.metadata = bom.metadata || {};
const priorComponents = ((bom.metadata.properties || []).find(p => p.name === 'bomlens:excluded-components') || {}).value || '';
const props = (bom.metadata.properties || []).filter(p => p.name !== 'bomlens:excluded-modules' && p.name !== 'bomlens:excluded-components');
// Every skip=true module actually present in this scan's reactor, not just the
// ones used to seed the BFS above (a nested excluded module, e.g. one two
// levels under an already-excluded parent, is reached through its parent and
// never becomes its own root, but it is still a module this scan excluded).
const excludedList = [...excludedGAs].filter(g => moduleRefByGA.has(g)).sort();
let modVal = excludedList.slice(0, LIMIT).join(', ');
if (excludedList.length > LIMIT) modVal += ` (+${excludedList.length - LIMIT} more)`;
props.push({ name: 'bomlens:excluded-modules', value: modVal });
// Keep what an earlier filter (the development-marker filter) recorded.
const priorM = /^(.*?)(?: \(\+(\d+) more\))?$/.exec(priorComponents);
const priorShown = priorM[1] ? priorM[1].split(', ').filter(Boolean) : [];
const allComponents = priorShown.concat(droppedPurls);
const totalComponents = allComponents.length + (priorM[2] ? parseInt(priorM[2], 10) : 0);
if (allComponents.length) {
  let compVal = allComponents.slice(0, LIMIT).join(', ');
  const hiddenComponents = totalComponents - Math.min(LIMIT, allComponents.length);
  if (hiddenComponents > 0) compVal += ` (+${hiddenComponents} more)`;
  props.push({ name: 'bomlens:excluded-components', value: compVal });
}
bom.metadata.properties = props;

fs.writeFileSync(bomPath, JSON.stringify(bom, null, 2));
process.stderr.write('[build-prep] maven: excluded ' + excludedList.length + ' non-deployed module(s), dropped ' + (before - bom.components.length) + ' of ' + before + ' components\n');
MNDF_JS
    node "$_mndf" "$OUT" || log "maven: non-deployed-module filter skipped (non-fatal)"
    rm -f "$_mndf"
fi

# Cargo workspace-member filter: the file-level exclusion above (the --exclude
# globs built from NON_SHIPPED_DIRS) narrows what cdxgen crawls, but cdxgen
# reads Cargo.lock directly for Rust, independent of that crawl -- a crate
# registered as a workspace member in Cargo.lock survives even when its own
# directory sits under an excluded tree (an examples-only crate, say). Drop
# such a member's own component, and a dependency only that member needs,
# unless a kept member reaches it too (any way at all -- Cargo.lock's own
# dependency list carries no normal/dev/build distinction, and there is no
# principled reason to treat them differently here anyway: reaching it at all
# is enough to keep it, same as everywhere else in this file).
# BOMLENS_INCLUDE_NON_SHIPPED=1 (the same switch the file-level exclusion
# above uses) opts out, since this extends that same exclusion to the lock
# file.
#
# Member/path discovery uses `cargo metadata --no-deps --offline`, confirmed
# to need no network at all (it reads only the Cargo.toml files already on
# disk, workspace inheritance and all). The dependency graph itself is NOT
# read from a full `cargo metadata` resolve -- that needs to download every
# crate's source even when Cargo.lock already pins exact versions, which is
# slow and fails outright offline. Instead this reads Cargo.lock's own flat,
# machine-generated package list directly: a single forward pass over its
# lines, no recursion, so the stuck-parser bug the pom parser above once had
# (a child parse that never advances the cursor) cannot recur here by
# construction. A byte-size cap and a wall-clock budget still bound it, and
# any dependency-list entry that cannot be traced to exactly one package
# block (Cargo.lock's three reference forms: bare name, "name version", or
# "name version (source)") stands the whole pass down rather than guess.
if [ "${rc:-1}" -eq 0 ] && [ -f Cargo.toml ] && [ -f Cargo.lock ] \
   && [ -n "$EXCLUDE_NON_SHIPPED" ] \
   && [ -f "$OUT" ] && command -v node >/dev/null 2>&1 && command -v cargo >/dev/null 2>&1; then
    _cwmeta=$(prep_step cargo-workspace-metadata "$PREP_TIMEOUT_DEFAULT" cargo metadata --no-deps --format-version 1 --offline)
    _cwmeta_rc=$?
    if [ "$_cwmeta_rc" -eq 0 ] && [ -n "$_cwmeta" ]; then
        _cwmetaf=$(mktemp)
        printf '%s' "$_cwmeta" > "$_cwmetaf"
        _cwmf=$(mktemp).js
        cat > "$_cwmf" <<'CWMF_JS'
const fs = require('fs');
const path = require('path');
const [bomPath, metaPath, lockPath, dirsStr] = process.argv.slice(2);
let bom;
try { bom = JSON.parse(fs.readFileSync(bomPath, 'utf8')); } catch (e) { process.exit(0); }
if (!Array.isArray(bom.components) || !Array.isArray(bom.dependencies)) process.exit(0);

let meta;
try { meta = JSON.parse(fs.readFileSync(metaPath, 'utf8')); } catch (e) { process.exit(0); }
const members = Array.isArray(meta.workspace_members) ? meta.workspace_members : [];
if (members.length === 0) process.exit(0);
const pkgById = new Map();
for (const p of (meta.packages || [])) pkgById.set(p.id, p);

const NON_SHIPPED_DIRS = new Set((dirsStr || '').split(/\s+/).filter(Boolean));
// realpath both sides: cargo (and process.cwd()) resolve symlinks, so a raw
// string comparison can spuriously disagree on any host where the scan root
// is reached through one (macOS routes its own tmp dir through /private,
// for one).
let cwd;
try { cwd = fs.realpathSync(process.cwd()); } catch (e) { cwd = process.cwd(); }
function relDir(manifestPath) {
  let dir = path.dirname(manifestPath);
  try { dir = fs.realpathSync(dir); } catch (e) { /* use the raw path */ }
  return path.relative(cwd, dir);
}
function underExcludedTree(manifestPath) {
  const rel = relDir(manifestPath);
  if (!rel || rel.startsWith('..')) return false;
  return rel.split(path.sep).some(seg => NON_SHIPPED_DIRS.has(seg));
}

const memberInfo = [];
for (const id of members) {
  const p = pkgById.get(id);
  if (!p || !p.name || !p.manifest_path) process.exit(0);   // metadata shape unexpected: bail
  memberInfo.push({ name: p.name, manifestPath: p.manifest_path,
                    excluded: underExcludedTree(p.manifest_path) });
}
const excludedMembers = memberInfo.filter(m => m.excluded);
if (excludedMembers.length === 0) process.exit(0);
const keptMembers = memberInfo.filter(m => !m.excluded);
if (keptMembers.length === 0) process.exit(0);

// --- Cargo.lock: single forward pass over its lines, no recursion ---
const LOCK_MAX_BYTES = 8 * 1024 * 1024;
const PARSE_BUDGET_MS = 3000;
let lockText;
try { lockText = fs.readFileSync(lockPath, 'utf8'); } catch (e) { process.exit(0); }
if (lockText.length > LOCK_MAX_BYTES) process.exit(0);

const deadline = Date.now() + PARSE_BUDGET_MS;
let steps = 0;
function overBudget() { return (++steps & 0xfff) === 0 && Date.now() > deadline; }

function quoted(s) {
  const m = /^"((?:[^"\\]|\\.)*)"\s*,?\s*$/.exec(s.trim());
  return m ? m[1].replace(/\\(.)/g, '$1') : null;
}

const lines = lockText.split('\n');
let lockVersion = null;
const blocks = [];
let cur = null;
let inDeps = false;
let malformed = false;
for (let i = 0; i < lines.length && !malformed; i++) {
  if (overBudget()) { malformed = true; break; }
  const trimmed = lines[i].trim();
  if (lockVersion === null && !cur) {
    const m = /^version\s*=\s*(\d+)\s*$/.exec(trimmed);
    if (m) lockVersion = m[1];
  }
  if (trimmed === '[[package]]') {
    if (inDeps) { malformed = true; break; }   // unterminated dependencies array
    if (cur) blocks.push(cur);
    cur = { name: null, version: null, source: null, deps: [] };
    continue;
  }
  if (!cur) continue;
  if (inDeps) {
    if (trimmed === ']' || trimmed === '],') { inDeps = false; continue; }
    const item = quoted(trimmed);
    if (item === null) { malformed = true; break; }
    cur.deps.push(item);
    continue;
  }
  let m;
  if ((m = /^name\s*=\s*"((?:[^"\\]|\\.)*)"\s*$/.exec(trimmed))) { cur.name = m[1]; continue; }
  if ((m = /^version\s*=\s*"((?:[^"\\]|\\.)*)"\s*$/.exec(trimmed))) { cur.version = m[1]; continue; }
  if ((m = /^source\s*=\s*"((?:[^"\\]|\\.)*)"\s*$/.exec(trimmed))) { cur.source = m[1]; continue; }
  if (/^dependencies\s*=\s*\[\s*\]\s*$/.test(trimmed)) { continue; }
  if ((m = /^dependencies\s*=\s*\[(.*)\]\s*$/.exec(trimmed))) {
    const inner = m[1].trim();
    if (inner) {
      for (const part of inner.split(',')) {
        const item = quoted(part);
        if (item === null) { malformed = true; break; }
        cur.deps.push(item);
      }
    }
    continue;
  }
  if (/^dependencies\s*=\s*\[\s*$/.test(trimmed)) { inDeps = true; continue; }
  // any other line (checksum, replace, ...) is ignored
}
if (!malformed && cur && !inDeps) blocks.push(cur);
if (malformed || inDeps || lockVersion === null || (lockVersion !== '3' && lockVersion !== '4')) process.exit(0);
if (blocks.some(b => !b.name || !b.version)) process.exit(0);

// Canonical key per Cargo.lock's own reference precedence: bare name if that
// name is unique in this lock, else "name version", else "name version
// (source)". A dependency-list item, resolved the same way, must land on
// exactly one block or the whole pass stands down.
const nameCount = new Map();
const nvCount = new Map();
for (const b of blocks) {
  nameCount.set(b.name, (nameCount.get(b.name) || 0) + 1);
  const nv = b.name + '|' + b.version;
  nvCount.set(nv, (nvCount.get(nv) || 0) + 1);
}
function canonicalKey(b) {
  if (nameCount.get(b.name) === 1) return b.name;
  if (nvCount.get(b.name + '|' + b.version) === 1) return b.name + ' ' + b.version;
  return b.name + ' ' + b.version + ' (' + (b.source || '') + ')';
}
const keyOf = new Map();
const blockByKey = new Map();
for (const b of blocks) { const k = canonicalKey(b); keyOf.set(b, k); blockByKey.set(k, b); }
if (blockByKey.size !== blocks.length) process.exit(0);   // two blocks collided on their key

const byName = new Map();
const byNameVersion = new Map();
const byNameVersionSource = new Map();
for (const b of blocks) {
  (byName.get(b.name) || byName.set(b.name, []).get(b.name)).push(b);
  const nv = b.name + '|' + b.version;
  (byNameVersion.get(nv) || byNameVersion.set(nv, []).get(nv)).push(b);
  const nvs = nv + '|' + (b.source || '');
  (byNameVersionSource.get(nvs) || byNameVersionSource.set(nvs, []).get(nvs)).push(b);
}
function resolveDepItem(item) {
  let m = /^(\S+) (\S+) \((.+)\)$/.exec(item);
  if (m) {
    const c = byNameVersionSource.get(m[1] + '|' + m[2] + '|' + m[3]) || [];
    return c.length === 1 ? c[0] : null;
  }
  m = /^(\S+) (\S+)$/.exec(item);
  if (m) {
    const c = byNameVersion.get(m[1] + '|' + m[2]) || [];
    return c.length === 1 ? c[0] : null;
  }
  const c = byName.get(item) || [];
  return c.length === 1 ? c[0] : null;
}

const adj = new Map();
for (const b of blocks) {
  if (overBudget()) process.exit(0);
  const targets = [];
  for (const item of b.deps) {
    const target = resolveDepItem(item);
    if (!target) process.exit(0);   // an unresolved reference: stand the whole pass down
    targets.push(keyOf.get(target));
  }
  adj.set(keyOf.get(b), targets);
}

// Workspace members are local path packages; a real workspace cannot have two
// members share a name, so this must resolve to exactly one block.
function memberKey(m) {
  const c = byName.get(m.name) || [];
  return c.length === 1 ? keyOf.get(c[0]) : null;
}
const keptRoots = [];
for (const m of keptMembers) { const k = memberKey(m); if (!k) process.exit(0); keptRoots.push(k); }
const excludeRoots = [];
for (const m of excludedMembers) { const k = memberKey(m); if (!k) process.exit(0); excludeRoots.push(k); }

function bfs(starts) {
  const seen = new Set(starts);
  const queue = starts.slice();
  while (queue.length) {
    if (overBudget()) return null;
    const cur = queue.shift();
    for (const next of (adj.get(cur) || [])) if (!seen.has(next)) { seen.add(next); queue.push(next); }
  }
  return seen;
}
const reachedFromKeep = bfs(keptRoots);
const reachedFromExclude = bfs(excludeRoots);
if (!reachedFromKeep || !reachedFromExclude) process.exit(0);

const dropKeys = new Set(excludeRoots);
for (const k of reachedFromExclude) if (!reachedFromKeep.has(k)) dropKeys.add(k);
if (dropKeys.size === 0) process.exit(0);

// purl matching only carries name@version, not source, so collapse drop/keep
// sets to name@version pairs; a pair reachable from a kept root under ANY of
// its blocks counts as kept -- conservative when the same name@version
// exists under two different sources and only one of them is excluded.
const nvOf = k => { const b = blockByKey.get(k); return b.name + '@' + b.version; };
const keptNV = new Set([...reachedFromKeep].map(nvOf));
const dropNV = new Set();
for (const k of dropKeys) { const nv = nvOf(k); if (!keptNV.has(nv)) dropNV.add(nv); }
if (dropNV.size === 0) process.exit(0);

// --- apply to the SBOM ---
const refOf = c => c['bom-ref'] || c.purl;
const nvOfPurl = purl => {
  const m = /^pkg:cargo\/([^@]+)@([^?]+)/.exec(purl || '');
  return m ? decodeURIComponent(m[1]) + '@' + decodeURIComponent(m[2]) : null;
};
const droppedPurls = [];
const keep = c => {
  const nv = nvOfPurl(c.purl);
  if (!nv || !dropNV.has(nv)) return true;
  droppedPurls.push(c.purl);
  return false;
};
const before = bom.components.length;
bom.components = bom.components.filter(keep);
if (droppedPurls.length === 0) process.exit(0);

const mc = bom.metadata && bom.metadata.component;
const keptRefs = new Set(bom.components.map(refOf));
if (mc) keptRefs.add(mc['bom-ref'] || mc.purl);
bom.dependencies = bom.dependencies
  .filter(d => keptRefs.has(d.ref))
  .map(d => Array.isArray(d.dependsOn) ? Object.assign({}, d, { dependsOn: d.dependsOn.filter(r => keptRefs.has(r)) }) : d);

// Record, merging into whatever another exclusion pass in this same scan
// already wrote to the same shared bomlens:excluded-components property
// (a polyglot repo could also trip the Maven non-deployed-module filter
// above). The prior value is itself a capped display string, so the merge
// is best-effort: it recovers the prior shown items and total count from
// the "(+N more)" suffix and re-caps over the combined total.
function mergeCapped(existing, additions, limit) {
  let shown = [];
  let priorTotal = 0;
  if (existing) {
    const m = /^(.*?)(?: \(\+(\d+) more\))?$/.exec(existing);
    shown = m[1] ? m[1].split(', ').filter(Boolean) : [];
    priorTotal = shown.length + (m[2] ? parseInt(m[2], 10) : 0);
  }
  const merged = shown.concat(additions);
  const total = priorTotal + additions.length;
  let val = merged.slice(0, limit).join(', ');
  const hidden = total - Math.min(limit, merged.length);
  if (hidden > 0) val += ' (+' + hidden + ' more)';
  return val;
}
const LIMIT = 50;
bom.metadata = bom.metadata || {};
const existingProps = bom.metadata.properties || [];
const priorMembers = (existingProps.find(p => p.name === 'bomlens:excluded-members') || {}).value || null;
const priorComponents = (existingProps.find(p => p.name === 'bomlens:excluded-components') || {}).value || null;
const memberList = excludedMembers.map(m =>
  'cargo:' + relDir(m.manifestPath).split(path.sep).join('/') + ' (' + m.name + ')');
const props = existingProps.filter(p => p.name !== 'bomlens:excluded-members' && p.name !== 'bomlens:excluded-components');
props.push({ name: 'bomlens:excluded-members', value: mergeCapped(priorMembers, memberList, LIMIT) });
props.push({ name: 'bomlens:excluded-components', value: mergeCapped(priorComponents, droppedPurls, LIMIT) });
bom.metadata.properties = props;

fs.writeFileSync(bomPath, JSON.stringify(bom, null, 2));
process.stderr.write('[build-prep] cargo: excluded ' + excludedMembers.length + ' workspace member(s), dropped ' + (before - bom.components.length) + ' of ' + before + ' components\n');
CWMF_JS
        node "$_cwmf" "$OUT" "$_cwmetaf" Cargo.lock "$NON_SHIPPED_DIRS" || log "cargo: workspace-member filter skipped (non-fatal)"
        rm -f "$_cwmf" "$_cwmetaf"
    else
        log "cargo: could not resolve workspace members offline; skipping workspace-member filter"
    fi
fi

# pnpm workspace-member filter: the same problem as the Cargo/npm filters
# above -- cdxgen reads pnpm-lock.yaml directly, so a member whose own
# directory sits under an excluded tree (a playground or __tests__ package,
# say) survives the file-level --exclude globs. Drop such a member's own
# component, and a dependency only that member reaches (any way at all),
# unless a kept member reaches it too. BOMLENS_INCLUDE_NON_SHIPPED=1 opts
# out, same switch as the file-level exclusion above.
#
# Member discovery and the dependency graph both come from `pnpm ls`, never
# from hand-parsing pnpm-lock.yaml's YAML. A single `pnpm ls -r --depth
# Infinity --json --lockfile-only` call needs no node_modules and no
# network, and returns every workspace project's own full recursive
# dependency tree in one process (confirmed against a real 283-project
# workspace: 1.1MB of JSON, ~3.5s -- far cheaper than one `pnpm ls --filter`
# call per member).
#
# A workspace-member dependency carries pnpm's `link:`/`file:` version
# prefix and always repeats the target's own absolute path in its `path`
# field, so a member-to-member edge resolves by matching that path against
# the top-level project list -- never by name, and never by trusting a link
# node's own inline expansion (pnpm fills that in for some occurrences of a
# link and leaves it empty for others; the top-level project entry is the
# one place every member's own direct dependencies are always complete).
#
# An external registry package's edges collapse onto its own name@version:
# pnpm expands a name@version's dependencies at most once per `pnpm ls`
# call and marks every later occurrence "deduped": true with no
# "dependencies" key, so the adjacency for that name@version has to be
# collected from whichever occurrence(s), anywhere in the whole document,
# actually carry it -- not from any one node's local subtree. A name@version
# that is deduped everywhere it appears does happen in real workspaces (an
# `overrides`-aliased package, and pnpm's own internal ESM/CJS-compat
# "-cjs" aliases both do this) -- `dedupedDependenciesCount` says it has
# children, but none of its occurrences ever show them. Such a package is
# never dropped (protected), the same conservative fallback the npm filter
# above gives an unresolved dependency name.
if [ "${rc:-1}" -eq 0 ] && [ -f pnpm-workspace.yaml ] && [ -f pnpm-lock.yaml ] \
   && [ -n "$EXCLUDE_NON_SHIPPED" ] \
   && [ -f "$OUT" ] && command -v node >/dev/null 2>&1 && command -v pnpm >/dev/null 2>&1; then
    _pwtree=$(prep_step pnpm-workspace-tree "$PREP_TIMEOUT_DEFAULT" pnpm ls -r --depth Infinity --json --lockfile-only)
    _pwtree_rc=$?
    if [ "$_pwtree_rc" -eq 0 ] && [ -n "$_pwtree" ]; then
        _pwtreef=$(mktemp)
        printf '%s' "$_pwtree" > "$_pwtreef"
        _pwmf=$(mktemp).js
        cat > "$_pwmf" <<'PWMF_JS'
const fs = require('fs');
const path = require('path');
const [bomPath, treePath, dirsStr] = process.argv.slice(2);
let bom;
try { bom = JSON.parse(fs.readFileSync(bomPath, 'utf8')); } catch (e) { process.exit(0); }
if (!Array.isArray(bom.components) || !Array.isArray(bom.dependencies)) process.exit(0);

const MAX_TREE_BYTES = 64 * 1024 * 1024;
let treeText;
try {
  const st = fs.statSync(treePath);
  if (st.size > MAX_TREE_BYTES) process.exit(0);
  treeText = fs.readFileSync(treePath, 'utf8');
} catch (e) { process.exit(0); }
let tree;
try { tree = JSON.parse(treeText); } catch (e) { process.exit(0); }
if (!Array.isArray(tree) || tree.length === 0) process.exit(0);
if (tree.some(p => !p || typeof p.path !== 'string')) process.exit(0);   // shape unexpected: bail

const NON_SHIPPED_DIRS = new Set((dirsStr || '').split(/\s+/).filter(Boolean));
let cwd;
try { cwd = fs.realpathSync(process.cwd()); } catch (e) { cwd = process.cwd(); }
function canon(p) { try { return fs.realpathSync(p); } catch (e) { return p; } }
function relOf(absPath) { return path.relative(cwd, canon(absPath)); }
function underExcludedTree(rel) {
  if (!rel || rel.startsWith('..')) return false;
  return rel.split(path.sep).some(seg => NON_SHIPPED_DIRS.has(seg));
}

// pathToMember keys on the realpath'd absolute path, the same identity a
// link/file dependency's own "path" field carries, so a member-to-member
// edge matches by exact key lookup, never by name.
const pathToMember = new Map();
for (const p of tree) {
  const key = canon(p.path);
  pathToMember.set(key, {
    name: typeof p.name === 'string' ? p.name : null,
    version: typeof p.version === 'string' ? p.version : null,
    relPath: relOf(p.path),
    excluded: underExcludedTree(relOf(p.path)),
  });
}
const excludedMembers = [...pathToMember.values()].filter(m => m.excluded);
if (excludedMembers.length === 0) process.exit(0);
const keptMembers = [...pathToMember.values()].filter(m => !m.excluded);
if (keptMembers.length === 0) process.exit(0);

const BUDGET_MS = 5000;
const deadline = Date.now() + BUDGET_MS;
let steps = 0;
let budgetExceeded = false;
function overBudget() {
  if (budgetExceeded) return true;
  if ((++steps & 0xfff) === 0 && Date.now() > deadline) budgetExceeded = true;
  return budgetExceeded;
}

function mergedDeps(node) {
  return Object.assign({}, node.dependencies, node.devDependencies, node.optionalDependencies);
}

// extAdj: "name@version" -> child tokens, built from whichever occurrence(s)
// in the WHOLE tree carry that name@version's real "dependencies" (the
// first one visited; later "deduped": true occurrences of the same
// name@version are skipped via the extAdj.has(nv) guard, since pnpm
// guarantees they resolve to the identical subtree). hiddenChildren
// collects a name@version pnpm says has children (dedupedDependenciesCount
// > 0) that this pass never once saw expanded -- protected below.
const extAdj = new Map();
const hiddenChildren = new Set();

function tokenFor(name, node) {
  if (overBudget() || !node || typeof node.version !== 'string') return null;
  if ((node.version.startsWith('link:') || node.version.startsWith('file:')) && typeof node.path === 'string') {
    const key = canon(node.path);
    return pathToMember.has(key) ? 'm:' + key : null;   // unresolvable link target: drop the edge
  }
  const from = typeof node.from === 'string' ? node.from : name;
  const nv = from + '@' + node.version;
  const hasDeps = Object.prototype.hasOwnProperty.call(node, 'dependencies')
    || Object.prototype.hasOwnProperty.call(node, 'devDependencies')
    || Object.prototype.hasOwnProperty.call(node, 'optionalDependencies');
  if (hasDeps) {
    if (!extAdj.has(nv)) extAdj.set(nv, collectTokens(mergedDeps(node)));
  } else if (typeof node.dedupedDependenciesCount === 'number' && node.dedupedDependenciesCount > 0) {
    hiddenChildren.add(nv);
  }
  return 'e:' + nv;
}
function collectTokens(depsObj) {
  const out = [];
  for (const name of Object.keys(depsObj)) {
    if (overBudget()) return out;
    const t = tokenFor(name, depsObj[name]);
    if (t) out.push(t);
  }
  return out;
}

// memberChildren: each member's own direct (dependencies + devDependencies
// + optionalDependencies) tokens, from its own top-level project entry --
// never from a link node's inline (sometimes-partial) copy of the same
// list. Walking every project here also fully populates extAdj above,
// regardless of which project happens to visit a given external package
// first.
const memberChildren = new Map();
for (const p of tree) {
  if (overBudget()) process.exit(0);
  memberChildren.set(canon(p.path), collectTokens(mergedDeps(p)));
}
if (budgetExceeded) process.exit(0);

const protectedNV = new Set([...hiddenChildren].filter(nv => !extAdj.has(nv)));

function childrenOf(token) {
  if (token.charCodeAt(0) === 109 /* 'm' */) return memberChildren.get(token.slice(2)) || [];
  return extAdj.get(token.slice(2)) || [];
}
function bfs(starts) {
  const seen = new Set(starts);
  const queue = starts.slice();
  while (queue.length) {
    if (overBudget()) return null;
    const cur = queue.shift();
    for (const next of childrenOf(cur)) if (!seen.has(next)) { seen.add(next); queue.push(next); }
  }
  return seen;
}
const keptRoots = [...pathToMember.entries()].filter(([, m]) => !m.excluded).map(([k]) => 'm:' + k);
const excludeRoots = [...pathToMember.entries()].filter(([, m]) => m.excluded).map(([k]) => 'm:' + k);
const reachedFromKeep = bfs(keptRoots);
const reachedFromExclude = bfs(excludeRoots);
if (!reachedFromKeep || !reachedFromExclude) process.exit(0);

// Drop set: reached from an excluded root, not reached from any kept root
// (any way at all), and -- for an external package -- not protected. A
// dropped member's own name@version joins the very same pool an external
// package purl is matched against below: its component carries an ordinary
// pkg:npm purl too, so one drop set and one filter pass cover both.
const dropNV = new Set();
for (const token of reachedFromExclude) {
  if (reachedFromKeep.has(token)) continue;
  if (token.charCodeAt(0) === 109 /* 'm' */) {
    const m = pathToMember.get(token.slice(2));
    if (m.name && m.version) dropNV.add(m.name + '@' + m.version);
  } else {
    const nv = token.slice(2);
    if (!protectedNV.has(nv)) dropNV.add(nv);
  }
}
if (dropNV.size === 0) process.exit(0);

const refOf = c => c['bom-ref'] || c.purl;
const nvOfPurl = purl => {
  const m = /^pkg:npm\/([^@]+)@([^?]+)/.exec(purl || '');
  return m ? decodeURIComponent(m[1]) + '@' + decodeURIComponent(m[2]) : null;
};
const droppedPurls = [];
const keep = c => {
  const nv = nvOfPurl(c.purl);
  if (!nv || !dropNV.has(nv)) return true;
  droppedPurls.push(c.purl);
  return false;
};
const before = bom.components.length;
bom.components = bom.components.filter(keep);
if (droppedPurls.length === 0) process.exit(0);

const mc = bom.metadata && bom.metadata.component;
const keptRefs = new Set(bom.components.map(refOf));
if (mc) keptRefs.add(mc['bom-ref'] || mc.purl);
bom.dependencies = bom.dependencies
  .filter(d => keptRefs.has(d.ref))
  .map(d => Array.isArray(d.dependsOn) ? Object.assign({}, d, { dependsOn: d.dependsOn.filter(r => keptRefs.has(r)) }) : d);

function mergeCapped(existing, additions, limit) {
  let shown = [];
  let priorTotal = 0;
  if (existing) {
    const m = /^(.*?)(?: \(\+(\d+) more\))?$/.exec(existing);
    shown = m[1] ? m[1].split(', ').filter(Boolean) : [];
    priorTotal = shown.length + (m[2] ? parseInt(m[2], 10) : 0);
  }
  const merged = shown.concat(additions);
  const total = priorTotal + additions.length;
  let val = merged.slice(0, limit).join(', ');
  const hidden = total - Math.min(limit, merged.length);
  if (hidden > 0) val += ' (+' + hidden + ' more)';
  return val;
}
const LIMIT = 50;
bom.metadata = bom.metadata || {};
const existingProps = bom.metadata.properties || [];
const priorMembers = (existingProps.find(p => p.name === 'bomlens:excluded-members') || {}).value || null;
const priorComponents = (existingProps.find(p => p.name === 'bomlens:excluded-components') || {}).value || null;
const memberList = excludedMembers.map(m => 'pnpm:' + m.relPath + ' (' + (m.name || '(unnamed)') + ')');
const props = existingProps.filter(p => p.name !== 'bomlens:excluded-members' && p.name !== 'bomlens:excluded-components');
props.push({ name: 'bomlens:excluded-members', value: mergeCapped(priorMembers, memberList, LIMIT) });
props.push({ name: 'bomlens:excluded-components', value: mergeCapped(priorComponents, droppedPurls, LIMIT) });
bom.metadata.properties = props;

fs.writeFileSync(bomPath, JSON.stringify(bom, null, 2));
process.stderr.write('[build-prep] pnpm: excluded ' + excludedMembers.length + ' workspace member(s), dropped ' + (before - bom.components.length) + ' of ' + before + ' components\n');
PWMF_JS
        node "$_pwmf" "$OUT" "$_pwtreef" "$NON_SHIPPED_DIRS" || log "pnpm: workspace-member filter skipped (non-fatal)"
        rm -f "$_pwmf" "$_pwtreef"
    else
        log "pnpm: could not resolve workspace tree; skipping workspace-member filter"
    fi
fi

# Maven parent-POM license inheritance: a project commonly declares
# <licenses> once, on a parent pom, and leaves the child silent about it,
# relying on Maven's own effective-POM inheritance. cdxgen reads each
# component's own pom.xml, not the effective one, so a component this reads
# as having no license at all -- correct for that one file, wrong for what it
# actually ships under. Applies to any Maven component in the SBOM, not only
# the scanned project's own reactor modules: a dependency resolved from the
# local repository (spring-boot-starter-web's own transitive jul-to-slf4j,
# say) has this exact shape just as often, its <parent> naming a coordinate
# (spring-boot-starter-parent) with no reactor directory to walk to at all.
#
# Walks the parent chain like the non-deployed-module filter above, but a
# link can point two different places: a <relativePath> that resolves to an
# actual pom.xml on disk (a reactor module's parent, most often), or --
# whenever that does not resolve, including when relativePath is absent
# entirely -- the parent's own group/artifact/version looked up in this run's
# own local repository, populated as a side effect of cdxgen's own Maven
# resolve above. Maven itself needs every ancestor's pom to compute an
# effective POM, so the chain is there to read, offline, no `mvn` invocation
# needed either way.
#
# Runs independently of BOMLENS_MAVEN_FULL_GRAPH -- that switch is about
# whether non-deployed modules get dropped from the graph, an unrelated
# question from whether a license gets filled in. A depth cap backstops the
# visited set: a long but non-cyclic chain, which a visited set alone would
# never catch, still terminates. Only fills a component whose OWN pom.xml
# declares no <licenses> at all (checked on the parsed pom.xml itself, not
# merely the SBOM component -- one that does declare one but that cdxgen
# failed to carry through is a cdxgen gap, not a case this fills over with a
# possibly different parent value) and only when an ancestor's pom.xml does
# declare one.
if [ "${rc:-1}" -eq 0 ] && [ -f pom.xml ] && [ -f "$OUT" ] && command -v node >/dev/null 2>&1; then
    log "maven: inheriting missing licenses from a parent POM"
    _mlic=$(mktemp).js
    cat > "$_mlic" <<'MLIC_JS'
const fs = require('fs');
const path = require('path');
const [bomPath, m2Root] = process.argv.slice(2);
let bom;
try { bom = JSON.parse(fs.readFileSync(bomPath, 'utf8')); } catch (e) { process.exit(0); }
if (!Array.isArray(bom.components)) process.exit(0);

const POM_MAX_BYTES = 2 * 1024 * 1024;
const POM_PARSE_BUDGET_MS = 2000;
const TAG_RE = /<([A-Za-z_][\w.:-]*)((?:\s+[^>]*?)?)(\/?)>/y;
function parseXml(src) {
  if (src.length > POM_MAX_BYTES) return null;
  src = src.replace(/<\?[\s\S]*?\?>/g, '').replace(/<!--[\s\S]*?-->/g, '');
  let i = 0;
  const n = src.length;
  const deadline = Date.now() + POM_PARSE_BUDGET_MS;
  let steps = 0;
  function overBudget() { return (++steps & 0xfff) === 0 && Date.now() > deadline; }
  function skipWs() { while (i < n && /\s/.test(src[i])) i++; }
  function parseNode() {
    skipWs();
    if (src[i] !== '<') return null;
    TAG_RE.lastIndex = i;
    const m = TAG_RE.exec(src);
    if (!m || m.index !== i) return null;
    i = TAG_RE.lastIndex;
    const tag = m[1];
    const node = { tag, children: [], text: '' };
    if (m[3] === '/') return node;
    const closeTag = '</' + tag + '>';
    while (i < n) {
      if (overBudget()) throw new Error('parse budget exceeded');
      skipWs();
      if (src.startsWith(closeTag, i)) { i += closeTag.length; return node; }
      if (src[i] === '<') {
        if (src.startsWith('</', i)) { const end = src.indexOf('>', i); i = end < 0 ? n : end + 1; return node; }
        if (src.startsWith('<![CDATA[', i)) {
          const end = src.indexOf(']]>', i);
          i = end < 0 ? n : end + 3;
          continue;
        }
        const beforeChild = i;
        const child = parseNode();
        if (child) node.children.push(child);
        if (i === beforeChild) { const end = src.indexOf('>', i); i = end < 0 ? n : end + 1; }
      } else {
        const next = src.indexOf('<', i);
        node.text += next < 0 ? src.slice(i) : src.slice(i, next);
        i = next < 0 ? n : next;
      }
    }
    return node;
  }
  try {
    const roots = [];
    while (i < n) {
      if (overBudget()) throw new Error('parse budget exceeded');
      skipWs();
      if (i >= n) break;
      const before = i;
      const node = parseNode();
      if (node) roots.push(node);
      if (i === before) break;
    }
    return roots.find(r => r.tag === 'project') || null;
  } catch (e) {
    return null;
  }
}
const decodeEntities = s => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&apos;/g, "'");
const directChild = (node, tag) => node ? (node.children.find(c => c.tag === tag) || null) : null;
const directChildren = (node, tag) => node ? node.children.filter(c => c.tag === tag) : [];
const directText = node => node ? decodeEntities(node.text).trim() : '';

const MAX_PARENT_DEPTH = 10;

// A location is either a reactor directory ({dir}) or a local-repository
// coordinate ({gav}) -- the two places a pom.xml can actually be read from
// offline. The local repository layout names a group/artifact/version's pom
// deterministically: group with dots turned to path segments, then
// artifact/version/artifact-version.pom, no classifier.
function m2PomPath(gav) {
  return path.join(m2Root, ...gav.group.split('.'), gav.artifact, gav.version,
    gav.artifact + '-' + gav.version + '.pom');
}
function locationKey(loc) {
  return loc.dir ? 'dir:' + path.resolve(loc.dir)
                 : 'gav:' + loc.gav.group + ':' + loc.gav.artifact + ':' + loc.gav.version;
}
function loadPom(loc) {
  const pomPath = loc.dir ? path.join(loc.dir, 'pom.xml') : m2PomPath(loc.gav);
  let text;
  try { text = fs.readFileSync(pomPath, 'utf8'); } catch (e) { return null; }
  const project = parseXml(text);
  return project ? { dir: loc.dir || null, project } : null;
}
// Where a <parent> points next: relativePath if it names an actual pom.xml
// on disk (only possible from a reactor directory), else the parent
// coordinate's own pom in the local repository.
function parentLocation(project, currentDir) {
  const parent = directChild(project, 'parent');
  if (!parent) return null;
  if (currentDir !== null) {
    const relPathNode = directChild(parent, 'relativePath');
    const relPath = relPathNode ? directText(relPathNode) : '../pom.xml';
    if (relPath !== '') {
      const candidateDir = path.dirname(path.join(currentDir, relPath));
      if (fs.existsSync(path.join(candidateDir, 'pom.xml'))) return { dir: candidateDir };
    }
  }
  const g = directText(directChild(parent, 'groupId'));
  const a = directText(directChild(parent, 'artifactId'));
  const v = directText(directChild(parent, 'version'));
  return (g && a && v) ? { gav: { group: g, artifact: a, version: v } } : null;
}
function loadChain(startLoc, seen, depth) {
  seen = seen || new Set();
  depth = depth || 0;
  if (depth >= MAX_PARENT_DEPTH) return [];
  const key = locationKey(startLoc);
  if (seen.has(key)) return [];
  seen.add(key);
  const loaded = loadPom(startLoc);
  if (!loaded) return [];
  const chain = [loaded];
  const next = parentLocation(loaded.project, loaded.dir);
  if (next) chain.push(...loadChain(next, seen, depth + 1));
  return chain;
}
function enumerateModules(rootDir) {
  const out = [];
  function walk(dir) {
    let text;
    try { text = fs.readFileSync(path.join(dir, 'pom.xml'), 'utf8'); } catch (e) { return; }
    const project = parseXml(text);
    if (!project) return;
    out.push({ dir, project });
    const modulesNode = directChild(project, 'modules');
    if (!modulesNode) return;
    for (const modNode of directChildren(modulesNode, 'module')) {
      const rel = directText(modNode);
      if (rel) walk(path.join(dir, rel));
    }
  }
  walk(rootDir);
  return out;
}
function gaOfProject(project) {
  const artifactId = directChild(project, 'artifactId');
  let groupId = directChild(project, 'groupId');
  if (!groupId) { const parent = directChild(project, 'parent'); groupId = parent ? directChild(parent, 'groupId') : null; }
  return (groupId ? directText(groupId) : '?') + ':' + (artifactId ? directText(artifactId) : '?');
}
function licensesOf(project) {
  const lics = directChild(project, 'licenses');
  if (!lics) return [];
  const out = [];
  for (const lic of directChildren(lics, 'license')) {
    const name = directText(directChild(lic, 'name'));
    if (name) out.push(name);
  }
  return out;
}

// A reactor module's own directory, keyed by group:artifact so a component
// resolved from the local build (version always matches what was just
// built) starts its chain on the actual checkout rather than a redundant
// .m2 copy; anything else starts straight from its own .m2 coordinate.
const reactorDirByGA = new Map();
for (const { dir, project } of enumerateModules('.')) reactorDirByGA.set(gaOfProject(project), dir);

const MAVEN_PURL_RE = /^pkg:maven\/([^/]+)\/([^@]+)@([^?]+)/;
function gavOfPurl(purl) {
  const m = MAVEN_PURL_RE.exec(purl || '');
  return m ? { group: decodeURIComponent(m[1]), artifact: decodeURIComponent(m[2]), version: decodeURIComponent(m[3]) } : null;
}

let filled = 0;
for (const c of bom.components) {
  if (Array.isArray(c.licenses) && c.licenses.length > 0) continue;
  const gav = gavOfPurl(c.purl);
  if (!gav) continue;
  const reactorDir = reactorDirByGA.get(gav.group + ':' + gav.artifact);
  const chain = loadChain(reactorDir ? { dir: reactorDir } : { gav });
  if (chain.length === 0 || licensesOf(chain[0].project).length > 0) continue;
  let names = [];
  for (let i = 1; i < chain.length; i++) {
    names = licensesOf(chain[i].project);
    if (names.length) break;
  }
  if (!names.length) continue;
  c.licenses = names.map(name => ({ license: { name } }));
  c.properties = (c.properties || []).filter(p => p.name !== 'bomlens:licenseSource')
    .concat([{ name: 'bomlens:licenseSource', value: 'parent POM' }]);
  filled++;
}
if (filled) {
  fs.writeFileSync(bomPath, JSON.stringify(bom, null, 2));
  process.stderr.write('[build-prep] maven: inherited a parent POM license for ' + filled + ' component(s)\n');
}
MLIC_JS
    node "$_mlic" "$OUT" "/tmp/sbomhome/.m2" || log "maven: parent-POM license inheritance skipped (non-fatal)"
    rm -f "$_mlic"
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
# the license files themselves, the trove classifiers, and a `License:` field. We
# read those in that order and only overwrite a component's license when the
# evidence settles on exactly one answer.
#
# A license file that carries the notices of bundled dependencies matches several
# templates at once. Rather than give up on all of them, we read the license the
# file OPENS with (the project's own) and confirm it against the distribution's
# trove classifiers: pandas' file is BSD-3-Clause followed by Bottleneck's,
# dateutil's and an MIT notice, and its one classifier says BSD. A file whose
# leading license the classifiers do not back, a genuinely dual-licensed
# distribution (two families claimed, or two license files that disagree), and a
# declared name too vague to place, like a bare "BSD", all still leave the
# component alone for a human to read. Whatever we do set is stamped with
# bomlens:licenseSource so the basis is visible in the SBOM.
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

    Same matching as identify_license_text in docker/lib/spdx-normalize.jq:
    clause phrases, never the copyright header, and deliberately silent when a
    text matches more than one template.

    The two are INTENTIONALLY no longer symmetric beyond this function. Here we
    can go further (classify_leading below reads which license a multi-license
    file LEADS with) because an installed distribution also carries trove
    classifiers to confirm the reading against. A raw SBOM has no such second
    source, so spdx-normalize.jq stops at the ambiguity.
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


# The opening clause of each license template, used to find where a license
# STARTS rather than merely whether it appears. Ordered as (family, anchor);
# the clause count of a BSD text is settled later, from that text alone.
ANCHORS = (
    ("mit", "permission is hereby granted, free of charge"),
    ("isc", "permission to use, copy, modify, and/or distribute this software for any purpose"),
    ("apache", "apache license"),
    ("bsd", "redistributions of source code must retain"),
)
# How far into a license file the primary license may start (normalised
# characters). A license file opens with at most a title and a copyright line
# before the terms: numpy's begins ~120 characters in, pandas' ~350. Appended
# third-party notices are by definition further down than this.
LEAD_LIMIT = 600
# Longest stretch treated as belonging to one license, when no other license
# starts sooner. The longest of these templates (Apache-2.0) is well under it.
SECTION_LIMIT = 3000


def settle_clauses(family, window):
    """Turn a matched family into an SPDX id, using one license's text only."""
    if family == "mit":
        return "MIT" if "without restriction" in window else None
    if family == "isc":
        return "ISC"
    if family == "apache":
        return "Apache-2.0" if "version 2.0" in window else None
    if family == "bsd":
        if ("redistributions in binary form must reproduce" not in window
                or "advertising materials" in window):
            return None
        return "BSD-3-Clause" if "neither the name" in window else "BSD-2-Clause"
    return None


def family_of(spdx_id):
    """The license family an SPDX id belongs to, for classifier confirmation."""
    if spdx_id.startswith("BSD-"):
        return "bsd"
    return {"MIT": "mit", "Apache-2.0": "apache", "ISC": "isc"}.get(spdx_id)


def classify_leading(text):
    """Identify the license a multi-license text LEADS with.

    A license file that also carries the notices of bundled dependencies matches
    several templates at once, and classify_text goes silent on it, which is
    why pandas kept the Apache-2.0 that cdxgen read off python-dateutil's notice
    inside pandas' own BSD-3-Clause file.

    The primary license is the one the file opens with, so we take the earliest
    template opening and require it to sit in the head of the file (LEAD_LIMIT).
    Everything after it is another project's notice, and every further check runs
    inside that first license's own window, up to wherever the next license
    starts. Reading the clause count outside the window is how a bundled BSD-3
    would turn a BSD-2 text into BSD-3-Clause.

    Returns None for a single-license text (classify_text's job) and for
    anything that does not settle. The caller must still confirm the answer
    against the distribution's trove classifiers.
    """
    x = re.sub(r"\s+", " ", text).lower()
    starts = []
    for family, anchor in ANCHORS:
        pos = x.find(anchor)
        if pos >= 0:
            starts.append((pos, family, anchor))
    if not starts:
        return None
    # A single template that appears once is an ordinary license file, and
    # classify_text already reads it. A template that appears twice is not: the
    # second copy is a bundled notice, and its clauses must be kept out.
    if len(starts) < 2 and x.find(starts[0][2], starts[0][0] + 1) < 0:
        return None
    starts.sort()
    pos, family, _anchor = starts[0]
    if pos > LEAD_LIMIT:
        # The file opens with something else (a preamble listing bundled
        # components, an aggregate notice); we cannot say what governs it.
        return None
    # The window ends where the next license begins, including a second
    # occurrence of the same template, which is how a bundled BSD notice after a
    # BSD license is kept out of the clause count.
    ends = []
    for _family, anchor in ANCHORS:
        nxt = x.find(anchor, pos + 1)
        if nxt > pos:
            ends.append(nxt)
    end = min(ends) if ends else len(x)
    return settle_clauses(family, x[pos:min(end, pos + SECTION_LIMIT)])


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
        # Longer than any license NAME: this is a license text in the field
        # (setuptools has long allowed it, and pandas ships 63 KB there).
        # classify_declared_text reads those.
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


def classify_declared_text(ev):
    """Read an over-long `License:` field as license TEXT rather than a name.

    Core metadata puts a NAME in this field, but setuptools never enforced it
    and projects paste the whole license in (pandas' is 63 KB, bundled notices
    and all). classify_name rightly refuses to treat that as a name; here we
    classify it the same way a license file is classified, under the same
    confirmation rule. Reached only when no license file settled the question.
    """
    text = ev["declared"] or ""
    if len(text) <= 100:
        return None
    got = classify_leading(text) or classify_text(text)
    return got if got and confirms(ev, got) else None


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


def classifier_families(meta):
    """License families named by a distribution's trove classifiers.

    PyPI files every variant of a family under one classifier ("License :: OSI
    Approved :: BSD License" covers the 2-, 3- and 4-clause texts alike), so this
    can never pick a license on its own: reading a clause count out of it is the
    very mistake this pass exists to undo. It is used only to confirm what a
    license text already said, and a distribution that names two families
    confirms nothing.
    """
    fams = set()
    try:
        classifiers = meta.get_all("Classifier") or []
    except Exception:
        return fams
    for entry in classifiers:
        c = str(entry).lower()
        if not c.startswith("license ::"):
            continue
        if c.endswith(":: bsd license"):
            fams.add("bsd")
        elif c.endswith(":: mit license"):
            fams.add("mit")
        elif c.endswith(":: apache software license"):
            fams.add("apache")
        elif c.endswith(":: isc license (iscl)"):
            fams.add("isc")
        elif c not in ("license :: osi approved", "license :: other/proprietary license"):
            # Some other named license (GPL, MPL, a project-specific one): not a
            # family we match, but it still means the distribution claims more
            # than one thing if a matched family is also present.
            fams.add(c)
    return fams


def evidence(dist):
    """Collect (version, expression, declared name, files, families) for a dist."""
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
            "families": classifier_families(meta),
            "files": license_files(dist)}


def confirms(ev, spdx_id):
    """True when the distribution's classifiers name that family and no other."""
    fam = family_of(spdx_id)
    return bool(fam) and ev["families"] == {fam}


def decide(ev):
    if ev["expression"]:
        return ev["expression"], "installed license expression"
    ids, from_lead = set(), False
    for path in ev["files"]:
        text = read_text(path)
        plain = classify_text(text)
        lead = classify_leading(text)
        # The leading license only overrides the whole-text reading when the two
        # disagree AND the classifiers back it. Otherwise the file is read exactly
        # as before, so an unconfirmed guess never makes things worse.
        if lead and lead != plain and confirms(ev, lead):
            ids.add(lead)
            from_lead = True
        elif plain:
            ids.add(plain)
    if len(ids) == 1:
        return ids.pop(), "installed license text (leading)" if from_lead \
            else "installed license text"
    if not ids and ev["declared"]:
        got = classify_name(ev["declared"])
        if got:
            return got, "installed license name"
        got = classify_declared_text(ev)
        if got:
            return got, "declared license text"
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
    # Nothing is installed here, so nothing can be checked. Say so: this is what
    # a failed `pip install` looks like from the SBOM's side, and in silence it
    # is indistinguishable from a run where every license was already right.
    sys.stderr.write("[build-prep] python: no installed distribution metadata found; "
                     "licenses left as the generator resolved them\n")
    sys.exit(0)

changed = missing = 0
for comp in components:
    if not str(comp.get("purl") or "").startswith("pkg:pypi/"):
        continue
    ev = index.get((canon(comp.get("name")), comp.get("version")))
    if not ev:
        missing += 1
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
if missing:
    # Usually a package the install could not reach (a failed pin, a private
    # index) or a version cdxgen resolved differently from the one installed.
    # Those components keep the generator's license, unchecked.
    sys.stderr.write("[build-prep] python: %d pypi component(s) had no installed evidence\n" % missing)
PY_LIC
    python3 "$_pylic" "$OUT" || log "python: license evidence pass skipped (non-fatal)"
    rm -f "$_pylic"
fi

# Copyright statements from the license files each installed package ships.
# cdxgen leaves component.copyright empty, so the NOTICE has no attribution line
# to print. The installed packages exist only until guard_restore below, and only
# in this container, so the statements have to be read here.
#
# Only the package's own license files are read (LICENSE, LICENCE, COPYING,
# NOTICE, COPYRIGHT), and only a line that opens with "Copyright", "(c)" or the
# copyright sign and then gives a year, another (c), or "by". A component that
# already has a copyright is left alone, a statement that cannot be tied to a
# package is dropped, and every value set is stamped bomlens:copyrightSource.
# BOMLENS_NO_COPYRIGHT=1 (or true) turns the pass off.
#
# Go and Rust read the same way, through the shared node script below: Go from the
# folders `go list -m` reports (the module cache, a replacement's folder) and from
# vendor/, Rust from the folders `cargo metadata --offline` reports (the registry, git
# checkouts, path dependencies). The scanned project's own module or crates are
# skipped. Maven is not covered: it downloads jars, not source trees.
if opted_out "${BOMLENS_NO_COPYRIGHT:-}"; then
    log "copyright: pass off (BOMLENS_NO_COPYRIGHT)"
elif [ "${rc:-1}" -eq 0 ] && [ -f "$OUT" ]; then
    if command -v python3 >/dev/null 2>&1 && grep -q '"pkg:pypi/' "$OUT" 2>/dev/null; then
        log "copyright: reading license files of installed python packages"
        _pycpr=$(mktemp)
        cat > "$_pycpr" <<'PY_CPR'
import json, os, re, stat, sys
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

FILE_RE = re.compile(r"^(licen[sc]e|copying|notice|copyright)([-_.].*)?$", re.I)
NEEDS_RE = re.compile(r"^[\s#*/;>|-]*(?:copyright\s*(?:\(c\)|\u00a9|&copy;|\d{4}|by\b)"
                      r"|(?:\(c\)|\u00a9|&copy;)\s*\d{4})", re.I)
# What is left of a statement once the marker, years and punctuation are removed must
# still name someone.
FILLER_RE = re.compile(r"copyright|\(c\)|\u00a9|&copy;|all rights reserved|\bby\b|[\d\s,.:;-]", re.I)
# A template the package never filled in: <year>, [fullname], {{author}}, "year name of
# author", "YEAR by AUTHOR EMAIL".
WORDS = r"(?:year|yyyy|names?|owners?|holders?|authors?|fullname|full|email|organi[sz]ation|company|copyright|of|and|your|the)"
PLACEHOLDER_RE = re.compile(r"[<\[{]{1,2}\s*" + WORDS + r"(?:[\s,]+" + WORDS + r")*\s*[>\]}]{1,2}"
                            r"|\byear\s+name\s+of\s+author\b", re.I)
UPPER_RE = re.compile(r"\b(?:YEAR|AUTHOR|OWNER|EMAIL)\b")
# Text that belongs to a license, not to the package that ships it.
BOILERPLATE_RE = re.compile(r"free software foundation|stichting mathematisch|"
                            r"corporation for national research|internet (?:systems|software) consortium", re.I)
PROSE_RE = re.compile(r"\b(?:notice|permission|shall|consisting|hereby|herein|conditions|provided|following)\b", re.I)
HEAD_BYTES, MAX_FILES, MAX_LINES, MAX_STATEMENTS, MAX_LEN = 65536, 6, 400, 5, 200


def canon(name):
    return re.sub(r"[-_.]+", "-", (name or "").strip()).lower()


def clean(line):
    text = re.sub(r"^[\s#*/;>|-]+|[\s#*/;|-]+$", "", line)
    return re.sub(r"\s+", " ", text).replace("&copy;", "(c)")


def read_head(path, root):
    """First HEAD_BYTES of a regular file that really lives under root."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return ""
        real = os.path.realpath(path)
        if not real.startswith(root + os.sep):
            return ""
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(HEAD_BYTES)
    except Exception:
        return ""


def statements_in(path, root):
    found = []
    lines = [ln.rstrip("\r") for ln in read_head(path, root).split("\n")[:MAX_LINES]]
    for n, line in enumerate(lines):
        if len(line) > MAX_LEN * 2 or not NEEDS_RE.match(line):
            continue
        text = clean(line)
        # A holder that runs onto the next line ("..., Stichting X," then "The Netherlands").
        if text.endswith(",") and n + 1 < len(lines):
            nxt = lines[n + 1]
            if nxt.strip() and not NEEDS_RE.match(nxt):
                text = clean(text + " " + nxt.strip())
        text = text.rstrip(",")
        if (not text or len(text) > MAX_LEN or PLACEHOLDER_RE.search(text) or UPPER_RE.search(text)
                or BOILERPLATE_RE.search(text) or PROSE_RE.search(text)
                or not re.search(r"[^\W\d_]", FILLER_RE.sub("", text))):
            continue
        found.append(text)
    return found


def key_of(text):
    text = re.sub(r"<[^>]*>", "", text.lower()).replace("\u00a9", "").replace("(c)", "")
    return re.sub(r"\s+", " ", text).strip().rstrip(".,;")


def collapse(found):
    """Drop repeats and any statement that only abbreviates a longer one."""
    kept = []
    for text in found:
        key = key_of(text)
        for i, (k, t) in enumerate(kept):
            if k.startswith(key) or key.startswith(k):
                if len(text) > len(t):
                    kept[i] = (key, text)
                break
        else:
            kept.append((key, text))
    return [t for _, t in kept][:MAX_STATEMENTS]


def dist_files(dist):
    """(path, root) pairs: the license files an installed distribution ships, and the
    directory each must stay under."""
    found, seen = [], set()

    def add(path, root):
        if path not in seen and os.path.isfile(path):
            seen.add(path)
            found.append((path, root))

    try:
        base = str(getattr(dist, "_path", "") or "")
        if base and os.path.isdir(base):
            root = os.path.realpath(base)
            for rel in (dist.metadata.get_all("License-File") or []):
                for sub in (os.path.join(base, "licenses"), base):
                    cand = os.path.join(sub, rel)
                    if os.path.isfile(cand):
                        add(cand, root)
                        break
            for cur, _dirs, names in os.walk(base):
                for fn in sorted(names):
                    if FILE_RE.match(fn):
                        add(os.path.join(cur, fn), root)
        # An egg-info install records no license file of its own; a wheel whose
        # metadata directory we could not locate still lists its files.
        if not found:
            root = os.path.realpath(str(dist.locate_file("")))
            for entry in (dist.files or []):
                if FILE_RE.match(os.path.basename(str(entry))):
                    add(str(dist.locate_file(entry)), root)
    except Exception:
        pass
    return found[:MAX_FILES]

index = {}
for dist in distributions():
    try:
        name, version = dist.metadata.get("Name"), dist.metadata.get("Version")
    except Exception:
        continue
    if name and version:
        index.setdefault((canon(name), version), dist)

if not index:
    sys.stderr.write("[build-prep] copyright: no installed python distribution metadata found; "
                     "python components left as they were\n")
    sys.exit(0)

changed = 0
for comp in components:
    if not str(comp.get("purl") or "").startswith("pkg:pypi/") or comp.get("copyright"):
        continue
    dist = index.get((canon(comp.get("name")), comp.get("version")))
    if not dist:
        continue
    found = []
    for path, root in dist_files(dist):
        found.extend(statements_in(path, root))
    found = collapse(found)
    if not found:
        continue
    comp["copyright"] = "; ".join(found)
    props = [p for p in comp.get("properties") or []
             if p.get("name") != "bomlens:copyrightSource"]
    props.append({"name": "bomlens:copyrightSource", "value": "installed license file"})
    comp["properties"] = props
    changed += 1

if changed:
    with open(bom_path, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=2)
    sys.stderr.write("[build-prep] copyright: filled %d python component(s) from installed license files\n" % changed)
PY_CPR
        python3 "$_pycpr" "$OUT" || log "copyright: python pass skipped (non-fatal)"
        rm -f "$_pycpr"
    fi
    # Same depth as guard_paths: a node_modules nested deeper than four levels in a
    # monorepo is not searched, and its components keep no copyright.
    _nmdirs=""
    if command -v node >/dev/null 2>&1 && grep -q '"pkg:npm/' "$OUT" 2>/dev/null; then
        _nmdirs=$(find . -maxdepth 4 -name .git -prune -o -type d -name node_modules -print -prune 2>/dev/null)
    fi
    _cprgo=""
    _cprcargo=""
    if command -v node >/dev/null 2>&1; then
        [ -f go.mod ] && command -v go >/dev/null 2>&1 && grep -q '"pkg:golang/' "$OUT" 2>/dev/null && _cprgo=1
        [ -f Cargo.toml ] && command -v cargo >/dev/null 2>&1 && grep -q '"pkg:cargo/' "$OUT" 2>/dev/null && _cprcargo=1
    fi
    if [ -n "$_nmdirs" ] || [ -n "$_cprgo" ] || [ -n "$_cprcargo" ]; then
        _jscpr=$(mktemp)
        cat > "$_jscpr" <<'NODE_CPR'
const fs = require('fs');
const path = require('path');
const bomPath = process.argv[2];
const roots = (process.env.BOMLENS_NM_DIRS || '').split('\n').filter(Boolean);
// Go and Rust hand over a name@version -> directory index instead of a node_modules tree.
const indexFile = process.env.BOMLENS_CPR_INDEX || '';
const purlPrefix = process.env.BOMLENS_CPR_PURL_PREFIX || 'pkg:npm/';
let bom;
try { bom = JSON.parse(fs.readFileSync(bomPath, 'utf8')); } catch (e) { process.exit(0); }
// Only to say that an ecosystem's license files could not be listed at all.
if (process.env.BOMLENS_CPR_UNREAD) {
  bom.metadata = bom.metadata || {};
  const props = bom.metadata.properties = bom.metadata.properties || [];
  const held = props.find(p => p.name === 'bomlens:copyrightUnread');
  if (held) held.value = held.value.split(',').concat(process.env.BOMLENS_CPR_UNREAD).filter((v, i, a) => a.indexOf(v) === i).join(',');
  else props.push({ name: 'bomlens:copyrightUnread', value: process.env.BOMLENS_CPR_UNREAD });
  fs.writeFileSync(bomPath, JSON.stringify(bom, null, 2));
  process.exit(0);
}
if (!Array.isArray(bom.components)) process.exit(0);

const FILE_RE = /^(licen[sc]e|copying|notice|copyright)([-_.].*)?$/i;
const NEEDS_RE = /^[\s#*/;>|-]*(?:copyright\s*(?:\(c\)|\u00a9|&copy;|\d{4}|by\b)|(?:\(c\)|\u00a9|&copy;)\s*\d{4})/i;
// What is left of a statement once the marker, years and punctuation are removed must
// still name someone.
const FILLER_RE = /copyright|\(c\)|\u00a9|&copy;|all rights reserved|\bby\b|[\d\s,.:;-]/gi;
// A template the package never filled in: <year>, [fullname], {{author}}, "year name of
// author", "YEAR by AUTHOR EMAIL".
const WORDS = '(?:year|yyyy|names?|owners?|holders?|authors?|fullname|full|email|organi[sz]ation|company|copyright|of|and|your|the)';
const PLACEHOLDER_RE = new RegExp('[<\\[{]{1,2}\\s*' + WORDS + '(?:[\\s,]+' + WORDS + ')*\\s*[>\\]}]{1,2}'
  + '|\\byear\\s+name\\s+of\\s+author\\b', 'i');
const UPPER_RE = /\b(?:YEAR|AUTHOR|OWNER|EMAIL)\b/;
// Text that belongs to a license, not to the package that ships it.
const BOILERPLATE_RE = /free software foundation|stichting mathematisch|corporation for national research|internet (?:systems|software) consortium/i;
const PROSE_RE = /\b(?:notice|permission|shall|consisting|hereby|herein|conditions|provided|following)\b/i;
const HEAD_BYTES = 65536, MAX_FILES = 6, MAX_LINES = 400, MAX_STATEMENTS = 5, MAX_LEN = 200;

function clean(line) {
  return line.replace(/^[\s#*/;>|-]+|[\s#*/;|-]+$/g, '').replace(/\s+/g, ' ').replace(/&copy;/g, '(c)');
}

// First HEAD_BYTES of a regular file that really lives under root.
function readHead(file, root) {
  let fd;
  try {
    if (!fs.lstatSync(file).isFile()) return '';
    if (!fs.realpathSync(file).startsWith(root + path.sep)) return '';
    fd = fs.openSync(file, 'r');
    const buf = Buffer.alloc(HEAD_BYTES);
    const n = fs.readSync(fd, buf, 0, HEAD_BYTES, 0);
    return buf.toString('utf8', 0, n);
  } catch (e) {
    return '';
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch (e) { /* closed */ }
  }
}

function statementsIn(file, root) {
  const found = [];
  const lines = readHead(file, root).split(/\r?\n/).slice(0, MAX_LINES);
  lines.forEach((line, n) => {
    if (line.length > MAX_LEN * 2 || !NEEDS_RE.test(line)) return;
    let t = clean(line);
    // A holder that runs onto the next line ("..., Stichting X," then "The Netherlands").
    if (t.endsWith(',') && n + 1 < lines.length) {
      const nxt = lines[n + 1];
      if (nxt.trim() && !NEEDS_RE.test(nxt)) t = clean(t + ' ' + nxt.trim());
    }
    t = t.replace(/,+$/, '');
    if (!t || t.length > MAX_LEN || PLACEHOLDER_RE.test(t) || UPPER_RE.test(t)
        || BOILERPLATE_RE.test(t) || PROSE_RE.test(t)
        || !/[\p{L}]/u.test(t.replace(FILLER_RE, ''))) return;
    found.push(t);
  });
  return found;
}

function keyOf(t) {
  return t.toLowerCase().replace(/<[^>]*>/g, '').replace(/\u00a9|\(c\)/g, '')
    .replace(/\s+/g, ' ').trim().replace(/[.,;]+$/, '');
}

// Drop repeats and any statement that only abbreviates a longer one.
function collapse(found) {
  const kept = [];
  for (const t of found) {
    const key = keyOf(t);
    const i = kept.findIndex(k => k[0].startsWith(key) || key.startsWith(k[0]));
    if (i === -1) kept.push([key, t]);
    else if (t.length > kept[i][1].length) kept[i] = [key, t];
  }
  return kept.map(k => k[1]).slice(0, MAX_STATEMENTS);
}

// name@version -> the package directory that holds its license files
const index = new Map();
const seen = new Set();
function walk(nm) {
  let real;
  try { real = fs.realpathSync(nm); } catch (e) { return; }
  if (seen.has(real)) return;
  seen.add(real);
  let entries;
  try { entries = fs.readdirSync(nm, { withFileTypes: true }); } catch (e) { return; }
  for (const e of entries) {
    if (e.name === '.bin' || (e.name.startsWith('.') && e.name !== '.pnpm')) continue;
    const dir = path.join(nm, e.name);
    if (e.name === '.pnpm') {
      try { fs.readdirSync(dir).forEach(v => walk(path.join(dir, v, 'node_modules'))); } catch (x) { /* none */ }
      continue;
    }
    if (e.name.startsWith('@')) {
      try { fs.readdirSync(dir).forEach(s => pkg(path.join(dir, s))); } catch (x) { /* none */ }
    } else {
      pkg(dir);
    }
  }
}
function pkg(dir) {
  let meta;
  try { meta = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')); } catch (e) { return; }
  // A package.json states its own name; only trust it where the folder agrees.
  if (meta && meta.name && meta.version && path.basename(dir) === String(meta.name).split('/').pop()) {
    const key = meta.name + '@' + meta.version;
    if (!index.has(key)) index.set(key, dir);
  }
  walk(path.join(dir, 'node_modules'));
}
if (indexFile) {
  try {
    const given = JSON.parse(fs.readFileSync(indexFile, 'utf8'));
    for (const k of Object.keys(given)) index.set(k, given[k]);
  } catch (e) { process.exit(0); }
} else {
  roots.forEach(walk);
}

let changed = 0;
for (const c of bom.components) {
  if (!String(c.purl || '').startsWith(purlPrefix) || c.copyright || !c.name || !c.version) continue;
  const dir = index.get((c.group ? c.group + '/' : '') + c.name + '@' + c.version);
  if (!dir) continue;
  let root;
  let files = [];
  try {
    root = fs.realpathSync(dir);
    files = fs.readdirSync(dir).filter(f => FILE_RE.test(f)).sort().slice(0, MAX_FILES);
  } catch (e) { continue; }
  let found = [];
  for (const f of files) found = found.concat(statementsIn(path.join(dir, f), root));
  found = collapse(found);
  if (!found.length) continue;
  c.copyright = found.join('; ');
  c.properties = (c.properties || []).filter(p => p.name !== 'bomlens:copyrightSource')
    .concat([{ name: 'bomlens:copyrightSource', value: 'installed license file' }]);
  changed++;
}
if (changed) {
  fs.writeFileSync(bomPath, JSON.stringify(bom, null, 2));
  process.stderr.write('[build-prep] copyright: filled ' + changed + ' ' + purlPrefix.replace(/^pkg:|\/$/g, '') + ' component(s) from installed license files\n');
}
NODE_CPR
        # Says on the SBOM that a whole ecosystem's license files could not be listed, so
        # "no copyright" and "not read" can be told apart.
        _cpr_unread() {
            log "copyright: $2"
            BOMLENS_CPR_UNREAD="$1" node "$_jscpr" "$OUT" || log "copyright: could not record the gap (non-fatal)"
        }
        if [ -n "$_nmdirs" ]; then
            log "copyright: reading license files under node_modules"
            BOMLENS_CPR_INDEX="" BOMLENS_CPR_PURL_PREFIX="pkg:npm/" BOMLENS_NM_DIRS="$_nmdirs" node "$_jscpr" "$OUT" \
                || log "copyright: npm pass skipped (non-fatal)"
        fi
        if [ -n "$_cprgo" ]; then
            log "copyright: reading license files in the Go module cache and vendor/"
            _cprix=$(mktemp)
            _cprjs=$(mktemp)
            cat > "$_cprjs" <<'GO_CPR_INDEX'
const fs = require('fs');
const path = require('path');
const out = {};
let text = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', d => { text += d; }).on('end', () => {
  // path@version <TAB> folder, one per line, from `go list -m`. A module that is not on
  // disk has no folder and is left out.
  for (const line of text.split('\n')) {
    const i = line.indexOf('\t');
    if (i > 0 && line.slice(i + 1)) out[line.slice(0, i)] = line.slice(i + 1);
  }
  // A vendored project keeps the modules under vendor/ and may have no module cache.
  try {
    const root = fs.realpathSync('vendor');
    for (const line of fs.readFileSync(path.join('vendor', 'modules.txt'), 'utf8').split('\n')) {
      const m = /^# (\S+) (\S+)(?: => .*)?$/.exec(line);
      if (!m || (m[1] + '@' + m[2]) in out) continue;
      let dir;
      try { dir = fs.realpathSync(path.join('vendor', m[1])); } catch (e) { continue; }
      if (dir.startsWith(root + path.sep)) out[m[1] + '@' + m[2]] = dir;
    }
  } catch (e) { /* no vendor directory */ }
  process.stdout.write(JSON.stringify(out));
});
GO_CPR_INDEX
            # -e keeps a module that fails to resolve in the listing instead of stopping the
            # whole command. A replaced module reads from its replacement's folder; when the
            # replacement has a version, that version is a second key, because cdxgen names a
            # component after the replacement when it falls back to reading go.mod.
            _cprgotmpl='{{if not .Main}}{{.Path}}@{{.Version}}{{"\t"}}{{if .Replace}}{{.Replace.Dir}}{{else}}{{.Dir}}{{end}}{{if .Replace}}{{if .Replace.Version}}{{"\n"}}{{.Replace.Path}}@{{.Replace.Version}}{{"\t"}}{{.Replace.Dir}}{{end}}{{end}}{{end}}'
            run_supervised_timeout "$PREP_TIMEOUT_DEFAULT" sh -c 'GOFLAGS="-mod=mod" go list -m -e -f "$1" all 2>/dev/null | node "$2" > "$3"' _ "$_cprgotmpl" "$_cprjs" "$_cprix"
            _cprrc=$?
            if [ "$_cprrc" -eq 0 ] && [ "$(wc -c < "$_cprix" | tr -d ' ')" -gt 2 ]; then
                BOMLENS_CPR_INDEX="$_cprix" BOMLENS_CPR_PURL_PREFIX="pkg:golang/" node "$_jscpr" "$OUT" \
                    || log "copyright: go pass skipped (non-fatal)"
            elif [ "$_cprrc" -eq 124 ]; then
                _cpr_unread golang "go module listing timed out after ${PREP_TIMEOUT_DEFAULT}s; go components left as they were"
            else
                _cpr_unread golang "no Go module folder found (modules not downloaded and no vendor/); go components left as they were"
            fi
            rm -f "$_cprix" "$_cprjs"
        fi
        if [ -n "$_cprcargo" ]; then
            log "copyright: reading license files in the cargo registry"
            _cprix=$(mktemp)
            _cprmeta=$(mktemp)
            _cprjs=$(mktemp)
            cat > "$_cprjs" <<'CARGO_CPR_INDEX'
const fs = require('fs');
const path = require('path');
const meta = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
// The scanned project's own crates are not third-party components.
const own = new Set(meta.workspace_members || []);
const out = {};
for (const k of meta.packages || []) {
  if (!k.name || !k.version || !k.manifest_path || own.has(k.id)) continue;
  out[k.name + '@' + k.version] = path.dirname(k.manifest_path);
}
process.stdout.write(JSON.stringify(out));
CARGO_CPR_INDEX
            # Offline on purpose: the crates are on disk only when the license pass above
            # (or an earlier build step) downloaded them. Reaching the network here would
            # make the result depend on the registry, which FETCH_LICENSE=false and
            # --byte-stable rule out.
            run_supervised_timeout "$PREP_TIMEOUT_DEFAULT" sh -c 'cargo metadata --format-version 1 --offline > "$1" 2>/dev/null' _ "$_cprmeta"
            _cprrc=$?
            if [ "$_cprrc" -eq 0 ] && [ -s "$_cprmeta" ] \
               && node "$_cprjs" "$_cprmeta" > "$_cprix" 2>/dev/null && [ -s "$_cprix" ]; then
                BOMLENS_CPR_INDEX="$_cprix" BOMLENS_CPR_PURL_PREFIX="pkg:cargo/" node "$_jscpr" "$OUT" \
                    || log "copyright: cargo pass skipped (non-fatal)"
            elif [ "$_cprrc" -eq 124 ]; then
                _cpr_unread cargo "cargo metadata timed out after ${PREP_TIMEOUT_DEFAULT}s; cargo components left as they were"
            else
                _cpr_unread cargo "crate sources are not on disk (cargo metadata --offline failed); cargo components left as they were"
            fi
            rm -f "$_cprix" "$_cprmeta" "$_cprjs"
        fi
        rm -f "$_jscpr"
    fi
fi

# Record what the non-shipped exclusion left out: the patterns in
# bomlens:excluded-paths and the manifest files, capped at 50, in
# bomlens:excluded-manifests.
if [ "${rc:-1}" -eq 0 ] && [ -n "$EXCLUDE_NON_SHIPPED" ] && [ -f "$OUT" ] && command -v node >/dev/null 2>&1; then
    _globs=""
    _re=""
    for _d in $NON_SHIPPED_DIRS; do _globs="$_globs, **/$_d/**"; _re="$_re|$_d"; done
    for _d in $NON_SHIPPED_PATHS; do _globs="$_globs, **/$_d/**"; done
    _globs="${_globs#, }"
    _re="(^|/)(${_re#|})/"
    _excl=$(mktemp)
    find . \( -name node_modules -o -name .git \) -prune -o -type f -print 2>/dev/null \
        | sed 's#^\./##' \
        | { grep -Ei "$NON_SHIPPED_PATH_FILE_RE|$_re" || true; } \
        | { grep -Ei "$NON_SHIPPED_PATH_FILE_RE|$NON_SHIPPED_MANIFEST_RE" || true; } \
        | LC_ALL=C sort > "$_excl"
    _js=$(mktemp).js
    cat > "$_js" <<'EXCL_JS'
const fs = require('fs');
const [bomPath, listPath, globs] = process.argv.slice(2);
let bom;
try { bom = JSON.parse(fs.readFileSync(bomPath, 'utf8')); } catch (e) { process.exit(0); }
const files = fs.readFileSync(listPath, 'utf8').split('\n').filter(Boolean);
const LIMIT = 50;
bom.metadata = bom.metadata || {};
const props = (bom.metadata.properties || []).filter(
  p => p.name !== 'bomlens:excluded-paths' && p.name !== 'bomlens:excluded-manifests');
props.push({ name: 'bomlens:excluded-paths', value: globs });
if (files.length) {
  let v = files.slice(0, LIMIT).join(', ');
  if (files.length > LIMIT) v += ` (+${files.length - LIMIT} more)`;
  props.push({ name: 'bomlens:excluded-manifests', value: v });
}
bom.metadata.properties = props;
fs.writeFileSync(bomPath, JSON.stringify(bom, null, 2));
process.stderr.write('[build-prep] non-shipped: left out ' + files.length + ' manifest file(s)\n');
EXCL_JS
    node "$_js" "$OUT" "$_excl" "$_globs" || log "non-shipped: recording skipped (non-fatal)"
    rm -f "$_js" "$_excl"
fi

# --reachability (Go): govulncheck reads the source with the Go toolchain this
# image carries, so it runs here, after the module graph is complete, and not
# in the post-processing image, which has no toolchain. The caller mounts the
# govulncheck binary of the post-processing image at BOMLENS_GOVULNCHECK and
# gives a nonce (BOMLENS_REACHABILITY_NONCE) that stage 2 checks, so files an
# earlier run left are never read as this run's. Nothing here changes the SBOM,
# and a failure (no network for the Go vulnerability database, a tree that
# does not build) is stage 2's to report.
#
# govulncheck reads one module per run and only the files the current GOOS
# and GOARCH build, so it runs for every go.mod that cdxgen reads into the SBOM
# (up to _rch_max_modules) and for GOOS linux, darwin and windows, GOARCH
# amd64. The modules are searched as cdxgen's own search does: not under
# vendor/, node_modules/ or a folder whose name starts with a dot (.git
# included; cdxgen 13.3.0 reads none of them, measured), nor under the
# non-shipped folders and paths it is told to leave out (NON_SHIPPED_DIRS,
# NON_SHIPPED_PATHS, unless BOMLENS_INCLUDE_NON_SHIPPED). Stage 2 keeps, per
# advisory, the deepest level any run found. A module listed in the go.work
# governing it runs in workspace mode, as `go build` there would; any other
# module runs alone (GOWORK=off). A module with a vendor/ folder is judged on
# the tree as it was before the go mod tidy above, after the guard puts it
# back: tidy can add requirements and raise the go line, and the vendored copy
# then no longer matches go.mod. With the guard off, a module outside a
# workspace is read from the module cache instead (-mod=mod, added to the
# caller's GOFLAGS; go refuses it in workspace mode). A run that fails for any
# reason but the GOOS (code that does not build there) stops the runs left,
# since stage 2 then fails the step anyway, and so does the time budget
# (PREP_TIMEOUT_DEFAULT for all the runs together). Each run's stream,
# standard error and exit status go beside the SBOM, the run list last
# (stage 2 reads nothing without it).
_rch_out=""; _rch_runs=""; _rch_deferred=""; _rch_n=0; _rch_stop=""; _rch_start=""
_rch_max_modules=20
if [ "${BOMLENS_REACHABILITY:-false}" = "true" ] && command -v go >/dev/null 2>&1; then
    _rch_out="${OUT%_bom.json}_govulncheck_stage1"
    rm -f "$_rch_out.json" "$_rch_out.err" "$_rch_out.rc"
    set -- -name vendor -o -name node_modules -o -name '.?*'
    if [ -n "$EXCLUDE_NON_SHIPPED" ]; then
        for _rch_x in $NON_SHIPPED_DIRS; do set -- "$@" -o -name "$_rch_x"; done
        for _rch_x in $NON_SHIPPED_PATHS; do set -- "$@" -o -path "*/$_rch_x"; done
    fi
    _rch_mods=$(find . -mindepth 1 -type d \( "$@" \) -prune -o -type f -name go.mod -print 2>/dev/null \
        | sed 's|/go\.mod$||' | LC_ALL=C sort)
    set --
    _rch_count=$(printf '%s\n' "$_rch_mods" | grep -c . || true)
    if [ "${_rch_count:-0}" -eq 0 ]; then
        _rch_out=""
    elif [ -z "${BOMLENS_GOVULNCHECK:-}" ] || [ ! -x "$BOMLENS_GOVULNCHECK" ]; then
        log "reachability: no govulncheck binary was handed to this image; call analysis skipped"
        _rch_out=""
    elif [ "$_rch_count" -gt "$_rch_max_modules" ]; then
        log "reachability: $_rch_count Go modules, over the $_rch_max_modules that are judged; call analysis skipped"
        printf 'nonce %s\ntoo_large %s %s\n' "${BOMLENS_REACHABILITY_NONCE:-}" "$_rch_count" "$_rch_max_modules" > "$_rch_out.rc"
        _rch_out=""
    else
        _rch_runs=$(mktemp)
        _rch_err1=$(mktemp)
        _rch_start=$(date +%s)
        : > "$_rch_out.json"; : > "$_rch_out.err"
    fi
fi

# rch_workspace_member <module dir>: true when the go.work that governs the
# module (go env GOWORK, from its folder) lists it in a use directive.
rch_workspace_member() {
    _rch_gw=$(cd "$1" && GOTOOLCHAIN="${HOST_GOTOOLCHAIN:-auto}" go env GOWORK 2>/dev/null) || return 1
    [ -n "$_rch_gw" ] && [ "$_rch_gw" != off ] && [ -f "$_rch_gw" ] || return 1
    _rch_mod=$(cd "$1" && pwd -P) || return 1
    _rch_gwdir=$(dirname "$_rch_gw")
    (cd "$_rch_gwdir" && GOTOOLCHAIN="${HOST_GOTOOLCHAIN:-auto}" go work edit -json "$_rch_gw" 2>/dev/null) \
        | sed -n 's/^[[:space:]]*"DiskPath": "\(.*\)",*$/\1/p' | {
        while IFS= read -r _rch_use; do
            case "$_rch_use" in /*) ;; *) _rch_use="$_rch_gwdir/$_rch_use" ;; esac
            [ "$(cd "$_rch_use" 2>/dev/null && pwd -P)" = "$_rch_mod" ] && exit 0
        done
        exit 1
    }
}

# rch_goos_only <stderr file>: true when a failed run failed only because the
# code does not build for that GOOS: no package matched (every file is
# constrained to other systems), build constraints exclude a package, or the
# package loading errors are all type errors in the code, with nothing about
# fetching, importing or the module itself. The same rule as stage 2's
# (assess-reachability.py); anything else stops the runs.
rch_goos_only() {
    grep -qE 'no packages matched the provided patterns|build constraints exclude all Go files' "$1" && return 0
    grep -q 'loading packages' "$1" || return 1
    grep -qiE 'fetching vulnerabilities|dial tcp|no such host|network is unreachable|i/o timeout|connection refused|proxy\.golang\.org|could not import|cannot find (module|package)|no required module|missing go\.sum|go\.mod|go: |unknown revision|invalid version' "$1" && return 1
    grep -qE '\.go:[0-9]+:[0-9]+: ' "$1"
}

# rch_run_module <module dir> <"vendor" when read off the module cache, or "">:
# govulncheck once per GOOS, until a run fails for another reason than the
# GOOS or the time budget is spent.
rch_run_module() {
    _rch_dir="$1"; _rch_flags=""; _rch_work=off; _rch_how=module; _rch_built=""
    if rch_workspace_member "$_rch_dir"; then _rch_work=workspace; _rch_how=workspace; fi
    if [ "$2" = vendor ] && [ "$_rch_work" = off ]; then _rch_flags="-mod=mod"; _rch_how="module,-mod=mod"; fi
    for _rch_goos in linux darwin windows; do
        [ -z "$_rch_stop" ] || return 0
        _rch_left=$((PREP_TIMEOUT_DEFAULT - ($(date +%s) - _rch_start)))
        _rch_n=$((_rch_n + 1))
        printf '{"bomlens_run": %s}\n' "$_rch_n" >> "$_rch_out.json"
        printf '== bomlens run %s ==\n' "$_rch_n" >> "$_rch_out.err"
        if [ "$_rch_left" -le 0 ]; then
            log "reachability: the time budget (${PREP_TIMEOUT_DEFAULT}s) is spent; the runs left are skipped"
            printf 'run %s 124 %s %s %s\n' "$_rch_n" "$_rch_goos" "$_rch_how" "$_rch_dir" >> "$_rch_runs"
            _rch_stop=1; return 0
        fi
        log "reachability: govulncheck (source, call graph) $_rch_dir GOOS=$_rch_goos"
        run_supervised_timeout "$_rch_left" sh -c '
            cd "$1" || exit 1
            if [ "$3" = workspace ]; then unset GOWORK; else export GOWORK=off; fi
            [ -z "$4" ] || export GOFLAGS="${GOFLAGS:+$GOFLAGS }$4"
            GOOS="$2" GOARCH=amd64 GOTOOLCHAIN="$6" "$0" -format json ./... >> "$5.json" 2> "$7"' \
            "$BOMLENS_GOVULNCHECK" "$_rch_dir" "$_rch_goos" "$_rch_work" \
            "$_rch_flags" "$_rch_out" "${HOST_GOTOOLCHAIN:-auto}" "$_rch_err1"
        _rch_rc=$?
        cat "$_rch_err1" >> "$_rch_out.err"
        printf 'run %s %s %s %s %s\n' "$_rch_n" "$_rch_rc" "$_rch_goos" "$_rch_how" "$_rch_dir" >> "$_rch_runs"
        if [ "$_rch_rc" -eq 0 ]; then
            _rch_built=1
        elif ! rch_goos_only "$_rch_err1"; then
            log "reachability: govulncheck failed for $_rch_dir (GOOS=$_rch_goos); the runs left are skipped"
            _rch_stop=1
        fi
    done
    # Built for none of the three: stage 2 does not judge the module, and keeps
    # every module its go.mod requires from a not_affected another module's
    # runs would give, so it needs that list (go mod edit -json, offline). A
    # go.mod that cannot be read is recorded as such (-), and stage 2 then
    # writes no not_affected at all.
    if [ -z "$_rch_built" ] && [ -z "$_rch_stop" ]; then
        _rch_n=$((_rch_n + 1))
        printf '{"bomlens_gomod": %s}\n' "$_rch_n" >> "$_rch_out.json"
        if (cd "$_rch_dir" && GOTOOLCHAIN="${HOST_GOTOOLCHAIN:-auto}" go mod edit -json) >> "$_rch_out.json" 2>/dev/null; then
            printf 'gomod %s 0 %s\n' "$_rch_n" "$_rch_dir" >> "$_rch_runs"
        else
            printf 'gomod %s 1 %s\n' "$_rch_n" "$_rch_dir" >> "$_rch_runs"
        fi
    fi
}

if [ -n "$_rch_runs" ]; then
    # Read the list from a here-document, not a pipe: the runs must count into
    # _rch_n in this shell.
    while IFS= read -r _rch_d; do
        [ -n "$_rch_d" ] || continue
        if [ -f "$_rch_d/vendor/modules.txt" ]; then
            _rch_deferred="$_rch_deferred$_rch_d
"
        else
            rch_run_module "$_rch_d" ""
        fi
    done <<EOF
$_rch_mods
EOF
fi

# Put the scanned tree back before the ownership fix below, so anything we
# restored is chown'd too (the trap only covers an abnormal exit).
_rch_restored=""; [ -z "$GUARD_DIR" ] || _rch_restored=1
guard_restore

# --reachability: the modules with a vendor/ folder, on the tree as it was
# (see above), then the run list that tells stage 2 the output is complete.
if [ -n "$_rch_runs" ]; then
    while IFS= read -r _rch_d; do
        [ -n "$_rch_d" ] || continue
        if [ -n "$_rch_restored" ]; then rch_run_module "$_rch_d" ""; else rch_run_module "$_rch_d" vendor; fi
    done <<EOF
$_rch_deferred
EOF
    { printf 'nonce %s\ngoarch amd64\n' "${BOMLENS_REACHABILITY_NONCE:-}"; cat "$_rch_runs"; } > "$_rch_out.rc"
    rm -f "$_rch_runs" "$_rch_err1"
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
