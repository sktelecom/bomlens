#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# engine-result.sh - the run's result manifest (bomlens-result.json).
#
# A program that runs this image as its scan engine needs to know, without
# reading the human log, which steps ran, which were turned off or could not
# run, which failed, and where each output is. entrypoint.sh records every step
# here as it goes (er_record, also called by run_optional_step) and writes the
# manifest from an EXIT trap, so a run that stops early still leaves one. The
# format is the engine contract in docs/reference/engine-contract.md, checked
# against schemas/engine-result-1.json by tests/test-engine-contract.sh.
#
# Recording rule: a step that applies to this mode is always recorded, as ok,
# degraded, failed, skipped (it could not run: no input, tool not installed) or
# disabled (a setting turned it off). A step that does not apply to the mode at
# all (CPE enrichment of an AI model) is not recorded.

ENGINE_CONTRACT_VERSION="1.3.0"
ENGINE_RESULT_NAME="bomlens-result.json"

er_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# Progress events (BOMLENS_EVENTS=file or stderr): one JSON object per line as
# the run goes, for a caller that shows progress while it runs. "file" writes
# bomlens-events.jsonl in the output folder, "stderr" writes to stderr. Types: run.start, step.start, step.end, run.end;
# seq rises by one per event so a reader can tell a lost line. The result
# manifest is the final record; where the two differ, the manifest wins.
# ER_SEQ lives in this shell: an event emitted from a subshell or a child
# process would repeat a number, which is why only entrypoint.sh's own shell
# emits them (the scripts that source pipeline-step.sh do not have er_event).
# In stderr mode the events share stderr with warnings and tool output; a
# reader takes only the lines that start with {"v":1.
ER_SEQ=0
ER_EVENTS_FILE=""
_er_events_on() {
    case "${BOMLENS_EVENTS:-}" in file|stderr) return 0 ;; esac
    return 1
}
# er_event <type> [step] [status] [reason] [detail]
er_event() {
    _er_events_on || return 0
    command -v jq >/dev/null 2>&1 || return 0
    ER_SEQ=$((ER_SEQ + 1))
    local line stage=2
    [ "${2:-}" = "generate" ] && [ "${SCAN_MODE:-}" = "POSTPROCESS" ] && stage=1
    line="$(jq -nc --argjson seq "$ER_SEQ" --arg ts "$(er_now)" --arg type "$1" \
        --arg step "${2:-}" --argjson stage "$stage" --arg st "${3:-}" --arg re "${4:-}" --arg de "${5:-}" '
        def nn: if . == "" then null else . end;
        {v: 1, seq: $seq, ts: $ts, type: $type}
        + (if $step != "" then {step: $step, stage: $stage} else {} end)
        + (if $st != "" then {status: $st} else {} end)
        + (if $type == "step.end" then {reason: ($re | nn)} else {} end)
        + (if $de != "" then {detail: ($de | gsub("[\u0000-\u001f]"; " ") | .[0:500])} else {} end)' 2>/dev/null)" || return 0
    if [ "${BOMLENS_EVENTS}" = "stderr" ]; then
        printf '%s\n' "$line" >&2
    elif [ -n "$ER_EVENTS_FILE" ]; then
        printf '%s\n' "$line" >> "$ER_EVENTS_FILE" 2>/dev/null || true
    fi
    return 0
}

# Start the run record. Safe to call once; later calls keep the first.
er_init() {
    [ -n "${ER_STEPS:-}" ] && return 0
    ER_STEPS="$(mktemp "${TMPDIR:-/tmp}/bomlens-steps.XXXXXX" 2>/dev/null)" || ER_STEPS=""
    ER_STARTED="$(er_now)"
    # A manifest left from an earlier run in the same folder must not be read as
    # this run's: remove it now, so a run killed before its trap leaves none.
    [ -n "${HOST_OUTPUT_DIR:-}" ] && rm -f "$HOST_OUTPUT_DIR/$ENGINE_RESULT_NAME" 2>/dev/null
    # An events file from an earlier run in this folder is not this run's,
    # whether or not this run writes one.
    [ -n "${HOST_OUTPUT_DIR:-}" ] && rm -f "$HOST_OUTPUT_DIR/bomlens-events.jsonl" 2>/dev/null
    if [ "${BOMLENS_EVENTS:-}" = "file" ]; then
        ER_EVENTS_FILE="${HOST_OUTPUT_DIR:-.}/bomlens-events.jsonl"
        [ -d "$(dirname "$ER_EVENTS_FILE")" ] && : > "$ER_EVENTS_FILE" 2>/dev/null || ER_EVENTS_FILE=""
    fi
    er_event run.start
    return 0
}

# Mark the step now running outside run_optional_step, so an exit inside it is
# recorded as its failure. er_phase_end clears it once the step has finished.
er_phase() { ER_PHASE="$1"; ER_PHASE_STARTED="$(er_now)"; er_event step.start "$1"; }
er_phase_end() { ER_PHASE=""; ER_PHASE_STARTED=""; }

# er_record <id> <status> [reason] [detail] [started] [ended] [counts-json]
er_record() {
    [ -n "${ER_STEPS:-}" ] && [ -f "$ER_STEPS" ] || return 0
    command -v jq >/dev/null 2>&1 || return 0
    local now; now="$(er_now)"
    jq -nc --arg id "$1" --arg st "$2" --arg re "${3:-}" --arg de "${4:-}" \
        --arg s "${5:-$now}" --arg e "${6:-$now}" --arg c "${7:-}" \
        '{id:$id, status:$st,
          reason:(if $re == "" then null else $re end),
          detail:(if $de == "" then null else ($de | gsub("[\u0000-\u001f]"; " ") | .[0:500]) end),
          started_at:$s, ended_at:$e}
         + (if $c == "" then {} else {counts:($c | fromjson? // {})} end)' \
        >> "$ER_STEPS" 2>/dev/null || true
    er_event step.end "$1" "$2" "${3:-}" "${4:-}"
}

# The output role a file plays, from its suffix. Unknown suffixes are "other".
_er_role() {
    case "$1" in
        *_bom.json) echo "sbom.cyclonedx" ;;
        *_bom.spdx.json) echo "sbom.spdx" ;;
        *_bom.spdx3.json) echo "sbom.spdx3" ;;
        *_security_trivy.json) echo "vulnerabilities.trivy" ;;
        *_security.json) echo "vulnerabilities.all" ;;
        *_security_grype.json|*_security_cvebintool.json|*_security_yocto.json) echo "vulnerabilities.other" ;;
        *_scancode.json) echo "license-scan.scancode" ;;
        *_vendored.cdx.json) echo "vendored.cyclonedx" ;;
        *_conformance.json) echo "conformance" ;;
        *_input.json) echo "input-description" ;;
        bomlens-plan.json) echo "plan" ;;
        bomlens-events.jsonl) echo "events" ;;
        *) echo "other" ;;
    esac
}

_er_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

_er_input_kind() {
    case "$1" in
        SOURCE|POSTPROCESS|PLAN) echo source ;;
        IMAGE) echo image ;;
        ANALYZE|MERGE) echo sbom ;;
        BINARY) echo binary ;;
        ROOTFS) echo rootfs ;;
        FIRMWARE) echo firmware ;;
        AIBOM|MODELFILE|AIDECLARE) echo ai-model ;;
        DATASET) echo dataset ;;
        *) echo unknown ;;
    esac
}

# The EXIT trap: write the manifest, then exit again with the run's own code,
# so nothing er_finish does can change it.
er_exit_trap() {
    local rc=$?
    set +e
    # A second Ctrl+C or TERM must not cut the manifest short: finishing it
    # takes a moment, and the run's own code is already decided.
    trap '' INT TERM
    er_finish "$rc"
    exit "$rc"
}

# Write the manifest. Called from the EXIT trap with the script's exit code.
# Never fails and never changes the exit code.
er_finish() {
    # Errexit off for this function only: a failing jq here must not end the
    # script with its own status instead of the run's.
    local -
    set +e
    local rc="${1:-0}"
    [ -n "${ER_STEPS:-}" ] && [ -f "$ER_STEPS" ] || return 0
    command -v jq >/dev/null 2>&1 || return 0
    local outdir="${HOST_OUTPUT_DIR:-}"
    [ -n "$outdir" ] && [ -d "$outdir" ] || outdir="."
    local bom="${OUTPUT_FILE:-}" sec="${OUT_PREFIX:-}_security.json"
    [ -f "$outdir/$(basename "$bom")" ] && bom="$outdir/$(basename "$bom")"
    [ -f "$outdir/$(basename "$sec")" ] && sec="$outdir/$(basename "$sec")"

    # Outcomes only visible after the fact, read from what the steps left behind.
    local props=""
    [ -n "$bom" ] && [ -f "$bom" ] && props="$(jq -c '[.metadata.properties[]? | .name]' "$bom" 2>/dev/null)"
    [ -n "$props" ] || props="[]"
    # A security report counts only when scan-security ran in this run: a file
    # left in the folder by an earlier run says nothing about this one.
    local scan_error="" sec_present=false sec_ran=false
    grep -q '"id":"scan-security","status":"ok"' "$ER_STEPS" 2>/dev/null && sec_ran=true
    if [ "$sec_ran" = true ] && [ -f "$sec" ]; then
        sec_present=true
        scan_error="$(jq -r '.ScanError.Message // empty' "$sec" 2>/dev/null)"
    fi

    # Output files: every artifact this run listed, found in the output folder.
    # When the caller asked for the stale-artifact cleanup, every file under
    # this run's prefix with a known suffix is also this run's own, including
    # reports a mode writes without listing them (conformance for a scan).
    local outputs="[]" f base path
    local -a seen=() extra=()
    if [ -n "${BOMLENS_RUN_INPUT:-}" ] || [ "${BOMLENS_ARTIFACT_CLEANUP:-}" = "1" ]; then
        for f in "${KNOWN_ARTIFACT_SUFFIXES[@]:-}"; do
            [ -n "$f" ] && extra+=("${OUT_PREFIX:-}$f")
        done
    fi
    [ "$sec_ran" = true ] && extra+=("${OUT_PREFIX:-}_security_trivy.json")
    for f in "${ARTIFACTS[@]:-}" "${extra[@]:-}"; do
        [ -n "$f" ] || continue
        base="$(basename "$f")"
        case " ${seen[*]:-} " in *" $base "*) continue ;; esac
        path=""
        if [ -f "$outdir/$base" ]; then path="$outdir/$base"; elif [ -f "$f" ]; then path="$f"; fi
        [ -n "$path" ] || continue
        seen+=("$base")
        outputs="$(jq -c --arg role "$(_er_role "$base")" --arg p "$base" \
            --arg h "$(_er_sha256 "$path")" --argjson b "$(wc -c < "$path" | tr -d '[:space:]')" \
            '. + [{role:$role, path:$p, sha256:$h, bytes:$b}]' <<<"$outputs")"
    done
    # With no other engine merged in, the full report is Trivy's own output.
    if ! jq -e 'any(.[]; .role == "vulnerabilities.trivy")' <<<"$outputs" >/dev/null; then
        outputs="$(jq -c '. + [.[] | select(.role == "vulnerabilities.all") | .role = "vulnerabilities.trivy"]' <<<"$outputs")"
    fi

    # Vulnerability engines that actually produced results for this run.
    local engines="[]" e
    if [ "$sec_present" = true ]; then
        engines='["trivy"]'
        for e in grype cvebintool yocto; do
            if [ -f "$outdir/${OUT_PREFIX}_security_${e}.json" ] || [ -f "${OUT_PREFIX}_security_${e}.json" ]; then
                [ "$e" = cvebintool ] && e="cve-bin-tool"
                engines="$(jq -c --arg e "$e" '. + [$e]' <<<"$engines")"
            fi
        done
    fi

    # Tool versions: the generator recorded in the SBOM, then the bundled tools.
    local tools="{}"
    [ -n "$bom" ] && [ -f "$bom" ] && tools="$(jq -c '[(.metadata.tools // [] | if type == "object" then .components[]? else .[]? end)
        | objects | select(.name and .version and .name != "BomLens") | {key:.name, value:(.version|tostring)}] | from_entries' "$bom" 2>/dev/null)"
    [ -n "$tools" ] || tools="{}"
    [ -n "${BOMLENS_SYFT_VERSION:-}" ] && tools="$(jq -c --arg v "${BOMLENS_SYFT_VERSION#v}" '. + {syft:$v}' <<<"$tools")"
    local trivy_db="null" trivy_used="$sec_present"
    # Trivy also read the licenses of Debian packages (os-licenses).
    grep -qE '"id":"os-licenses","status":"(ok|degraded)"' "$ER_STEPS" 2>/dev/null && trivy_used=true
    if [ "$trivy_used" = true ] && command -v trivy >/dev/null 2>&1; then
        local tv; tv="$(trivy version --format json 2>/dev/null)"
        if [ -n "$tv" ]; then
            tools="$(jq -c --argjson t "$tv" '. + (if $t.Version then {trivy:$t.Version} else {} end)' <<<"$tools" 2>/dev/null || echo "$tools")"
            [ "$sec_present" = true ] && trivy_db="$(jq -c '.VulnerabilityDB // null | if . then {schema_version:.Version, updated_at:.UpdatedAt, downloaded_at:.DownloadedAt} else null end' <<<"$tv" 2>/dev/null || echo null)"
        fi
    fi

    # A non-zero exit inside a step that is not wrapped by run_optional_step
    # (generation, the fail-closed metadata stamp) is that step's failure.
    if [ "$rc" != "0" ] && [ -n "${ER_PHASE:-}" ]; then
        er_record "$ER_PHASE" failed failed "exit code $rc" "${ER_PHASE_STARTED:-}"
    fi

    local ended; ended="$(er_now)"
    local target=""
    [ "${SCAN_MODE:-}" = "IMAGE" ] && target="${TARGET_IMAGE:-}"
    if [ -n "$ER_EVENTS_FILE" ] && [ -f "$ER_EVENTS_FILE" ]; then
        outputs="$(jq -c --arg p "$(basename "$ER_EVENTS_FILE")" '. + [{role: "events", path: $p, sha256: "", bytes: 0}]' <<<"$outputs")"
    fi
    # The input fingerprint of stage 1 (input-fingerprint.sh, set by
    # entrypoint.sh for POSTPROCESS as {fingerprint, plan_mismatch}) goes on
    # the generate step, with whether the caller used an earlier stage 1's SBOM
    # instead of running it.
    local fp="null" mismatch="null" reused=false
    if [ -n "${ER_INPUT_FINGERPRINT:-}" ] && jq -e '(.fingerprint | type) == "object"' <<<"$ER_INPUT_FINGERPRINT" >/dev/null 2>&1; then
        fp="$(jq -c .fingerprint <<<"$ER_INPUT_FINGERPRINT")"
        mismatch="$(jq -c 'if .plan_mismatch == true then true elif .plan_mismatch == false then false else null end' <<<"$ER_INPUT_FINGERPRINT")"
    fi
    case "${BOMLENS_STAGE1_REUSED:-}" in 1|true) reused=true ;; esac
    local s1deg=false
    [ "${ER_STAGE1_DEGRADED:-}" = "true" ] && s1deg=true
    # The image an IMAGE run read (image-digest.sh, set by entrypoint.sh once
    # syft has read it): the reference, the digest the later reads were pinned
    # to (null when it could not be resolved, or for an archive), the platform.
    # A run that stopped before syft read the image has the reference only.
    local image="null"
    if [ "${SCAN_MODE:-}" = "IMAGE" ]; then
        image="$(jq -c --arg ref "${TARGET_IMAGE:-}" '
            def dig: if type == "string" and test("^sha256:[0-9a-f]{64}$") then . else null end;
            (if type == "object" then . else {} end) as $i
            | {reference: (if $ref == "" then null else $ref end),
               source: ($i.source // null),
               digest: ($i.digest | dig),
               platform: (if ($i.platform | type) == "string" then $i.platform else null end)}
              + (if ($i.index_digest | dig) != null then {index_digest: ($i.index_digest | dig)} else {} end)' \
            <<<"${ER_INPUT_IMAGE:-"{}"}" 2>/dev/null)" || image=""
        [ -n "$image" ] || image="$(jq -nc --arg ref "${TARGET_IMAGE:-}" '{reference: (if $ref == "" then null else $ref end), source: null, digest: null, platform: null}')"
    fi
    local tmp="$outdir/.${ENGINE_RESULT_NAME}.tmp.$$"
    jq -s \
        --arg cv "$ENGINE_CONTRACT_VERSION" --arg ev "${BOMLENS_VERSION:-}" \
        --arg img "${BOMLENS_IMAGE_REF:-}" --arg dig "${BOMLENS_IMAGE_DIGEST:-}" \
        --arg kind "$(_er_input_kind "${SCAN_MODE:-}")" --arg mode "${SCAN_MODE:-}" \
        --arg target "$target" --arg started "${ER_STARTED:-$ended}" --arg ended "$ended" \
        --argjson rc "$rc" --argjson props "$props" --arg scanerr "$scan_error" \
        --argjson secpresent "$sec_present" --argjson outputs "$outputs" \
        --argjson engines "$engines" --argjson tools "$tools" --argjson tdb "$trivy_db" \
        --argjson fp "$fp" --argjson mismatch "$mismatch" --argjson reused "$reused" --argjson s1deg "$s1deg" \
        --argjson image "$image" '
        def rank: {"failed":4, "degraded":3, "skipped":2, "disabled":1, "ok":0}[.] // 0;
        # One entry per step id, in first-seen order: the worst status wins, the
        # time span covers every call (conformance can run twice in one scan).
        (reduce .[] as $s ({order: [], by: {}};
            if .by[$s.id] then
                .by[$s.id] |= (if ($s.status | rank) > (.status | rank)
                               then . + {status:$s.status, reason:$s.reason, detail:$s.detail} else . end
                               | .ended_at = $s.ended_at
                               | .counts = ((.counts // {}) + ($s.counts // {}))
                               | if .counts == {} then del(.counts) else . end)
            else .order += [$s.id] | .by[$s.id] = $s end)) as $acc
        | [ $acc.order[] as $id | $acc.by[$id] ] as $steps
        # Facts only visible afterwards: a Trivy run that wrote ScanError failed
        # even though its script returned 0, and a check whose data was missing
        # stamped the SBOM instead of failing.
        | ($steps | map(
            if .id == "scan-security" and .status == "ok" and $scanerr != "" then
                .status = "failed" | .reason = "failed" | .detail = ($scanerr | .[0:500])
            elif .id == "scan-security" and .status == "ok" and ($secpresent | not) then
                .status = "skipped" | .reason = "not_installed"
            elif .id == "enrich-eol" and .status == "ok" and ($props | index("bomlens:eol-check-unavailable")) then
                .status = "degraded" | .reason = "unavailable"
            elif .id == "enrich-malicious" and .status == "ok" and ($props | index("bomlens:malicious-check-unavailable")) then
                .status = "degraded" | .reason = "unavailable"
            else . end
            # The SBOM a POSTPROCESS run reads was generated by the stage-1
            # language image before this container started.
            | .stage = (if .id == "generate" and $mode == "POSTPROCESS" then 1 else 2 end)
            # Reuse the caller chose although the fingerprint did not allow it
            # (or there is none, or it differs from the value in the plan) is unsafe.
            # A stage 1 that came out short (a failed step recorded in its
            # SBOM, or generate degraded or failed here) is not one to keep.
            | if .id == "generate" and $mode == "POSTPROCESS" then
                (if $fp != null and ($s1deg or .status == "degraded" or .status == "failed")
                 then $fp | .reusable = false | .sha256 = null | .reasons = ((.reasons + ["stage1-degraded"]) | unique)
                 else $fp end) as $fp
                | . + {reused: $reused,
                     reuse_unsafe: ($reused and (($fp.reusable // false) != true or $mismatch == true))}
                  + (if $fp != null then {input_fingerprint: $fp} else {} end)
                  + (if $mismatch != null then {plan_mismatch: $mismatch} else {} end)
              else . end)) as $steps
        | (if $rc == 130 or $rc == 143 then "cancelled"
           elif $rc != 0 then "failed"
           # A step that was asked for and could not run (its tool missing, its
           # input over a limit, its image unavailable) leaves the result short
           # of what was asked, the same as a failed one. Only "nothing to read"
           # (no_input) is neutral.
           elif any($steps[]; .status == "failed" or .status == "degraded"
                    or (.status == "skipped" and .reason != "no_input")) then "succeeded_degraded"
           else "succeeded" end) as $status
        | {
            contract: {name: "bomlens-engine", version: $cv},
            engine: {
              version: (if $ev == "" then null else $ev end),
              image: (if $img == "" then null else $img end),
              image_digest: (if $dig == "" then null else $dig end)
            },
            input: ({
              kind: $kind, mode: $mode,
              target: (if $target == "" then null else $target end)
            } + (if $image != null then {image: $image} else {} end)),
            run: {
              status: $status,
              reason: (if $status == "cancelled" then "cancelled"
                       elif $status == "failed" then "exit_code"
                       elif $status == "succeeded_degraded" then "step_failed_or_degraded"
                       else null end),
              started_at: $started, ended_at: $ended, exit_code: $rc
            },
            steps: $steps,
            tools: $tools,
            engines: $engines,
            data_sources: {trivy_db: $tdb},
            outputs: $outputs
          }' "$ER_STEPS" > "$tmp" 2>/dev/null || { rm -f "$tmp"; rm -f "$ER_STEPS"; return 0; }
    # Everything the manifest says is settled before it appears: run.end goes
    # to the events, the events file's final size and hash go into the
    # manifest, and only then is the manifest moved into place, in one step.
    # A caller that waits for the file never sees a half-finished one.
    if _er_events_on; then
        er_event run.end "" "$(jq -r '.run.status // empty' "$tmp" 2>/dev/null)"
        if [ -n "$ER_EVENTS_FILE" ] && [ -f "$ER_EVENTS_FILE" ]; then
            local etmp="$tmp.ev"
            jq --arg p "$(basename "$ER_EVENTS_FILE")" --arg h "$(_er_sha256 "$ER_EVENTS_FILE")" \
               --argjson b "$(wc -c < "$ER_EVENTS_FILE" | tr -d '[:space:]')" \
               '.outputs |= map(if .role == "events" and .path == $p then .sha256 = $h | .bytes = $b else . end)' \
               "$tmp" > "$etmp" 2>/dev/null && mv "$etmp" "$tmp" || rm -f "$etmp"
        fi
    fi
    mv "$tmp" "$outdir/$ENGINE_RESULT_NAME" || rm -f "$tmp"
    if [[ "${HOST_UID:-}" =~ ^[0-9]+$ ]] && [[ "${HOST_GID:-}" =~ ^[0-9]+$ ]]; then
        chown "${HOST_UID}:${HOST_GID}" "$outdir/$ENGINE_RESULT_NAME" ${ER_EVENTS_FILE:+"$ER_EVENTS_FILE"} 2>/dev/null || true
    fi
    rm -f "$ER_STEPS"
    return 0
}
