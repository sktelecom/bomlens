#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# license-entry.sh: the CycloneDX licenses[] entry for a licence given as text
# (--license, PROJECT_LICENSE), shared by scan-sbom.sh (checked before a scan),
# entrypoint.sh (checked before the generator runs), stamp-metadata.sh and
# stamp-yocto-root.sh, so none of them reads one differently.
#
# Usage: license-entry.sh <licence> [acknowledgement]
#   prints the entry as compact JSON (nothing for an empty licence), or exits 2
#   with the reason on stderr when the text is none of the three below.
#   LICENSE_ENTRY_QUIET=1 leaves the reason out of stderr; the caller then says
#   what it does instead (a licence read from a manifest is only left out).
#
# CycloneDX takes a licence in one of three places, and the schema holds each
# to its form:
#   - license.id: an id on the SPDX License List, from the bundled
#     cdx-spdx-ids.json (the list the CycloneDX schema accepts). An id in
#     another letter case is written in the list's.
#   - license.name: a LicenseRef- (or DocumentRef-...:LicenseRef-) name, for a
#     licence the list does not hold, such as a closed product licence. The
#     prefixes are read in any letter case and written as SPDX spells them.
#   - expression: an SPDX licence expression. Each operand must be an id from
#     the list (with an optional trailing +) or a LicenseRef- name, joined by
#     AND or OR (any letter case, written in upper case); WITH must follow a
#     licence and be followed by an exception id from the list; parentheses
#     must balance. Anything else, such as "Proprietary or commercial",
#     "MIT AND" or "(MIT", is refused.
# Free text ("Proprietary") is refused with the LicenseRef- name to use
# instead. Runs of white space (a tab included) are read as one space.
#
# The list holds the licence ids, then the exception ids, each run sorted; the
# exceptions start where the order breaks. With no break, every id is taken
# as either.
set -e

LIC="${1:-}"
ACK="${2:-concluded}"
DIR="$(cd "$(dirname "$0")" && pwd)"
IDS="$DIR/cdx-spdx-ids.json"
[ -f "$IDS" ] || IDS=/dev/null

if ! command -v jq >/dev/null 2>&1; then
    echo "[license] ERROR: jq not available; cannot record the licence. This is a build defect: rebuild the image with jq." >&2
    exit 1
fi

# The program is kept out of the command substitution below: bash 3.2 (macOS)
# misreads an unbalanced parenthesis inside quotes there.
# shellcheck disable=SC2016  # jq source; the $names are jq variables.
PROG='
    def ref_name:
      if test("^(?i:documentref-)[A-Za-z0-9.-]+:(?i:licenseref-)[A-Za-z0-9.-]+$")
      then sub("^(?i:documentref-)"; "DocumentRef-") | sub(":(?i:licenseref-)"; ":LicenseRef-")
      elif test("^(?i:licenseref-)[A-Za-z0-9.-]+$") then sub("^(?i:licenseref-)"; "LicenseRef-")
      else null end;
    ($l | gsub("\\s+"; " ") | gsub("^ | $"; "")) as $t
    | ($ids[0].ids // []) as $all
    | ([range(1; $all | length) | select(($all[.] | ascii_downcase) < ($all[. - 1] | ascii_downcase))] | first // ($all | length)) as $cut
    | ($all[0:$cut] | map({key: ascii_downcase, value: .}) | from_entries) as $lic
    | (if $cut < ($all | length) then $all[$cut:] else $all end | map({key: ascii_downcase, value: .}) | from_entries) as $exc
    | def operand:
        if ref_name != null then ref_name
        elif $lic[ascii_downcase] != null then $lic[ascii_downcase]
        elif endswith("+") and $lic[.[0:-1] | ascii_downcase] != null then $lic[.[0:-1] | ascii_downcase] + "+"
        else null end;
    # Read an expression token by token. state: "operand" (a licence or "("
    # comes next), "op" (AND, OR, WITH or ")" or the end), "exc" (an
    # exception comes next, after WITH).
    def parse:
      (gsub("\\("; " ( ") | gsub("\\)"; " ) ") | split(" ") | map(select(length > 0)))
      | reduce .[] as $k ({state: "operand", depth: 0, out: [], err: null, lastlic: false};
          if .err != null then .
          elif .state == "exc" then
            (if $exc[$k | ascii_downcase] != null then .out += [$exc[$k | ascii_downcase]] | .state = "op" | .lastlic = false
             else .err = "\"\($k)\" after WITH is not an SPDX exception id" end)
          elif $k == "(" then (if .state == "operand" then .depth += 1 | .out += ["("] else .err = "a parenthesis where an operator should be" end)
          elif $k == ")" then (if .state == "op" and .depth > 0 then .depth -= 1 | .out += [")"] | .lastlic = false
                               else .err = "a closing parenthesis with nothing to close" end)
          elif ($k | ascii_downcase) == "and" or ($k | ascii_downcase) == "or" then
            (if .state == "op" then .out += [$k | ascii_upcase] | .state = "operand" | .lastlic = false
             else .err = "\"\($k)\" where a licence should be" end)
          elif ($k | ascii_downcase) == "with" then
            (if .state == "op" and .lastlic then .out += ["WITH"] | .state = "exc"
             else .err = "WITH that does not follow a licence" end)
          elif .state == "operand" then
            (($k | operand) as $o
             | if $o != null then .out += [$o] | .state = "op" | .lastlic = true
               else .err = "\"\($k)\" is not an SPDX license id or a LicenseRef- name" end)
          else .err = "\"\($k)\" where an operator should be" end)
      | if .err != null then .
        elif .state == "exc" then .err = "WITH is not followed by an exception id"
        elif .state != "op" then .err = "it ends where a licence should come"
        elif .depth != 0 then .err = "a parenthesis is not closed"
        else . end;
    if $t == "" then {entry: null}
    elif ($t | test("[()]")) or ($t | test("(^| )(?i:and|or|with)( |$)")) then
      ($t | parse) as $p
      | if $p.err != null then {refuse: $t, reason: ("not a licence expression: " + $p.err), suggest: ""}
        else {entry: {expression: ($p.out | join(" ") | gsub("\\( "; "(") | gsub(" \\)"; ")")), acknowledgement: $ack}} end
    elif ($t | operand) != null and (($t | ref_name) != null)
    then {entry: {license: {name: ($t | ref_name), acknowledgement: $ack}}}
    elif $lic[$t | ascii_downcase] != null
    then {entry: {license: {id: $lic[$t | ascii_downcase], acknowledgement: $ack}}}
    elif ($t | operand) != null
    then {entry: {expression: ($t | operand), acknowledgement: $ack}}
    else ($t | sub("^(?i:licenseref-)"; "") | gsub("[^A-Za-z0-9.-]+"; "-") | gsub("^-+|-+$"; "")) as $base
      | {refuse: $t, reason: "not an SPDX license id, a LicenseRef- name or a licence expression",
         suggest: (if $base == "" then "LicenseRef-<your-name>" else "LicenseRef-" + $base end)}
    end'
OUT="$(jq -cn --arg l "$LIC" --arg ack "$ACK" --slurpfile ids "$IDS" "$PROG")"

REFUSED="$(printf '%s' "$OUT" | jq -r '.refuse // empty')"
if [ -n "$REFUSED" ]; then
    if [ "${LICENSE_ENTRY_QUIET:-}" != "1" ]; then
        REASON="$(printf '%s' "$OUT" | jq -r '.reason')"
        SUGGEST="$(printf '%s' "$OUT" | jq -r '.suggest')"
        if [ -n "$SUGGEST" ]; then
            echo "[license] ERROR: the licence '$REFUSED' is $REASON, so CycloneDX has no field for it. Write a licence the SPDX list does not hold as $SUGGEST (for example --license $SUGGEST), or give its SPDX id." >&2
        else
            echo "[license] ERROR: the licence '$REFUSED' is $REASON. Write SPDX license ids and LicenseRef- names joined by AND, OR or WITH, for example --license \"MIT OR LicenseRef-ExampleCorp-Commercial\"." >&2
        fi
    fi
    exit 2
fi
printf '%s' "$OUT" | jq -c '.entry // empty'
