#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# license-entry.sh: the CycloneDX licenses[] entry for a licence given as text
# (--license, PROJECT_LICENSE), shared by stamp-metadata.sh and
# stamp-yocto-root.sh so the two never write one differently.
#
# Usage: license-entry.sh <licence> [acknowledgement]
#   prints the entry as compact JSON (nothing for an empty licence), or exits 2
#   with the reason on stderr when the text is none of the three below.
#
# CycloneDX takes a licence in one of three places, and the schema holds each
# to its form:
#   - license.id: an id on the SPDX License List (the list the bundled
#     cdx-spdx-ids.json carries, from the CycloneDX schema). An id written in
#     another letter case is written in the list's.
#   - license.name: a LicenseRef- (or DocumentRef-...:LicenseRef-) name, for a
#     licence the list does not hold, such as a closed product licence.
#   - expression: anything with an AND, OR or WITH operator (in any letter
#     case; written in upper case, as SPDX spells them) or a parenthesis.
# Free text ("Proprietary") is none of them, and is refused with the
# LicenseRef- name to use instead. Runs of white space (a tab included) are
# read as one space.
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
# shellcheck disable=SC2016  # jq source; $t, $ack and $known are jq variables.
PROG='
    ($l | gsub("\\s+"; " ") | gsub("^ | $"; "")) as $t
    | (($ids[0].ids // []) | map({key: ascii_downcase, value: .}) | from_entries) as $known
    | if $t == "" then {entry: null}
      elif ($t | test("(^|[ (])(and|or|with)([ )]|$)"; "i")) or ($t | test("[()]"))
      then {entry: {expression: ($t | gsub(" (?<o>and|or|with) "; " \(.o | ascii_upcase) "; "i")), acknowledgement: $ack}}
      elif $known[$t | ascii_downcase] != null
      then {entry: {license: {id: $known[$t | ascii_downcase], acknowledgement: $ack}}}
      elif ($t | test("^(DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+$"))
      then {entry: {license: {name: $t, acknowledgement: $ack}}}
      else {refuse: $t, suggest: ("LicenseRef-" + ($t | gsub("^LicenseRef-"; "") | gsub("[^A-Za-z0-9.-]+"; "-") | gsub("^-+|-+$"; "")))}
      end'
OUT="$(jq -cn --arg l "$LIC" --arg ack "$ACK" --slurpfile ids "$IDS" "$PROG")"

REFUSED="$(printf '%s' "$OUT" | jq -r '.refuse // empty')"
if [ -n "$REFUSED" ]; then
    SUGGEST="$(printf '%s' "$OUT" | jq -r '.suggest')"
    echo "[license] ERROR: the licence '$REFUSED' is not an SPDX license id, a LicenseRef- name or a licence expression, so CycloneDX has no field for it. Write a licence the SPDX list does not hold as $SUGGEST (for example --license $SUGGEST), or give its SPDX id." >&2
    exit 2
fi
printf '%s' "$OUT" | jq -c '.entry // empty'
