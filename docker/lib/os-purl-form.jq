# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
#
# os-purl-form.jq - the form a deb, rpm or apk PURL takes in a BomLens SBOM:
# the one Trivy and the purl-spec use, so an identifier joins the same package
# from a Trivy scan, a supplier SBOM or another BomLens scan.
#
#   - deb: an epoch in the version ("1:2.38.1-5", or "1%3A...") moves into an
#     epoch qualifier, unless the PURL already has one (then the version is
#     left alone rather than cut twice)
#   - apk: distro=alpine-3.20.10 becomes distro=3.20.10
#   - upstream (the source package syft records) is dropped when
#     $drop_upstream is true; normalize-sbom.sh passes true only for a
#     component whose source package is already kept in
#     aquasecurity:trivy:SrcName
#   - qualifier names are lowercased and the qualifiers sorted by name
#
# Anything that is not a deb, rpm or apk PURL is returned unchanged.
# Used by normalize-sbom.sh (to rewrite) and merge-sbom.sh (to compare).
def os_purl_form($drop_upstream):
  (capture("^(?<head>pkg:(?<t>[Dd][Ee][Bb]|[Rr][Pp][Mm]|[Aa][Pp][Kk])/[^@?#]+)(@(?<ver>[^?#]*))?([?](?<q>[^#]*))?(?<frag>#.*)?$") // null) as $m
  | if $m == null then . else
      ($m.t | ascii_downcase) as $t
      | [($m.q // "") | split("&")[] | select(. != "")
         | (index("=")) as $i
         | if $i == null then {k: ascii_downcase, v: null}
           else {k: (.[0:$i] | ascii_downcase), v: .[($i + 1):]} end] as $qs
      | (($qs | map(.k) | index("epoch")) != null) as $has_epoch
      | (if $t == "deb" and ($has_epoch | not) and $m.ver != null
         then ($m.ver | capture("^(?<e>[0-9]+)(:|%3[Aa])(?<rest>.*)$") // null)
         else null end) as $ev
      | ($qs
         | map(select(($drop_upstream | not) or .k != "upstream"))
         | map(if $t == "apk" and .k == "distro" and ((.v // "") | startswith("alpine-"))
               then .v |= .[7:] else . end)
         | (if $ev != null then . + [{k: "epoch", v: $ev.e}] else . end)
         | sort_by(.k)) as $q2
      | $m.head
        + (if $m.ver != null then "@" + (if $ev != null then $ev.rest else $m.ver end) else "" end)
        + (if ($q2 | length) > 0
           then "?" + ($q2 | map(if .v == null then .k else .k + "=" + .v end) | join("&"))
           else "" end)
        + ($m.frag // "")
    end;
