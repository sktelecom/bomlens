# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
#
# conformance-semantic.jq - value checks on purls and versions, and the
# suggestions for the components that fail them. Read by validate-sbom.sh.
#
# Input:  {components: [{ref, name, version, purl, group}], osNames: [string]}
# Args:   $distros   accepted distribution ids (os-distros.json)
#         $required  true when the two rows fail the verdict (skt-submission)
#         $cap       cap on the missing list of a row
#         $nsre, $nsnsre  the purl-namespace check's own regexes (type that
#                    requires a namespace, and a namespace present)
# Output: {rows: [check rows], suggestions: [...]}
#
# Suggestions never change the submitted document. A candidate is given only
# when one rule yields exactly one answer; anything ambiguous gets none, since
# a wrong candidate would attach another package's vulnerabilities.

def clean($n): tostring | gsub("[\\x00-\\x1f\\x7f]"; " ")
               | if length > $n then .[0:$n] + "..." else . end;

def purl_head: sub("[?#].*$"; "");
def purl_ns: (purl_head | ltrimstr("pkg:") | split("/")) as $p
             | if ($p | length) >= 3 then $p[1] else null end;
def is_os_purl: test("^pkg:(rpm|deb|apk)/"; "i");
def distro_ok($id): ($id | ascii_downcase) as $d | ($distros.all | index($d)) != null;
# An id fits a package type: apk and deb have their own families, every other id is rpm.
def type_ok($t; $id):
  ($id | ascii_downcase) as $d
  | if ($t | ascii_downcase) == "apk" then ($distros.apk | index($d)) != null
    elif ($t | ascii_downcase) == "deb" then ($distros.deb | index($d)) != null
    else distro_ok($d) and (($distros.apk | index($d)) == null) and (($distros.deb | index($d)) == null) end;
def purl_pkgtype: ltrimstr("pkg:") | split("/")[0] | ascii_downcase;

# The raw distro qualifier value, or null.
def qualifier_raw:
  ((capture("[?&]distro=(?<d>[^&#]*)") // null) | if . == null then null else .d end)
  | if . == "" then null else . end;

# The distribution id named by the purl's distro qualifier: "rhel-9" -> "rhel",
# "opensuse-leap-15.5" -> "opensuse-leap". A bare release ("3.20.10") names none.
def qualifier_distro:
  ((capture("[?&]distro=(?<d>[^&#]*)") // null) | if . == null then null else .d end)
  | if . == null or . == "" then null
    else (ascii_downcase
          | (capture("^(?<id>[a-z][a-z0-9._]*(-[a-z][a-z0-9._]*)*?)-[0-9]") // {id: .}) | .id) end;

def trim_ws: sub("^\\s+"; "") | sub("\\s+$"; "");
def version_bad: (type == "string") and length > 0
                 and (test("\\s") or contains(": ") or test("[\\x00-\\x1f\\x7f]") or length > 128);

. as $in
| ($in.components // []) as $c
| ($c | map(. + {purlS: (.purl // "")})) as $cc

# --- OS namespace value ---
| [ $cc[] | select(.purlS | is_os_purl) | (.purlS | purl_ns) as $ns | select($ns != null)
      | . + {ns: $ns} ] as $os_with_ns
# A namespace is also accepted when it is the distribution the document or the
# purl itself declares (an operating-system component, or the purl's distro id).
| ($in.osNames // [] | map(ascii_downcase) | unique) as $osn
| [ $os_with_ns[] | (.ns | ascii_downcase) as $n
      | select((distro_ok($n) or ($osn | index($n)) != null or ((.purlS | qualifier_distro) == $n)) | not) ] as $os_bad
| ($os_bad | group_by(.ns | ascii_downcase)
   | map({v: (.[0].ns | clean(40)), n: length}) | sort_by(-.n)) as $os_vals
| ($os_vals[0:5] | map("\(.v) (\(.n))") | join(", ")) as $os_list

# --- version sanity ---
| [ $cc[] | select((.version | type) == "string" and (.version | length) > 0) ] as $with_ver
| [ $with_ver[] | select(.version | version_bad) ] as $ver_bad

# --- purl-namespace failures (the existing check's own definition) ---
| [ $cc[] | select(.purlS | test($nsre)) | select((.purlS | test($nsnsre)) | not) ] as $ns_missing

# one operating-system name for the whole document, when it is a distribution id
| (if ($osn | length) == 1 and distro_ok($osn[0]) then $osn[0] else null end) as $os_hint

| def os_candidate:
    (.purlS | purl_pkgtype) as $t
    | (.purlS | qualifier_raw) as $raw
    | (.purlS | qualifier_distro) as $d
    | if $raw != null and ($raw | test("^[0-9]") | not)
      then (if $d != null and type_ok($t; $d)
            then {ns: $d, basis: "distro qualifier in the purl", basis_ko: "purl의 distro 한정자", confidence: "high"}
            else null end)
      elif $os_hint != null and type_ok($t; $os_hint)
      then {ns: $os_hint, basis: "operating-system component of the SBOM", basis_ko: "SBOM의 operating-system 구성요소", confidence: "medium"}
      else null end;
  def none($note; $note_ko): {candidates: [], basis: "none", basis_ko: "없음", confidence: "none", note: $note, note_ko: $note_ko};
  def base: {ref: ((.ref // null) | if . == null then null else clean(200) end), name: ((.name // null) | if . == null then null else clean(200) end), version: ((.version // null) | if . == null then null else clean(200) end)};

  ( [ $os_bad[] | . as $x
        | ($x | os_candidate) as $k
        | ($x | base) + {check: "purl-namespace-os", field: "purl", original: ($x.purlS | clean(300))}
          + (if $k == null
             then none("The base distribution is needed to name the namespace; it cannot be derived from this SBOM.";
                       "네임스페이스에 쓸 기반 배포판이 필요하지만 이 SBOM에서는 알 수 없습니다.")
             else {candidates: [ $x.purlS | sub("^pkg:(?<t>rpm|deb|apk)/[^/@?#]+/"; "pkg:" + .t + "/" + $k.ns + "/"; "i") ],
                   basis: $k.basis, basis_ko: $k.basis_ko, confidence: $k.confidence} end) ]
    + [ $ns_missing[] | . as $x
        | ($x | base) + {check: "purl-namespace", field: "purl", original: ($x.purlS | clean(300))}
          + (if ($x.purlS | is_os_purl) then
               (($x | os_candidate) as $k
                | if $k == null
                  then none("The base distribution is needed to name the namespace; it cannot be derived from this SBOM.";
                            "네임스페이스에 쓸 기반 배포판이 필요하지만 이 SBOM에서는 알 수 없습니다.")
                  else {candidates: [ $x.purlS | sub("^pkg:(?<t>rpm|deb|apk)/"; "pkg:" + .t + "/" + $k.ns + "/"; "i") ],
                        basis: $k.basis, basis_ko: $k.basis_ko, confidence: $k.confidence} end)
             elif ($x.purlS | test("^pkg:maven/"; "i"))
                  and (($x.group // "") | type == "string") and (($x.group // "") | test("^[A-Za-z0-9._-]+$"))
                  and (($x.purlS | purl_head | ltrimstr("pkg:maven/") | sub("@.*$"; "") | ascii_downcase) as $pn
                       | ($pn | test(":|%3a")) | not)
                  and (($x.purlS | purl_head | ltrimstr("pkg:maven/") | sub("@.*$"; "") | ascii_downcase) as $pn
                       | ($pn | startswith($x.group | ascii_downcase)) | not) then
               {candidates: [ $x.purlS | sub("^pkg:maven/"; "pkg:maven/" + ($x.group | @uri) + "/"; "i") ],
                basis: "group field of the component (not proven to match the purl name)", basis_ko: "구성요소의 group 필드 (purl 이름과의 일치는 확인되지 않음)", confidence: "medium"}
             else
               none("The namespace this purl type requires is needed; it cannot be derived from this SBOM.";
                    "이 purl 유형이 요구하는 네임스페이스가 필요하지만 이 SBOM에서는 알 수 없습니다.")
             end) ]
    + [ $ver_bad[] | . as $x
        | ($x.version | trim_ws) as $t
        | ($x | base) + {check: "version-sanity", field: "version", original: ($x.version | clean(300))}
          + (if $t != $x.version and ($t | length) > 0 and (($t | version_bad) | not)
             then {candidates: [$t], basis: "leading or trailing whitespace removed", basis_ko: "앞뒤 공백 제거", confidence: "high"}
             else none("The intended version cannot be determined from this value.";
                       "이 값만으로는 의도한 버전을 알 수 없습니다.") end) ]
  ) as $sug

| { rows: [
      { id: "purl-namespace-os",
        label: ("PURL namespace of rpm/deb/apk is a distribution id" + (if $required then "" else " (advisory)" end)),
        label_ko: ("rpm/deb/apk PURL 네임스페이스가 배포판 식별자" + (if $required then "" else " (권고)" end)),
        required: $required,
        source: (if ($os_with_ns | length) == 0 then "na" else "auto" end),
        naKind: (if ($os_with_ns | length) == 0 then "not-applicable" else "" end),
        status: (if ($os_bad | length) == 0 then "pass" elif $required then "fail" else "warn" end),
        detail: (if ($os_with_ns | length) == 0 then "no rpm, deb or apk identifiers with a namespace"
                 elif ($os_bad | length) == 0 then "all namespaces are distribution ids"
                 else "\($os_bad | length) with a namespace that is not a distribution id: \($os_list)" end),
        detail_ko: (if ($os_with_ns | length) == 0 then "네임스페이스를 가진 rpm, deb, apk 식별자 없음"
                    elif ($os_bad | length) == 0 then "모든 네임스페이스가 배포판 식별자임"
                    else "배포판 식별자가 아닌 네임스페이스 \($os_bad | length)개: \($os_list)" end),
        missing: ([ $os_bad[] | .purlS | clean(300) ][0:$cap]) },
      { id: "version-sanity",
        label: ("Component version is a plain version string" + (if $required then "" else " (advisory)" end)),
        label_ko: ("구성요소 버전이 정상적인 버전 문자열" + (if $required then "" else " (권고)" end)),
        required: $required,
        source: (if ($with_ver | length) == 0 then "na" else "auto" end),
        naKind: (if ($with_ver | length) == 0 then "not-applicable" else "" end),
        status: (if ($ver_bad | length) == 0 then "pass" elif $required then "fail" else "warn" end),
        detail: (if ($with_ver | length) == 0 then "no component versions to check"
                 else "\($ver_bad | length) malformed version(s) (whitespace, \"key: value\" shape, control character or over 128 characters)" end),
        detail_ko: (if ($with_ver | length) == 0 then "확인할 구성요소 버전 없음"
                    else "비정상 버전 \($ver_bad | length)개 (공백, \"키: 값\" 형태, 제어 문자 또는 128자 초과)" end),
        missing: ([ $ver_bad[] | ((.name // "(unnamed)") | clean(80)) + "@" + (.version | clean(120)) ][0:$cap]) }
    ],
    suggestions: $sug }
