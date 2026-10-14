# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# security-advisory-ids.jq - keep distribution advisory numbers out of the
# vulnerability list.
#
# Input and output: a Trivy JSON report (_security.json), before the other
# engines' results are merged in. Trivy files a finding under the number of a
# distribution's update advisory when the advisory data names no CVE for it:
# Debian (DLA-4792-1, DSA-...), Oracle Linux (ELSA-...), SUSE and openSUSE
# (SUSE-SU-..., openSUSE-SU-...), Bottlerocket (BRSA-...). Red Hat, Ubuntu,
# Amazon Linux, AlmaLinux and Rocky Linux findings come out under their CVE,
# with the advisory number in VendorIDs. Such an advisory announces an update
# and can cover several vulnerabilities, or a fix with none, so its number does
# not belong in a list of vulnerabilities, its counts or its EPSS/KEV lookup.
#
# A finding filed under a distribution advisory number is handled in one of
# two ways:
#   - The advisory names a CVE: it is reported under that CVE, one finding per
#     CVE, and the advisory number is kept in VendorIDs, the field Trivy itself
#     uses for a CVE's advisory numbers. A CVE already reported for the same
#     package takes the advisory number into its own VendorIDs instead of being
#     repeated. A CVE made this way takes the advisory's severity and fixed
#     version (the highest severity, and every fixed version, when several
#     advisories name it) and is marked bomlens:fromAdvisory.
#   - It names none: it moves to the top-level Advisories list, with the Target
#     it came from. It is not counted in the vulnerability totals, the severity
#     counts or the --fail-on gate, and the reports list it apart.
#
# Every other id stays a finding. A Node.js security working group entry
# (NSWG-ECO-...) describes one vulnerability: when it names a CVE it is
# reported under that CVE in the same way, otherwise it is left as it is. A
# lower-case ghsa- or cve- prefix is written in upper case.
#
# A CVE counts as named only when it is in VendorIDs, or when PrimaryURL or a
# reference is the record page of that one CVE (nvd.nist.gov, cve.org,
# cve.mitre.org, or SUSE's CVE page, the only CVE link a SUSE advisory
# carries). A CVE mentioned in any other link, such as a commit or a mailing
# list post, is not taken. Idempotent: a second pass finds nothing to do.

def sa_is_distro_advisory:
  test("^(DLA|DSA|DTSA|ELSA|BRSA|USN|RHSA|RHBA|RHEA|ALAS[0-9A-Z]*|ALSA|RLSA|MGASA|FEDORA|GLSA|SUSE-[A-Z]{2}|openSUSE-[A-Z]{2})-");

def sa_is_single_record: test("^NSWG-ECO-");

def sa_norm_id:
  if test("^ghsa-") then "GHSA-" + .[5:]
  elif test("^cve-") then "CVE-" + .[4:]
  else . end;

def sa_pkg_key: (((.PkgIdentifier // {}).PURL // .PkgName) // "");

def sa_uniq: reduce .[] as $v ([]; if index([$v]) then . else . + [$v] end);

# The CVE whose record page this URL is, or nothing.
def sa_cve_of_url:
  capture("^https?://(www\\.)?(nvd\\.nist\\.gov/vuln/detail/|cve\\.org/CVERecord\\?id=|cve\\.mitre\\.org/cgi-bin/cvename\\.cgi\\?name=|suse\\.com/security/cve/)(?<c>CVE-[0-9]{4}-[0-9]{4,})/?$")?
  | .c;

# CVE ids this finding names, first occurrence first.
def sa_related_cves:
  [ ((.VendorIDs // [])[]? | strings | select(test("^CVE-[0-9]{4}-[0-9]{4,}$"))),
    ((.PrimaryURL // "") | strings | sa_cve_of_url),
    ((.References // [])[]? | strings | sa_cve_of_url) ]
  | sa_uniq;

# The advisory numbers to keep in VendorIDs: its own, then any other non-CVE
# number it carried.
def sa_vendor_ids($orig):
  ([$orig] + ((.VendorIDs // []) | map(strings | select(test("^CVE-") | not)))) | sa_uniq;

# Add $v to .vulns, or, when the same id is already reported for the same
# package, add $ids to that finding's VendorIDs.
def sa_put($v; $ids):
  ($v | sa_pkg_key) as $k
  | (.vulns | map((.VulnerabilityID == $v.VulnerabilityID) and (sa_pkg_key == $k)) | index(true)) as $at
  | if $at != null then
      .vulns[$at] |= (.VendorIDs = (((.VendorIDs // []) + ($ids | map(select(. != $v.VulnerabilityID)))) | sa_uniq))
    else .vulns += [$v] end;

def sa_sev_rank: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}[. // "" | ascii_upcase] // 0;

# One CVE for one package, from every advisory ($g: [{cve, o}]) that names it.
# The result does not depend on the advisories' order: the fields come from
# the one with the lowest id, Severity is the highest any of them gives,
# FixedVersion lists their fixed versions sorted, and VendorIDs holds every
# advisory number, sorted. It is marked bomlens:fromAdvisory. When Trivy
# already reports the CVE for the package, that finding is kept and only
# takes the advisory numbers into its VendorIDs.
def sa_put_group($g):
  ($g[0].cve) as $cve
  | ($g | map(.o) | sort_by(.VulnerabilityID // "")) as $os
  | ([$os[] | sa_vendor_ids(.VulnerabilityID)] | add | unique) as $ids
  | ([$os[] | .Severity] | max_by(sa_sev_rank)) as $sev
  | ([$os[] | .FixedVersion | strings | select(. != "")] | unique | join(", ")) as $fixed
  | sa_put($os[0] | .VulnerabilityID = $cve | .VendorIDs = $ids
           | (if $sev == null then del(.Severity) else .Severity = $sev end)
           | (if $fixed == "" then del(.FixedVersion) else .FixedVersion = $fixed end)
           | .["bomlens:fromAdvisory"] = true; $ids);

# True for a finding this filter rewrites or moves.
def sa_needs_work:
  (.VulnerabilityID // "") as $id
  | ($id | sa_is_distro_advisory) or ($id | sa_norm_id != $id)
    or (($id | sa_is_single_record) and (sa_related_cves | length) > 0);

(.Advisories // []) as $prior
| reduce range(0; (.Results // []) | length) as $i (
    {doc: ., adv: []};
    .doc.Results[$i] as $r
    | ($r.Vulnerabilities // []) as $all
    | if ($all | any(sa_needs_work) | not) then .
      else
        ({vulns: ($all | map(select(sa_needs_work | not))), adv: []}
         | reduce ($all[] | select(sa_needs_work)
                   | select(.VulnerabilityID // "" | sa_norm_id != .)) as $o (.;
             sa_put($o | .VulnerabilityID |= sa_norm_id; $o.VendorIDs // []))
         | reduce ([$all[] | select(sa_needs_work)
                   | select(.VulnerabilityID // "" | sa_norm_id == .)
                   | . as $o | sa_related_cves[] | {cve: ., key: ($o | sa_pkg_key), o: $o}]
                   | group_by([.cve, .key]))[] as $g (.; sa_put_group($g))
         | .adv += [$all[] | select(sa_needs_work)
                   | select(.VulnerabilityID // "" | sa_norm_id == .)
                   | select((sa_related_cves | length) == 0)
                   | . + {Target: ($r.Target // "")}]) as $out
        | .doc.Results[$i].Vulnerabilities = $out.vulns
        | .adv += $out.adv
      end)
| if (.adv | length) > 0 or ($prior | length) > 0
  then .doc + {Advisories: ($prior + .adv)}
  else .doc end
