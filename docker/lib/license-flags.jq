# license-flags.jq — classify a license id/name into an AI-relevant restriction
# class that a human must review. Single source of truth shared by
# generate-notice.sh (the "license review" section) and normalize-sbom.sh (the
# bomlens:licenseReview component property the web UI can badge).
#
# Scope is deliberately narrow: the licenses that standard OSS-compliance tooling
# does NOT already make obvious and that the AI guidance (OpenChain 3.5, G7)
# calls out — behavioral-use restrictions (RAIL/OpenRAIL, Llama/Gemma/Falcon
# community licenses) and non-commercial terms (CC-BY-NC…). Permissive (MIT,
# Apache) and ordinary copyleft (GPL/LGPL) are intentionally NOT flagged here, so
# a normal software scan's NOTICE is unchanged.
#
# Returns "" for anything not in scope. The tool only SURFACES the class; whether
# a given restriction applies to a use is a human/legal judgement.
def license_flag($s):
  (($s // "") | ascii_downcase | gsub("[ ._/-]+"; " ")) as $n |
  if   ($n | test("openrail|\\brail\\b|responsible ai|community license|\\bllama|\\bgemma\\b|falcon llm")) then "behavioral-use"
  elif ($n | test("cc by nc|non ?commercial")) then "non-commercial"
  else "" end;

# ---------------------------------------------------------------------------
# license_class — copyleft-strength classification (bomlens:licenseClass).
#
# MIRROR of the web UI classifier in
# docker/web/frontend/src/lib/licenses.ts (licenseRiskTier + TIER_RANK): the
# same permissive allowlist, the same tier patterns in the same order, and the
# same worst-of precedence, so the SBOM property, the risk report and the UI
# badge never disagree. tests/test-postprocess.sh diffs the id sets and
# patterns of the two files, so a change on either side without the matching
# change on the other fails CI.
#
# The headline rule (same as the UI): an unrecognised license is NEVER assumed
# permissive — it falls to "uncategorized" (a human must look). Orthogonal to
# license_flag above: a component can carry both bomlens:licenseClass and
# bomlens:licenseReview.
# ---------------------------------------------------------------------------

# Known permissive SPDX ids (uppercased). An allowlist, not a heuristic — keep
# in sync with the PERMISSIVE set in licenses.ts (single line: the drift guard
# extracts the quoted ids from this def).
def permissive_ids: ["MIT","MIT-0","ISC","0BSD","BSD-2-CLAUSE","BSD-3-CLAUSE","APACHE-2.0","APACHE-1.1","ZLIB","UNLICENSE","BSL-1.0","PSF-2.0","PYTHON-2.0","CC0-1.0","WTFPL","NCSA","X11"];

# Classify ONE license id/name/expression. Order matters: AGPL and LGPL are
# matched before the bare GPL test so they don't fall to strong-copyleft.
def license_class($s):
  (($s // "") | sub("^\\s+"; "") | sub("\\s+$"; "")) as $id
  | if $id == "" then "uncategorized"
    elif ((permissive_ids | index($id | ascii_upcase)) != null) then "permissive"
    elif ($id | test("\\bAGPL"; "i")) then "network-copyleft"
    elif ($id | test("\\bLGPL"; "i")) then "weak-copyleft"
    elif ($id | test("\\b(MPL|EPL|CDDL|CPL|OSL|EUPL|CeCILL|Sleepycat)\\b"; "i")) then "weak-copyleft"
    elif ($id | test("\\bGPL"; "i")) then "strong-copyleft"
    else "uncategorized" end;

# Worst-of ranking across a component's licenses (licenses.ts TIER_RANK):
# network > strong > weak > uncategorized > permissive. Known copyleft outranks
# an unknown license; an unknown license outranks known-permissive.
def class_rank: {"network-copyleft": 5, "strong-copyleft": 4, "weak-copyleft": 3, "uncategorized": 2, "permissive": 1};

# One class for a whole CycloneDX component: the strongest class across its
# non-empty license ids/names/expressions (the same strings the web server
# extracts for the UI); a component with no license info is "uncategorized".
def component_license_class:
  [ (.licenses // [])[] | (.license.id // .license.name // .expression // "") | select(. != "") ]
  | if length == 0 then "uncategorized"
    else map(license_class(.)) | max_by(class_rank[.]) end;
