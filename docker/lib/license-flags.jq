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

# ---------------------------------------------------------------------------
# SPDX expression parsing (bomlens:licenseConflict).
#
# MIRROR of parseLicenseExpression in licenses.ts; tests/test-postprocess.sh
# diffs the operator patterns of the two files.
#
# Why a parser at all: a component's license arrives in two different shapes —
# several entries in `licenses[]`, or ONE string holding an SPDX expression
# ("MIT OR Apache-2.0", "EPL-2.0 AND GPL-2.0-with-classpath-exception"). OR and
# AND mean opposite things for a conflict verdict: OR lets the consumer pick one
# (so one compatible choice clears it), AND applies every term at once (so one
# bad term condemns it). license_class above deliberately ignores the operators
# and takes the worst term — safe for a strength label, wrong for a verdict.
#
# Scope: flat expressions only. Parentheses are NOT parsed — a nested expression
# yields no terms and the caller records "unknown" rather than guessing. AND
# binds tighter than OR (per the SPDX spec), which falls out of splitting on OR
# first and then on AND.
#
# Shape: [[term, …], …] — a list of OR alternatives, each a list of AND terms.
#   "MIT OR Apache-2.0"      -> [["MIT"], ["Apache-2.0"]]
#   "EPL-1.0 AND LGPL-2.1"   -> [["EPL-1.0", "LGPL-2.1"]]
#   "(A OR B) AND C"         -> []            (parenthesised: not parsed)
# ---------------------------------------------------------------------------

# A slash is the other OR spelling seen in the wild ("MIT/X11"). Only treated as
# an operator when there is exactly one and the string carries no URL scheme, so
# a license *name* holding a link is never chopped in half.
def slash_is_or($s):
  ([$s | scan("/")] | length) == 1 and ($s | test("://") | not);

def parse_license_expr($s):
  (($s // "") | sub("^\\s+"; "") | sub("\\s+$"; "")) as $e
  | if $e == "" or ($e | test("[()]")) then []
    else
      (if slash_is_or($e) then ($e | sub("\\s*/\\s*"; " OR ")) else $e end)
      | [ splits("\\s+OR\\s+"; "i") ]
      | map([ splits("\\s+AND\\s+"; "i") ] | map(sub("^\\s+"; "") | sub("\\s+$"; "")) | map(select(. != "")))
      | map(select(length > 0))
    end;

# True when a term carries an exception clause. Such a clause exists precisely to
# permit a combination the base license would otherwise forbid (the classpath
# exception being the common one), so the verdict is capped at "conditional" and
# never reaches "incompatible".
def has_license_exception($t):
  ($t // "") | test("\\bWITH\\b|-with-.*-exception"; "i");

# ---------------------------------------------------------------------------
# license_conflict — does a dependency's license clash with the outbound license
# the project is distributed under?
#
# Distinct from license_class, which labels one component's copyleft strength in
# isolation. A conflict only exists relative to an outbound license, so this
# needs `metadata.component.licenses` (declared by the supplier's SBOM, or set
# with PROJECT_LICENSE). With no outbound license there is no verdict — the
# caller records nothing rather than guessing.
#
# Rules live in license-compat.json (passed in as $compat) so the reasoning is
# reviewable data, not code: a class matrix plus explicit pairs for the known
# exceptions the class matrix cannot express (GPL-2.0-only with Apache-2.0).
#
# Combination follows the operators (see parse_license_expr):
#   AND terms  -> worst verdict wins (every term applies)
#   OR groups  -> best verdict wins (the consumer picks one)
# ---------------------------------------------------------------------------

def verdict_rank: {"compatible": 0, "conditional": 1, "unknown": 2, "incompatible": 3};

# Verdict for ONE dependency term against the outbound license. Explicit pairs
# win over the class matrix; an exception clause caps the result at conditional.
def term_verdict($term; $outbound; $compat):
  ($term | ascii_upcase) as $dep_up
  | ($outbound | ascii_upcase) as $out_up
  | ( ($compat.pairs // [])
      | map(select((.outbound | ascii_upcase) == $out_up and (.dependency | ascii_upcase) == $dep_up))
      | first ) as $pair
  | (if $pair != null then {verdict: $pair.verdict, why: $pair.why}
     else
       (license_class($outbound)) as $out_class
       | (license_class($term)) as $dep_class
       | (($compat.matrix[$out_class] // {})[$dep_class]) as $cell
       | if $cell == null then {verdict: "unknown", why: "No rule for this combination."}
         else {verdict: $cell.verdict, why: $cell.why} end
     end)
  | if has_license_exception($term) and .verdict == "incompatible"
    then {verdict: "conditional",
          why: ("The dependency carries an exception clause, which exists to permit exactly this combination. Confirm the exception covers your use. (" + .why + ")")}
    else . end;

# Verdict for one license string (which may be an SPDX expression) against the
# outbound license. Returns null when the string yields no parseable terms, so
# the caller can fall back to "unknown".
def expr_verdict($s; $outbound; $compat):
  (parse_license_expr($s)) as $groups
  | if ($groups | length) == 0 then null
    else
      $groups
      | map( map(term_verdict(.; $outbound; $compat)) | max_by(verdict_rank[.verdict]) )
      | min_by(verdict_rank[.verdict])
    end;

# Verdict for a whole CycloneDX component. Several `licenses[]` entries mean the
# consumer may choose one (CycloneDX treats them as alternatives), so the best
# verdict across entries wins — the same rule as OR inside an expression.
def component_license_conflict($outbound; $compat):
  [ (.licenses // [])[] | (.license.id // .license.name // .expression // "") | select(. != "") ] as $strings
  | if ($strings | length) == 0 then {verdict: "unknown", why: "The component declares no license."}
    else
      ([ $strings[] | expr_verdict(.; $outbound; $compat) | select(. != null) ]) as $vs
      | if ($vs | length) == 0
        then {verdict: "unknown", why: "The declared license could not be parsed as an SPDX expression."}
        else $vs | min_by(verdict_rank[.verdict]) end
    end;
