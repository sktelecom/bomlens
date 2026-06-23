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
# a given restriction applies to a use is a human/legal judgement (see
# docs/internal/ai-sbom-readiness.md §8).
def license_flag($s):
  (($s // "") | ascii_downcase | gsub("[ ._/-]+"; " ")) as $n |
  if   ($n | test("openrail|\\brail\\b|responsible ai|community license|\\bllama|\\bgemma\\b|falcon llm")) then "behavioral-use"
  elif ($n | test("cc by nc|non ?commercial")) then "non-commercial"
  else "" end;
