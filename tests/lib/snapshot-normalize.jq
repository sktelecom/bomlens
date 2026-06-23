# snapshot-normalize.jq — strip volatile fields from a CycloneDX SBOM so that a
# committed golden snapshot diffs only on MEANINGFUL changes (specVersion,
# component set, fields, licenses, cpe/purl). Used by tests/test-snapshot.sh and
# the generation/upstream-compat snapshot jobs.
#
# Removed (noise on every run / every tool bump):
#   - serialNumber           (random per run)
#   - metadata.timestamp     (wall-clock)
#   - metadata.tools[].version / tools.components[].version  (bumps on upgrade —
#     the whole point is to see what ELSE changed when a tool version moves)
# Kept on purpose: specVersion, component count/fields, licenses, cpe, purl,
# dependencies — these are the contract a tool upgrade must not silently break.

def strip_tool_versions:
  if (.metadata.tools | type) == "object" then
    .metadata.tools.components = ((.metadata.tools.components // []) | map(del(.version)))
  elif (.metadata.tools | type) == "array" then
    .metadata.tools |= map(del(.version))
  else . end;

del(.serialNumber)
| del(.metadata.timestamp)
| strip_tool_versions
# Deterministic component ordering so reordering alone is never a false diff.
| .components = ((.components // []) | sort_by((.purl // "") + "|" + (.name // "") + "|" + (.version // "")))
