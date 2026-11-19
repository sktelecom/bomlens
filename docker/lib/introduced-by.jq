# SPDX-License-Identifier: Apache-2.0
# For each package URL named in $purls, the direct dependencies of the scanned
# product that pull it in: the entries of the root component's dependsOn that
# the component is reached through, nearest first, at most $max of them.
#
#   jq -f introduced-by.jq --argjson purls '["pkg:maven/a/b@1"]' --argjson max 3 sbom.json
#
# Output: {graph: <bool>, skipped: <string>, map: {purl: [{name, version, purl, direct}]}}
#   graph    false when the SBOM has no usable dependency graph (no edge, or no
#            root to count from); map is then empty.
#   skipped  "too-large" when the SBOM holds more components than the cap; the
#            map is then empty (the walk is not worth its cost on such a graph).
#   direct   true on the entry for the component itself when it is a direct
#            dependency (the fix is to raise it).
# A component the walk cannot connect to the root gets no entry: the reader is
# told nothing rather than a guess.
def cap: 20000;
(.components // []) as $comps
| ([ .dependencies[]? | select((.ref // "") != "") ]) as $deps
| (.metadata.component["bom-ref"] // "") as $root
| ($deps | map({key: .ref, value: (.dependsOn // [])}) | from_entries) as $down
| (if $root != "" and ($down[$root] != null) then $down[$root]
   else
     # No usable root reference: what nothing depends on, among the nodes that
     # have edges, is the top, and its dependencies are the direct ones.
     ([ $deps[].dependsOn[]? ] | unique) as $targets
     | [ $deps[] | select(.ref as $r | ($targets | index($r)) == null) | .dependsOn[]? ] | unique
   end) as $direct
| ([ $deps[] | .dependsOn[]? ] | length) as $edges
| if $edges == 0 or ($direct | length) == 0 then {graph: false, skipped: "", map: {}}
  elif ($comps | length) > cap then {graph: true, skipped: "too-large", map: {}}
  else
    ($deps | reduce .[] as $d ({}; reduce ($d.dependsOn // [])[] as $c (.; .[$c] += [$d.ref]))) as $up
    | ($direct | map({key: ., value: true}) | from_entries) as $isdirect
    | ($comps | map(select((.["bom-ref"] // "") != "")
                    | {key: .["bom-ref"], value: {name: (.name // ""), version: (.version // ""), purl: (.purl // "")}})
       | from_entries) as $info
    | ($comps | map(select((.purl // "") != "" and (.["bom-ref"] // "") != "")
                    | {key: .purl, value: .["bom-ref"]}) | reverse | from_entries) as $ref_of
    | def walk($start):
        # Breadth-first toward the root; a direct dependency ends the walk.
        if $isdirect[$start] then [$start]
        else
          {seen: {($start): true}, front: [$start], hits: []}
          | until((.front | length) == 0 or (.hits | length) >= $max;
              .seen as $seen
              | (.front | map($up[.] // []) | add // [] | unique
                 | map(select(. != $root and ($seen[.] | not)))) as $next
              | .seen += ($next | map({key: ., value: true}) | from_entries)
              | .hits += ($next | map(select($isdirect[.])))
              | .front = ($next | map(select($isdirect[.] | not))))
          | .hits[0:$max]
        end;
      {graph: true, skipped: "",
       map: ($purls | unique
             | map(. as $p | ($ref_of[$p] // null) as $r
                   | select($r != null)
                   | (walk($r) | map(. as $h | ($info[$h] // {name: $h, version: "", purl: ""}) + {direct: ($h == $r)})) as $by
                   | select(($by | length) > 0)
                   | {key: $p, value: $by})
             | from_entries)}
  end
