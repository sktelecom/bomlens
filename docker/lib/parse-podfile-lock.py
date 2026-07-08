#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# parse-podfile-lock.py — reconstruct the CocoaPods dependency graph from a Podfile.lock.
#
# Usage: parse-podfile-lock.py <Podfile.lock> <name2ref.json>
#   <name2ref.json> maps each pod name to the bom-ref of its emitted component
#   (identify-cocoapods.sh builds it from the syft component set). Prints one CycloneDX
#   dependency object per line ({"ref": ..., "dependsOn": [...]}) for pods that have
#   sub-dependencies. Names that are not in the map (e.g. a pod syft did not surface) are
#   skipped so every ref points at a real component.
#
# Why parse by hand instead of a YAML lib: the scanner image ships no PyYAML, and
# Podfile.lock's PODS block has a fixed two-space layout — a top-level "  - Name (ver)"
# entry, optionally followed by four-space "    - SubName (constraint)" children. That is
# all we need; the nested list under each pod is its resolved sub-dependency set.
import json
import re
import sys

# "  - Alamofire (5.8.1)"  /  "  - Moya (15.0.0):"  (trailing colon when children follow)
POD = re.compile(r"^  - (?P<name>.+?)(?: \((?P<ver>[^)]*)\))?:?\s*$")
# "    - Moya/Core (= 15.0.0)"  ->  name only (version comes from the pod's own entry)
SUB = re.compile(r"^    - (?P<name>.+?)(?: \([^)]*\))?\s*$")


def main() -> int:
    if len(sys.argv) < 3:
        return 0
    lock_path, map_path = sys.argv[1], sys.argv[2]
    try:
        with open(lock_path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
        with open(map_path, encoding="utf-8") as fh:
            name2ref = json.load(fh)
    except (OSError, ValueError):
        return 0
    if not isinstance(name2ref, dict):
        return 0

    edges = {}          # pod name -> set of sub-dependency names
    in_pods = False
    current = None
    for line in lines:
        if not in_pods:
            if line.rstrip() == "PODS:":
                in_pods = True
            continue
        # The PODS block ends at the next top-level key (a non-indented, non-empty line).
        if line and not line.startswith(" "):
            break
        m = POD.match(line)
        if m:
            current = m.group("name").strip()
            edges.setdefault(current, set())
            continue
        s = SUB.match(line)
        if s and current is not None:
            edges[current].add(s.group("name").strip())

    for pod, subs in edges.items():
        ref = name2ref.get(pod)
        if not ref or not subs:
            continue
        depends = sorted(
            {name2ref[s] for s in subs if s in name2ref and name2ref[s] != ref}
        )
        if depends:
            print(json.dumps({"ref": ref, "dependsOn": depends}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
