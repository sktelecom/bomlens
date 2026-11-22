#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# check-doc-ci-examples.sh - syntax-check the CI examples in the CI/CD guide.
#
# Usage: scripts/check-doc-ci-examples.sh [<file.md>...]
#        (default: docs/guides/ci-cd.md and docs/guides/ci-cd.ko.md)
#
# Every ```yaml block is taken out of the page. A block with a top-level
# `jobs:` is a GitHub Actions workflow and is checked with actionlint. Any
# other block is a GitLab CI file: it must parse as YAML, and each job's
# `stage` (test when it has none) must be one GitLab accepts: one listed under
# `stages:`, or build, test or deploy when there is no `stages:`, and .pre and
# .post in either case.
#
# Needs actionlint on PATH and python3 with PyYAML. Exit 0 when every block
# passes, 1 when one does not, 2 when a tool is missing.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "$#" -eq 0 ]; then
    set -- "$ROOT_DIR/docs/guides/ci-cd.md" "$ROOT_DIR/docs/guides/ci-cd.ko.md"
fi

command -v actionlint >/dev/null 2>&1 || { echo "[ERROR] actionlint is not on PATH (https://github.com/rhysd/actionlint)." >&2; exit 2; }
python3 -c 'import yaml' 2>/dev/null || { echo "[ERROR] python3 cannot import yaml: PyYAML is needed to read the GitLab examples." >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Write each GitHub Actions block to $WORK/<n>-github.yml and list it with
# its place in the page in where.txt. The GitLab blocks are checked here.
rc=0
python3 -I - "$WORK" "$@" <<'PY' || rc=$?
import os
import sys

import yaml

work, pages = sys.argv[1], sys.argv[2:]
GITLAB_KEYWORDS = {"default", "include", "stages", "variables", "workflow", "image",
                   "services", "cache", "before_script", "after_script"}
failed = 0
n = 0
for page in pages:
    with open(page, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    i = 0
    while i < len(lines):
        if lines[i].strip() != "```yaml":
            i += 1
            continue
        start = i + 1
        j = start
        while j < len(lines) and lines[j].strip() != "```":
            j += 1
        text = "\n".join(lines[start:j]) + "\n"
        rel = os.path.relpath(page)
        where = "%s:%d" % (page if rel.startswith("..") else rel, start)
        i = j + 1
        n += 1
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as err:
            print("FAIL %s: not valid YAML: %s" % (where, err))
            failed += 1
            continue
        if not isinstance(doc, dict):
            print("FAIL %s: not a YAML mapping" % where)
            failed += 1
            continue
        if "jobs" in doc:
            path = os.path.join(work, "%02d-github.yml" % n)
            with open(path, "w", encoding="utf-8") as out:
                out.write(text)
            with open(os.path.join(work, "where.txt"), "a", encoding="utf-8") as out:
                out.write("%s %s\n" % (path, where))
            continue
        declared = doc.get("stages")
        if declared is not None and not (isinstance(declared, list) and all(isinstance(s, str) for s in declared)):
            print("FAIL %s: stages: is not a list of names" % where)
            failed += 1
            continue
        allowed = set(declared if declared is not None else ["build", "test", "deploy"]) | {".pre", ".post"}
        jobs = {k: v for k, v in doc.items() if k not in GITLAB_KEYWORDS and not str(k).startswith(".")}
        if not jobs:
            print("FAIL %s: no GitLab job found" % where)
            failed += 1
            continue
        bad = []
        for name, job in jobs.items():
            if not isinstance(job, dict) or "script" not in job:
                bad.append("%s has no script" % name)
                continue
            stage = job.get("stage", "test")
            if stage not in allowed:
                bad.append("%s uses stage %r, not one of %s" % (name, stage, ", ".join(sorted(allowed))))
        if bad:
            print("FAIL %s: %s" % (where, "; ".join(bad)))
            failed += 1
        else:
            print("PASS %s: GitLab CI (%s)" % (where, ", ".join(jobs)))
if n == 0:
    print("FAIL no ```yaml block in %s" % ", ".join(pages))
    failed += 1
sys.exit(1 if failed else 0)
PY

if [ -f "$WORK/where.txt" ]; then
    while read -r file where; do
        if out="$(cd "$WORK" && actionlint -no-color "$(basename "$file")" 2>&1)"; then
            echo "PASS $where: GitHub Actions (actionlint)"
        else
            echo "FAIL $where: actionlint (line numbers count from the line after the fence):"
            printf '%s\n' "$out" | sed 's/^/  /'
            rc=1
        fi
    done < "$WORK/where.txt"
fi
exit "$rc"
