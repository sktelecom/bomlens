#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# fetch-cocoapods-licenses.py - fill the licence of CocoaPods components from
# the podspec the CocoaPods trunk publishes for the exact version.
#
# Usage: fetch-cocoapods-licenses.py <cocoapods_sbom.json> <Podfile.lock> [...]
# Edits the SBOM in place and prints one JSON line of counts to stdout.
#
# Podfile.lock pins every pod and version but carries no licence, and the
# components identify-cocoapods.sh builds from it have none either. The licence
# is in the pod's podspec, which the trunk CDN serves as JSON at
#   <cdn>/Specs/<a>/<b>/<c>/<Name>/<version>/<Name>.podspec.json
# where a, b and c are the first three hex digits of md5(<Name>). A subspec
# (Name/Sub) has no podspec of its own and takes the licence of its pod.
#
# Only pods the lockfile lists under the trunk in SPEC REPOS are asked about
# (trunk, https://cdn.cocoapods.org/, https://github.com/CocoaPods/Specs.git):
# a pod from another spec repo, or from a git or path source, can share a name
# with a trunk pod and be a different project. A lockfile without SPEC REPOS
# (written before CocoaPods 1.7) asks about every pod not under EXTERNAL SOURCES.
#
# A podspec licence is free text ("MIT", "Apache License, Version 2.0"). An
# SPDX id is written as license.id, anything else as a licence name, which
# normalize-sbom.sh maps to an SPDX id when it knows the spelling. Every licence written here is marked bomlens:licenseSource =
# "CocoaPods trunk podspec". A component that already has a licence is left as
# it is.
#
# The first request is made alone. When it cannot reach the CDN at all (no
# network, a proxy that inspects TLS with a CA this container does not trust),
# the rest are not tried, so an offline scan does not wait on every pod.
#
# Environment:
#   COCOAPODS_CDN_URL              base URL of the trunk CDN or a mirror with the
#                                  same layout (default https://cdn.cocoapods.org)
#   COCOAPODS_LICENSE_BUDGET       total seconds for the lookups (default 120)
#   COCOAPODS_LICENSE_FIXTURE_DIR  read "<Name>_<version>.podspec.json" files from
#                                  this directory instead of the network (tests)

import concurrent.futures
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

CDN = os.environ.get("COCOAPODS_CDN_URL", "https://cdn.cocoapods.org").rstrip("/")
REQUEST_TIMEOUT = 12
MAX_WORKERS = 8
DEFAULT_BUDGET = 120
SOURCE = "CocoaPods trunk podspec"
# The CDN refuses the default Python-urllib agent (HTTP 403).
USER_AGENT = "bomlens-scanner"
NOT_FOUND = "not-found"
TRUNK_REPOS = {
    "trunk",
    "https://cdn.cocoapods.org",
    "https://github.com/cocoapods/specs",
    "git@github.com:cocoapods/specs",
}
# A pod name as CocoaPods allows it in a path; anything else is not asked about.
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


def unquote_yaml(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def repo_key(value):
    key = unquote_yaml(value.rstrip(":")).strip().lower().rstrip("/")
    if key.endswith(".git"):
        key = key[:-4]
    return key


def read_lock(path):
    """(trunk pod names, whether SPEC REPOS was present, external pod names)."""
    trunk, external = set(), set()
    has_spec_repos = False
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return trunk, has_spec_repos, external
    section, repo = None, None
    for line in lines:
        if line and not line.startswith(" "):
            section = line.rstrip().rstrip(":")
            repo = None
            if section == "SPEC REPOS":
                has_spec_repos = True
            continue
        if section == "SPEC REPOS":
            if line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":"):
                repo = repo_key(line.strip())
            elif line.startswith("    - ") and repo in TRUNK_REPOS:
                trunk.add(unquote_yaml(line[6:]))
        elif section == "EXTERNAL SOURCES":
            if line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":"):
                external.add(unquote_yaml(line.strip()[:-1]))
    return trunk, has_spec_repos, external


def podspec_url(name, version):
    digest = hashlib.md5(name.encode("utf-8")).hexdigest()  # noqa: S324 - CDN path shard, not security
    shard = "/".join(digest[:3])
    quoted = urllib.parse.quote(name, safe="")
    return f"{CDN}/Specs/{shard}/{quoted}/{urllib.parse.quote(version, safe='')}/{quoted}.podspec.json"


def fetch(name, version):
    """The podspec's licence text, "" when it names none, NOT_FOUND when the
    CDN has no podspec for the version, or None when the CDN did not answer."""
    fixture_dir = os.environ.get("COCOAPODS_LICENSE_FIXTURE_DIR")
    if fixture_dir:
        path = os.path.join(fixture_dir, f"{name}_{version}.podspec.json")
        if not os.path.isfile(path):
            return NOT_FOUND
        try:
            with open(path, encoding="utf-8") as fh:
                spec = json.load(fh)
        except (OSError, ValueError):
            return None
    else:
        req = urllib.request.Request(podspec_url(name, version), headers={"Accept": "application/json", "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:  # noqa: S310
                spec = json.load(resp)
        except urllib.error.HTTPError as exc:
            return NOT_FOUND if exc.code == 404 else None
        except (urllib.error.URLError, OSError, ValueError):
            return None
    if not isinstance(spec, dict):
        return ""
    lic = spec.get("license")
    if isinstance(lic, dict):
        lic = lic.get("type")
    return lic.strip() if isinstance(lic, str) else ""


def spdx_ids():
    """SPDX ids the CycloneDX schema accepts in license.id, keyed by lower case."""
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "cdx-spdx-ids.json"),
                  encoding="utf-8") as fh:
            ids = json.load(fh).get("ids")
    except (OSError, ValueError, AttributeError):
        return {}
    return {str(i).lower(): str(i) for i in ids} if isinstance(ids, list) else {}


def licence_entry(text, ids):
    """An SPDX id ("MIT", "mit") as license.id; any other text as license.name."""
    spdx = ids.get(text.lower())
    return {"license": {"id": spdx}} if spdx else {"license": {"name": text}}


def has_licence(component):
    licences = component.get("licenses")
    return isinstance(licences, list) and any(isinstance(x, dict) and x for x in licences)


def set_prop(component, name, value):
    props = component.get("properties")
    props = [p for p in props if isinstance(p, dict) and p.get("name") != name] if isinstance(props, list) else []
    props.append({"name": name, "value": value})
    component["properties"] = props


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("usage: fetch-cocoapods-licenses.py <cocoapods_sbom.json> <Podfile.lock> [...]\n")
        return 2
    path, locks = sys.argv[1], sys.argv[2:]
    try:
        budget = float(os.environ.get("COCOAPODS_LICENSE_BUDGET", DEFAULT_BUDGET))
    except ValueError:
        budget = DEFAULT_BUDGET
    try:
        with open(path, encoding="utf-8") as fh:
            bom = json.load(fh)
    except (OSError, ValueError):
        sys.stderr.write("[cocoapods] could not read the SBOM for the licence lookup\n")
        return 1

    trunk, external, legacy = set(), set(), False
    for lock in locks:
        t, has_repos, e = read_lock(lock)
        trunk |= t
        external |= e
        legacy = legacy or not has_repos

    def eligible(root):
        if root in trunk:
            return True
        return legacy and root not in external

    counts = {"candidates": 0, "filled": 0, "no_answer": 0, "not_found": 0,
              "other_source": 0, "lookup_failed": 0, "budget_reached": 0}
    work = []
    for comp in bom.get("components") or []:
        if not isinstance(comp, dict) or has_licence(comp):
            continue
        if not str(comp.get("purl") or "").startswith("pkg:cocoapods/"):
            continue
        name, version = str(comp.get("name") or ""), str(comp.get("version") or "")
        root = name.split("/", 1)[0]
        if not eligible(root) or not SAFE_NAME.match(root) or not SAFE_VERSION.match(version):
            counts["other_source"] += 1
            continue
        work.append((comp, (root, version)))
    counts["candidates"] = len(work)

    coords = list(dict.fromkeys(c for _, c in work))
    answers = {}
    deadline = time.monotonic() + budget
    if coords:
        answers[coords[0]] = fetch(*coords[0])
    reachable = not coords or answers[coords[0]] is not None
    rest = coords[1:] if reachable else []
    if rest:
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)
        futures = {pool.submit(fetch, *c): c for c in rest}
        try:
            for fut in concurrent.futures.as_completed(futures, timeout=max(deadline - time.monotonic(), 0)):
                try:
                    answers[futures[fut]] = fut.result()
                except Exception:  # noqa: BLE001 - best effort, never abort a scan
                    answers[futures[fut]] = None
        except concurrent.futures.TimeoutError:
            pass
        pool.shutdown(wait=False, cancel_futures=True)

    ids = spdx_ids()
    for comp, coord in work:
        if coord not in answers:
            counts["lookup_failed" if not reachable else "budget_reached"] += 1
            continue
        answer = answers[coord]
        if answer is None:
            counts["lookup_failed"] += 1
        elif answer == NOT_FOUND:
            counts["not_found"] += 1
        elif not answer:
            counts["no_answer"] += 1
        else:
            comp["licenses"] = [licence_entry(answer, ids)]
            set_prop(comp, "bomlens:licenseSource", SOURCE)
            counts["filled"] += 1

    if counts["filled"]:
        tmp = path + ".podlic.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(bom, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
        except OSError:
            sys.stderr.write("[cocoapods] could not write the SBOM; licences left unfilled\n")
            return 1
    sys.stderr.write(
        f"[cocoapods] licence lookup ({CDN}): {counts['candidates']} pods asked, {counts['filled']} filled, "
        f"{counts['no_answer']} podspecs without a licence, {counts['not_found']} not found, "
        f"{counts['lookup_failed']} failed, {counts['budget_reached']} over the time budget; "
        f"{counts['other_source']} pods from another spec repo or a git/path source not asked.\n"
    )
    if not reachable:
        sys.stderr.write(
            f"[WARN] [cocoapods] {CDN} did not answer, so CocoaPods pods have no licence. "
            "Behind a proxy that inspects TLS, pass its CA with SBOM_EXTRA_CA_CERTS; "
            "for a mirror set COCOAPODS_CDN_URL; FETCH_LICENSE=false turns the lookup off.\n"
        )
    print(json.dumps(counts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
