#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# enrich-license-registry.py - OPT-IN: ask the package registry for a
# component's licence when the SBOM has none, or has only one licence that is
# likely a misreading.
#
# Usage: enrich-license-registry.py <sbom>
# Edits the SBOM in place and prints one JSON line of counts to stdout.
#
# Two cases are asked about, both for the exact version in the purl:
#
#   1. The component has no licence. The registry's licence fills it.
#   2. The component has exactly one licence and it is on the verify list
#      (strong copyleft and non-commercial licences by default). A generator
#      that reads one licence file can record a single GPL for a package the
#      registry lists as dual-licensed or as something else entirely, and that
#      one reading is what blocks a release. When the registry says something
#      different, its answer replaces the recorded one, and the replaced value
#      is kept in bomlens:license:superseded. When the registry agrees, or has
#      no answer, nothing changes.
#
# A component with several licences, or a single licence not on the verify
# list, is not asked about: the generator already read more than one licence,
# or its reading would not change a decision. Neither is a licence that carries
# more than an identifier (its text, a url, or an analyst's "concluded"
# acknowledgement): that is evidence the registry cannot outrank.
#
# A registry answer that lists the recorded licence (after mapping deprecated
# ids such as GPL-2.0+ to GPL-2.0-or-later) confirms it and changes nothing. An
# answer that includes a licence deps.dev could not map to SPDX ("non-standard")
# is not used, since it would understate what applies. Several licences in one
# answer are joined with AND: whether a registry's list means all of them or a
# choice differs by ecosystem, and AND does not understate obligations.
#
# --fill-only asks only about components with no licence (used for a supplier's
# SBOM, whose declared licences are never overwritten).
#
# The registry answer comes from deps.dev, which reads each ecosystem's own
# registry metadata (npm, PyPI, Maven Central, Go, crates.io, NuGet,
# RubyGems). Every licence written here is marked bomlens:licenseSource =
# registry (deps.dev).
#
# Environment:
#   LICENSE_REGISTRY_VERIFY        space- or comma-separated SPDX ids whose single
#                                  occurrence is checked (default below)
#   LICENSE_REGISTRY_BUDGET        total seconds for the lookups (default 240)
#   LICENSE_REGISTRY_API           base URL of a deps.dev v3 compatible API
#                                  (default https://api.deps.dev/v3)
#   LICENSE_REGISTRY_FIXTURE_DIR   read "<system>_<name>_<version>.json" files
#                                  from this directory instead of the network
#   LICENSE_REGISTRY_FIXTURE_DELAY seconds each fixture answer takes (tests)

import concurrent.futures
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# LICENSE_REGISTRY_API points at another server that answers the same deps.dev
# v3 GetVersion call (a mirror or proxy inside a closed network).
API_BASE = os.environ.get("LICENSE_REGISTRY_API", "https://api.deps.dev/v3").rstrip("/")
API = API_BASE + "/systems/{system}/packages/{name}/versions/{version}"
REQUEST_TIMEOUT = 12
MAX_WORKERS = 8
DEFAULT_BUDGET = 240
SOURCE = "registry (deps.dev)"
NOT_FOUND = "not-found"

SYSTEMS = {
    "npm": "npm",
    "pypi": "pypi",
    "maven": "maven",
    "golang": "go",
    "cargo": "cargo",
    "nuget": "nuget",
    "gem": "rubygems",
}

DEFAULT_VERIFY = (
    "GPL-1.0-only GPL-1.0-or-later GPL-2.0-only GPL-2.0-or-later GPL-3.0-only GPL-3.0-or-later "
    "GPL-1.0 GPL-1.0+ GPL-2.0 GPL-2.0+ GPL-3.0 GPL-3.0+ "
    "AGPL-1.0-only AGPL-1.0-or-later AGPL-3.0-only AGPL-3.0-or-later AGPL-3.0 "
    "SSPL-1.0 BUSL-1.1 CC-BY-NC-4.0 CC-BY-NC-SA-4.0 CC-BY-NC-ND-4.0"
)


def coordinate(purl):
    """(system, name, version) for a purl, or None when it cannot be asked."""
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    if "/" not in body or "@" not in body:
        return None
    ptype, rest = body.split("/", 1)
    system = SYSTEMS.get(ptype.lower())
    if not system:
        return None
    coord, version = rest.rsplit("@", 1)
    version = urllib.parse.unquote(version)
    parts = [urllib.parse.unquote(s) for s in coord.split("/") if s]
    if not parts or not version:
        return None
    if system == "maven":
        if len(parts) < 2:
            return None
        return system, ".".join(parts[:-1]) + ":" + parts[-1], version
    return system, "/".join(parts), version


OTHER = "(licence text or url)"


def licences_of(component):
    """The licences the component carries, in order, and whether any of them
    carries more than an identifier (text, url, a concluded acknowledgement).

    A licence given only as text or a url counts as a licence (OTHER), so a
    component that has one is never treated as having none.
    """
    out, evidence = [], False
    licences = component.get("licenses")
    if not isinstance(licences, list):
        return out, evidence
    for entry in licences:
        if not isinstance(entry, dict):
            continue
        if entry.get("acknowledgement") == "concluded":
            evidence = True
        if entry.get("expression"):
            out.append(str(entry["expression"]).strip())
            continue
        lic = entry.get("license")
        if not isinstance(lic, dict):
            continue
        if lic.get("acknowledgement") == "concluded" or lic.get("text") or lic.get("url"):
            evidence = True
        value = lic.get("id") or lic.get("name")
        if value:
            out.append(str(value).strip())
        elif lic.get("text") or lic.get("url"):
            out.append(OTHER)
    return [v for v in out if v], evidence


def canonical(spdx):
    """Current SPDX id for the deprecated GNU ids, so GPL-2.0+ and
    GPL-2.0-or-later compare equal."""
    m = re.fullmatch(r"((?:A|L)?GPL-(?:1\.0|2\.0|2\.1|3\.0))(\+)?", spdx.strip(), re.IGNORECASE)
    if not m:
        return spdx.strip()
    return m.group(1).upper() + ("-or-later" if m.group(2) else "-only")


def fetch(system, name, version):
    """The registry's licence list, [] when it has none, NOT_FOUND when the
    registry does not know the version, or None on error."""
    fixture_dir = os.environ.get("LICENSE_REGISTRY_FIXTURE_DIR")
    if fixture_dir:
        try:
            time.sleep(float(os.environ.get("LICENSE_REGISTRY_FIXTURE_DELAY", "0")))
        except ValueError:
            pass
        safe = re.sub(r"[/:@]", "_", f"{system}_{name}_{version}")
        path = os.path.join(fixture_dir, f"{safe}.json")
        if not os.path.isfile(path):
            return NOT_FOUND
        try:
            with open(path, encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, ValueError):
            return None
    else:
        url = API.format(
            system=system,
            name=urllib.parse.quote(name, safe=""),
            version=urllib.parse.quote(version, safe=""),
        )
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:  # noqa: S310
                payload = json.load(resp)
        except urllib.error.HTTPError as exc:
            return NOT_FOUND if exc.code == 404 else None
        except (urllib.error.URLError, OSError, ValueError):
            return None
    licences = payload.get("licenses") if isinstance(payload, dict) else None
    if not isinstance(licences, list):
        return []
    return [str(x).strip() for x in licences if str(x).strip()]


def as_expression(licences):
    if len(licences) == 1:
        return licences[0]
    return " AND ".join(f"({x})" if " " in x else x for x in licences)


def set_prop(component, name, value):
    props = component.get("properties")
    props = [p for p in props if isinstance(p, dict) and p.get("name") != name] if isinstance(props, list) else []
    props.append({"name": name, "value": value})
    component["properties"] = props


def walk(components):
    if not isinstance(components, list):
        return
    for c in components:
        if isinstance(c, dict):
            yield c
            yield from walk(c.get("components"))


def main():
    args = [a for a in sys.argv[1:] if a != "--fill-only"]
    fill_only = "--fill-only" in sys.argv[1:]
    if len(args) != 1:
        sys.stderr.write("usage: enrich-license-registry.py [--fill-only] <sbom>\n")
        return 2
    path = args[0]
    verify = {
        canonical(v) for v in re.split(r"[,\s]+", os.environ.get("LICENSE_REGISTRY_VERIFY", DEFAULT_VERIFY).strip()) if v
    }
    try:
        budget = float(os.environ.get("LICENSE_REGISTRY_BUDGET", DEFAULT_BUDGET))
    except ValueError:
        budget = DEFAULT_BUDGET
    try:
        with open(path, encoding="utf-8") as fh:
            bom = json.load(fh)
    except (OSError, ValueError):
        sys.stderr.write("[license-registry] could not read the SBOM\n")
        return 1

    # component -> ("fill" | "verify", coordinate); one question per coordinate.
    work = []
    for comp in walk(bom.get("components")):
        current, evidence = licences_of(comp)
        if not current:
            kind = "fill"
        elif not fill_only and not evidence and len(current) == 1 and canonical(current[0]) in verify:
            kind = "verify"
        else:
            continue
        coord = coordinate(comp.get("purl"))
        if coord is None:
            continue
        work.append((comp, kind, coord))

    coords = list(dict.fromkeys(c for _, _, c in work))
    # The budget bounds the wait for answers, not only the submitting: what has
    # not answered when it runs out is counted as over the budget and left as
    # it was. A request already in flight still ends within REQUEST_TIMEOUT.
    deadline = time.monotonic() + budget
    answers = {}
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)
    futures = {pool.submit(fetch, *coord): coord for coord in coords}
    try:
        for fut in concurrent.futures.as_completed(futures, timeout=max(deadline - time.monotonic(), 0)):
            try:
                answers[futures[fut]] = fut.result()
            except Exception:  # noqa: BLE001 - best effort, never abort a scan
                answers[futures[fut]] = None
    except concurrent.futures.TimeoutError:
        pass
    pool.shutdown(wait=False, cancel_futures=True)
    skipped = {c for c in coords if c not in answers}

    counts = {"candidates": len(work), "filled": 0, "superseded": 0, "confirmed": 0,
              "no_answer": 0, "not_found": 0, "non_standard": 0, "lookup_failed": 0,
              "budget_reached": 0}
    for comp, kind, coord in work:
        if coord in skipped:
            counts["budget_reached"] += 1
            continue
        answer = answers.get(coord)
        if answer is None:
            counts["lookup_failed"] += 1
            continue
        if answer == NOT_FOUND:
            counts["not_found"] += 1
            continue
        if not answer:
            counts["no_answer"] += 1
            continue
        if "non-standard" in answer:
            counts["non_standard"] += 1
            continue
        expression = as_expression(answer)
        if kind == "fill":
            comp["licenses"] = [{"expression": expression}]
            set_prop(comp, "bomlens:licenseSource", SOURCE)
            counts["filled"] += 1
            continue
        recorded = licences_of(comp)[0][0]
        if canonical(recorded) in {canonical(a) for a in answer}:
            counts["confirmed"] += 1
            continue
        comp["licenses"] = [{"expression": expression}]
        set_prop(comp, "bomlens:licenseSource", SOURCE)
        set_prop(comp, "bomlens:license:superseded", recorded)
        counts["superseded"] += 1

    if counts["filled"] or counts["superseded"]:
        tmp = path + ".licreg.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(bom, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
        except OSError:
            sys.stderr.write("[license-registry] could not write the SBOM; left unchanged\n")
            return 1
    sys.stderr.write(
        f"[license-registry] {counts['candidates']} asked: {counts['filled']} filled, "
        f"{counts['superseded']} replaced, {counts['confirmed']} confirmed, "
        f"{counts['no_answer']} without an answer, {counts['not_found']} not found, "
        f"{counts['non_standard']} with a non-SPDX licence, {counts['lookup_failed']} failed, "
        f"{counts['budget_reached']} over the time budget.\n"
    )
    print(json.dumps(counts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
