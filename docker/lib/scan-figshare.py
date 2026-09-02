#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Describe a Figshare item as a CycloneDX data SBOM.

Usage: scan-figshare.py <reference> <output.json> [project_version]

Research code reaches for its data where the paper put it, and for a great deal
of science that is Figshare rather than a model hub: a DOI, a licence and a pile
of files behind one item number. Nothing in a dependency scan sees any of it,
so the terms of the data a result was produced from stay outside the SBOM while
the code's terms are recorded in full.

Figshare answers this better than a model hub does. The public item endpoint
needs no account, and the fields an SBOM wants are already fields rather than
prose in a card: `license` carries a name and a url, `files[]` carry per-file
MD5 digests, and the DOI identifies the exact version that was read. So the
mapping here is a transcription, not an interpretation:

    item        -> the document's root `data` component
    license     -> component.licenses (SPDX id where the licence is one we can
                   place from its identifier or its url, verbatim name otherwise)
    files[]     -> component.hashes (MD5, capped) + a recorded file count
    doi         -> an external reference and a property, so the exact version
                   read can be cited
    authors[]   -> component.authors, and the first as supplier

`reference` is what a person would paste: an item url, a DOI, an api url, or the
bare item number, with an optional version (`.../33412285/2`, `...figshare.
33412285.v2`). A version that is named is fetched as that version, so a rescan a
year later reads the same bytes rather than whatever the item became.

Nothing is invented. A field the item does not carry is left out, and an item
that cannot be read is an error rather than an empty SBOM -- a dataset silently
described as having no licence would be worse than no dataset at all.
"""
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

API_BASE = "https://api.figshare.com/v2"
TIMEOUT = 30
# Figshare asks clients for no more than one request per second. This makes two
# calls at most (the item, then its files if a version was named), so the rate
# is respected without any pacing of its own.
USER_AGENT = "BomLens (+https://github.com/sktelecom/bomlens)"

# A dataset can hold thousands of files. The digests are evidence that content
# hashes exist and were recorded, not a manifest, so the list is capped and the
# true count is recorded beside it. Same contract as the HuggingFace dataset
# builder in enrich-aibom.sh.
HASH_CAP = 64

# The seven licences the public instance offers, by the name it returns. An
# institutional instance can add its own, which is what the url patterns below
# are for.
LICENSE_BY_NAME = {
    "cc by 4.0": "CC-BY-4.0",
    "cc0": "CC0-1.0",
    "mit": "MIT",
    "gpl 2.0+": "GPL-2.0-or-later",
    "gpl 3.0+": "GPL-3.0-or-later",
    "apache 2.0": "Apache-2.0",
}

# Creative Commons deeds are identified by their url, which is stable across
# instances and carries the exact variant. `nc` and `nd` are the ones that
# decide whether a dataset can be used commercially, so placing them precisely
# is the point of reading the url at all.
CC_URL = re.compile(
    r"creativecommons\.org/(?:licenses/(?P<parts>[a-z-]+)/(?P<ver>[0-9.]+)"
    r"|publicdomain/zero/(?P<zero>[0-9.]+))"
)

# An item number is a run of digits; the forms below are the ways one is written.
REF_PATTERNS = (
    # DOI minted by figshare.com itself, and the institutional form that keeps
    # the item number in the same place: 10.6084/m9.figshare.33413521.v1
    re.compile(r"figshare\.(?P<id>\d+)(?:\.v(?P<version>\d+))?", re.I),
    # api.figshare.com/v2/articles/33412285[/versions/2]
    re.compile(r"/articles/(?P<id>\d+)(?:/versions/(?P<version>\d+))?"),
    # A page url ends with the item number and, when a version is pinned, the
    # version after it: figshare.com/articles/dataset/Title/33412285/2
    re.compile(r"/(?P<id>\d{4,})(?:/(?P<version>\d+))?/?$"),
    # An institutional DOI with no "figshare" in it: 10.25916/sut.33412285.v1
    re.compile(r"\.(?P<id>\d{4,})(?:\.v(?P<version>\d+))?$"),
    # The bare number.
    re.compile(r"^(?P<id>\d+)$"),
)


class FigshareError(Exception):
    """An item that could not be read, with a message meant for the user."""


def parse_reference(reference):
    """(item id, version or None) from a url, DOI, api url or bare number."""
    ref = (reference or "").strip()
    if not ref:
        raise FigshareError("no Figshare item given")
    for pattern in REF_PATTERNS:
        found = pattern.search(ref)
        if found:
            version = found.groupdict().get("version")
            return found.group("id"), version
    raise FigshareError(
        f"could not find an item number in '{reference}'\n"
        "        Give the item url, its DOI, or the number itself, e.g.\n"
        "        https://figshare.com/articles/dataset/Title/33412285"
    )


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        if err.code == 404:
            raise FigshareError(
                f"no public Figshare item at {url}\n"
                "        A private, embargoed or withdrawn item cannot be read "
                "without an account."
            ) from err
        raise FigshareError(f"Figshare returned HTTP {err.code} for {url}") from err
    except (urllib.error.URLError, TimeoutError) as err:
        raise FigshareError(f"could not reach Figshare ({err})") from err
    except ValueError as err:
        raise FigshareError(f"Figshare returned something that is not JSON ({err})") from err


def fetch_item(item_id, version):
    """The item as Figshare holds it, at the version asked for when one was."""
    if version:
        return fetch(f"{API_BASE}/articles/{item_id}/versions/{version}")
    return fetch(f"{API_BASE}/articles/{item_id}")


def spdx_license(license_field):
    """(spdx id or None, name as given, url as given) for the item's licence."""
    if not isinstance(license_field, dict):
        return None, None, None
    name = (license_field.get("name") or "").strip()
    url = (license_field.get("url") or "").strip()

    found = CC_URL.search(url) if url else None
    if found:
        if found.group("zero"):
            return "CC0-1.0", name, url
        parts = found.group("parts").upper()
        return f"CC-{parts}-{found.group('ver')}", name, url

    return LICENSE_BY_NAME.get(name.lower()), name, url


def hashes(files):
    """MD5 digests for the item's files, capped.

    Figshare computes MD5 and nothing stronger, which CycloneDX accepts. A
    weaker digest recorded honestly is worth more than no integrity data: it
    still says the bytes were fixed at the version that was read.
    """
    out = []
    for entry in files:
        if not isinstance(entry, dict):
            continue
        digest = entry.get("computed_md5") or entry.get("supplied_md5")
        if digest:
            out.append({"alg": "MD5", "content": digest})
        if len(out) >= HASH_CAP:
            break
    return out


def component(item, reference):
    """The CycloneDX `data` component for one Figshare item."""
    item_id = item.get("id")
    title = (item.get("title") or "").strip() or f"figshare-{item_id}"
    doi = (item.get("doi") or "").strip()
    page = (item.get("figshare_url") or item.get("url_public_html") or "").strip()
    kind = (item.get("defined_type_name") or "").strip()
    files = [f for f in (item.get("files") or []) if isinstance(f, dict)]

    properties = [
        {"name": "bomlens:dataset:collectedBy", "value": "figshare"},
        {"name": "bomlens:dataset:itemId", "value": str(item_id)},
    ]
    if doi:
        properties.append({"name": "bomlens:dataset:doi", "value": doi})
    if kind:
        # dataset / software / figure / … — what the depositor said this is.
        # Recorded rather than acted on: a Figshare "software" item is still
        # described here as the data component it was fetched as.
        properties.append({"name": "bomlens:dataset:itemType", "value": kind})
    if files:
        properties.append({"name": "bomlens:dataset:fileCount", "value": str(len(files))})
    if item.get("is_embargoed"):
        properties.append({"name": "bomlens:dataset:visibility", "value": "embargoed"})

    external = []
    if page:
        external.append({"type": "distribution", "url": page, "comment": "Figshare item"})
    if doi:
        external.append({"type": "website", "url": f"https://doi.org/{doi}"})

    comp = {
        "type": "data",
        "bom-ref": f"dataset:figshare/{item_id}",
        "name": title,
        "properties": properties,
    }

    version = item.get("version")
    if version is not None:
        comp["version"] = f"v{version}"

    spdx, name, url = spdx_license(item.get("license"))
    if spdx:
        comp["licenses"] = [{"license": {"id": spdx}}]
    elif name:
        # An institutional licence we cannot place stays as the depositor wrote
        # it, with its url. Guessing an SPDX id here would turn "we do not know"
        # into a claim about what is permitted.
        entry = {"name": name}
        if url:
            entry["url"] = url
        comp["licenses"] = [{"license": entry}]

    authors = [a.get("full_name") for a in (item.get("authors") or [])
               if isinstance(a, dict) and a.get("full_name")]
    if authors:
        comp["authors"] = [{"name": a} for a in authors]
        comp["supplier"] = {"name": authors[0]}

    digests = hashes(files)
    if digests:
        comp["hashes"] = digests

    if external:
        comp["externalReferences"] = external

    description = (item.get("description") or "").strip()
    if description:
        # The abstract as deposited, trimmed: it is provenance a reader needs
        # when deciding what the data covers, not a field to carry in full.
        comp["description"] = re.sub(r"<[^>]+>", " ", description)[:600].strip()

    # componentData is where CycloneDX describes what a data component holds.
    contents = {"url": page} if page else {}
    data_entry = {"type": "dataset", "name": title}
    if contents:
        data_entry["contents"] = contents
    if authors:
        data_entry["governance"] = {"owners": [{"organization": {"name": authors[0]}}]}
    comp["data"] = [data_entry]

    comp["properties"].append({"name": "bomlens:dataset:reference", "value": reference})
    return comp


def build(item, reference, project_version):
    root = component(item, reference)
    if project_version:
        root["version"] = project_version
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": root,
        },
        "components": [],
    }


def main():
    if len(sys.argv) < 3:
        print("usage: scan-figshare.py <reference> <output.json> [project_version]",
              file=sys.stderr)
        return 2
    reference, output = sys.argv[1], sys.argv[2]
    project_version = sys.argv[3] if len(sys.argv) > 3 else ""

    try:
        item_id, version = parse_reference(reference)
        print(f"[figshare] reading item {item_id}"
              + (f" version {version}" if version else " (latest version)"))
        item = fetch_item(item_id, version)
        sbom = build(item, reference, project_version)
    except FigshareError as err:
        print(f"[figshare] ERROR: {err}", file=sys.stderr)
        return 1

    try:
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(sbom, fh, indent=2)
    except OSError as err:
        print(f"[figshare] ERROR: could not write {output}: {err}", file=sys.stderr)
        return 1

    root = sbom["metadata"]["component"]
    licenses = root.get("licenses") or []
    shown = (licenses[0]["license"].get("id") or licenses[0]["license"].get("name")
             if licenses else "none declared")
    print(f"[figshare] {root['name']} — license: {shown}, "
          f"files hashed: {len(root.get('hashes') or [])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
