#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Add the lock file's package hashes to an SBOM read from the lock file.

Usage: static-lock-hashes.py <source-root> <sbom.json>

`trivy fs` lists the packages of a lock file without their hashes. A build
records them, taken from the same lock file, so a static read is filled in
here from the lock files at the root of the tree:

- package-lock.json and npm-shrinkwrap.json: each package's `integrity`
- pnpm-lock.yaml: `resolution: {integrity: ...}` under `packages:`
- bun.lock: the fourth item of each package entry
- gradle/verification-metadata.xml, when the project has one: the checksums
  of each component's jar

An integrity value is an SRI string (`sha512-<base64>`); it is written as a
CycloneDX hash with the algorithm name and a hex digest, the form a build
writes. A component that already has hashes is left as it is. The SBOM is
rewritten only when at least one hash was added. Exits 0 when nothing could be
read, so a lock file in an unexpected shape never fails the scan.
"""
import base64
import binascii
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from urllib.parse import unquote

SRI_ALGS = {"sha512": "SHA-512", "sha384": "SHA-384", "sha256": "SHA-256", "sha1": "SHA-1"}
GRADLE_ALGS = {"sha512": "SHA-512", "sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5"}
DIGEST_BYTES = {"SHA-512": 64, "SHA-384": 48, "SHA-256": 32, "SHA-1": 20, "MD5": 16}
HEX = re.compile(r"^[0-9a-f]+$")


def sri_hashes(value):
    """CycloneDX hashes of an SRI string; it may hold several space-separated values."""
    out = []
    for part in str(value or "").split():
        alg, _, b64 = part.partition("-")
        name = SRI_ALGS.get(alg.lower())
        if not name or not b64:
            continue
        try:
            digest = base64.b64decode(b64.split("?")[0], validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(digest) == DIGEST_BYTES[name] and all(h["alg"] != name for h in out):
            out.append({"alg": name, "content": digest.hex()})
    return out


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def npm_lock(path, table):
    text = read_text(path)
    if text is None:
        return
    try:
        doc = json.loads(text)
    except ValueError:
        return
    if not isinstance(doc, dict):
        return
    packages = doc.get("packages")
    if isinstance(packages, dict):
        for key, entry in packages.items():
            if not key or not isinstance(entry, dict):
                continue
            name = entry.get("name") or key.rsplit("node_modules/", 1)[-1]
            add(table, "npm", name, entry.get("version"), sri_hashes(entry.get("integrity")))
    # lockfileVersion 1 nests packages under "dependencies".
    def walk(deps):
        if not isinstance(deps, dict):
            return
        for name, entry in deps.items():
            if isinstance(entry, dict):
                add(table, "npm", name, entry.get("version"), sri_hashes(entry.get("integrity")))
                walk(entry.get("dependencies"))
    walk(doc.get("dependencies"))


def split_name_version(spec, slash_version=False):
    """'@scope/name@1.2.3' or 'name@1.2.3(peer@x)' -> (name, version).

    With slash_version (pnpm-lock.yaml before 6.0), '/name/1.2.3' and
    '/@scope/name/1.2.3_peer@4.5.6'.
    """
    spec = spec.strip().strip("'\"").lstrip("/")
    spec = spec.split("(", 1)[0]
    if slash_version:
        name, slash, version = spec.rpartition("/")
        if slash and name and version[:1].isdigit():
            return name, version.split("_", 1)[0]
        return None, None
    at = spec.rfind("@")
    if at > 0:
        return spec[:at], spec[at + 1:]
    return None, None


def pnpm_lock(path, table):
    text = read_text(path)
    if text is None:
        return
    section = None
    current = None
    m = re.search(r"^lockfileVersion:\s*['\"]?(\d+)", text, re.M)
    slash_version = bool(m) and int(m.group(1)) < 6
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            section = line.rstrip().rstrip(":")
            current = None
            continue
        if section != "packages":
            continue
        if indent == 2 and line.rstrip().endswith(":"):
            current = split_name_version(line.strip()[:-1], slash_version)
            continue
        if current and current[0] and indent >= 4:
            m = re.search(r"integrity:\s*['\"]?([A-Za-z0-9+/=_-]+-[A-Za-z0-9+/=]+)", line)
            if m:
                add(table, "npm", current[0], current[1], sri_hashes(m.group(1)))


def bun_lock(path, table):
    text = read_text(path)
    if text is None:
        return
    # bun.lock is JSON with trailing commas.
    try:
        doc = json.loads(re.sub(r",(\s*[}\]])", r"\1", text))
    except ValueError:
        return
    packages = doc.get("packages") if isinstance(doc, dict) else None
    if not isinstance(packages, dict):
        return
    for entry in packages.values():
        if not isinstance(entry, list) or not entry or not isinstance(entry[0], str):
            continue
        name, version = split_name_version(entry[0])
        sri = next((x for x in entry[1:] if isinstance(x, str) and re.match(r"^sha(1|256|384|512)-", x)), None)
        if name and sri:
            add(table, "npm", name, version, sri_hashes(sri))


def gradle_verification(path, table):
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return
    for comp in root.iter():
        if not comp.tag.endswith("component"):
            continue
        group, name, version = comp.get("group"), comp.get("name"), comp.get("version")
        if not (group and name and version):
            continue
        artifacts = [a for a in comp if a.tag.endswith("artifact")]
        # Only the main artifact: sources, javadoc and classifier jars have other checksums.
        wanted = ("%s-%s.jar" % (name, version), "%s-%s.aar" % (name, version))
        jar = next((a for a in artifacts if a.get("name") == wanted[0]), None) \
            or next((a for a in artifacts if a.get("name") == wanted[1]), None)
        if jar is None:
            continue
        hashes = []
        for h in jar:
            alg = GRADLE_ALGS.get(h.tag.rsplit("}", 1)[-1].lower())
            value = (h.get("value") or "").lower()
            if alg and HEX.match(value) and len(value) == 2 * DIGEST_BYTES[alg] and all(x["alg"] != alg for x in hashes):
                hashes.append({"alg": alg, "content": value})
        add(table, "maven", "%s/%s" % (group, name), version, hashes)


def add(table, kind, name, version, hashes):
    if isinstance(name, str) and isinstance(version, (str, int, float)) and name and version and hashes:
        table.setdefault((kind, name, str(version)), hashes)


def purl_key(purl):
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    kind, _, rest = body.partition("/")
    path, at, version = rest.rpartition("@")
    if not at:
        return None
    return kind, unquote(path), unquote(version)


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    root, sbom_path = argv[1], argv[2]
    table = {}
    # npm uses npm-shrinkwrap.json when both are there, so it is read first.
    readers = ((npm_lock, "npm-shrinkwrap.json"), (npm_lock, "package-lock.json"),
               (pnpm_lock, "pnpm-lock.yaml"), (bun_lock, "bun.lock"),
               (gradle_verification, os.path.join("gradle", "verification-metadata.xml")))
    for reader, lock in readers:
        try:
            reader(os.path.join(root, lock), table)
        except Exception:  # pylint: disable=broad-except  # one odd lock file must not stop the others
            continue
    if not table:
        return 0
    try:
        with open(sbom_path, encoding="utf-8") as fh:
            sbom = json.load(fh)
    except (OSError, ValueError):
        return 0
    components = sbom.get("components") if isinstance(sbom, dict) else None
    if not isinstance(components, list):
        return 0
    added = 0
    for comp in components:
        if not isinstance(comp, dict) or comp.get("hashes"):
            continue
        hashes = table.get(purl_key(comp.get("purl")))
        if hashes:
            comp["hashes"] = [dict(h) for h in hashes]
            added += 1
    if added:
        tmp = sbom_path + ".hashes.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(sbom, fh, indent=2)
                fh.write("\n")
            os.replace(tmp, sbom_path)
        except OSError:
            try:
                os.remove(tmp)
            except OSError:
                pass
            return 0
    print(added)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
