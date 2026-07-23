#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# enrich-os-context.py — synthesize an operating-system component from distro
# package PURLs so the vulnerability scanner can match rpm/deb CVEs.
#
# Usage: enrich-os-context.py <sbom.json>   (CycloneDX JSON, edited in place)
#
# Why: a supplier SBOM can list every OS package (pkg:rpm/centos/...,
# pkg:deb/ubuntu/...) yet omit an `operating-system` component. Trivy needs that
# OS component to know which distro advisory database to match against; without
# it, an SBOM full of rpm/deb packages returns ZERO findings even though the PURLs
# are perfectly formed. Adding one OS component recovers them — measured on real
# supplier SBOMs, a CentOS-package SBOM went from 0 to tens of thousands of
# findings once the OS component was present.
#
# What it does: infer (distro, major version) from the dominant rpm PURL's
# namespace (centos/rocky/redhat/...) and its `.elN` release suffix or a
# `distro=` qualifier, then append a single `operating-system` component. If the
# SBOM already carries one, only normalize its version to the major for RHEL-like
# distros (Trivy matches rpm distros by MAJOR version, so a syft-supplied
# "rocky 8.10" matches nothing and is corrected to "8").
#
# Accuracy first: only rpm namespaces we can name a Trivy distro for are voted on;
# an unrecognized namespace or a deb-only SBOM is left untouched (deb is recovered
# by the OSV engine, not by an OS component). Best-effort: any failure leaves the
# SBOM unchanged and never aborts the scan. Idempotent: re-running is a no-op once
# the OS component exists and its version is already normalized.
#
# Toggle: ENRICH_OS_CONTEXT (default on); the entrypoint skips it for AI SBOMs.
import json
import re
import sys

# rpm PURL namespace -> the OS `name` Trivy matches on. Only namespaces we can map
# to a distro Trivy actually carries are listed; anything else is not voted on.
NS_TO_OS = {
    "centos": "centos",
    "rocky": "rocky",
    "rhel": "redhat",
    "redhat": "redhat",
    "almalinux": "alma",
    "alma": "alma",
    "amazon": "amazon",
    "amzn": "amazon",
    "fedora": "fedora",
}

# Distros Trivy matches by MAJOR version only; a minor-carrying version ("8.10")
# matches nothing and must be reduced to the major ("8").
RHEL_LIKE = {"centos", "rocky", "redhat", "alma", "fedora", "amazon"}


def _rpm_ns(purl):
    """pkg:rpm/<ns>/name@ver -> <ns> (lowercased), or None if not an rpm PURL."""
    if not purl or not purl.startswith("pkg:rpm/"):
        return None
    return purl[len("pkg:rpm/"):].split("/", 1)[0].split("@", 1)[0].lower()


def infer_os(purls):
    """Vote a dominant (os_name, major_version) from rpm PURLs. None if none map."""
    votes = {}
    for p in purls:
        ns = _rpm_ns(p)
        os_name = NS_TO_OS.get(ns) if ns else None
        if not os_name:
            continue
        # A `distro=<name>-<major>[.minor]` qualifier is authoritative; take the
        # major only (Trivy matches rpm distros by major version).
        mq = re.search(r"distro=([a-z]+)-([0-9]+)", p)
        if mq:
            key = (NS_TO_OS.get(mq.group(1), mq.group(1)), mq.group(2))
            votes[key] = votes.get(key, 0) + 1
            continue
        # Otherwise the `.elN` release suffix carries the major version.
        me = re.search(r"\.el(\d+)", p)
        if me:
            key = (os_name, me.group(1))
            votes[key] = votes.get(key, 0) + 1
    if not votes:
        return None
    (os_name, version), n = max(votes.items(), key=lambda kv: kv[1])
    return {"name": os_name, "version": version, "votes": n,
            "total": sum(votes.values())}


def enrich(path):
    try:
        with open(path) as f:
            doc = json.load(f)
    except (OSError, ValueError) as exc:
        print(f"[os-context] WARN: could not read SBOM ({exc}); skipping", file=sys.stderr)
        return
    if doc.get("bomFormat") != "CycloneDX":
        return  # pipeline is CycloneDX here; anything else is left untouched

    components = doc.get("components")
    if not isinstance(components, list):
        return

    purls = [c.get("purl") for c in components if c.get("purl")]
    existing = [c for c in components if c.get("type") == "operating-system"]

    if existing:
        # Do not add a second OS; only fix a minor-carrying version on RHEL-like
        # distros so Trivy can match (e.g. "rocky 8.10" -> "8").
        fixed = 0
        for c in existing:
            name = str(c.get("name", "")).lower()
            ver = str(c.get("version", ""))
            if name in RHEL_LIKE and "." in ver:
                c["version"] = ver.split(".", 1)[0]
                fixed += 1
        if fixed:
            _write(path, doc)
            print(f"[os-context] normalized {fixed} existing OS component version(s) "
                  f"to major for distro matching.")
        return

    os_info = infer_os(purls)
    if not os_info:
        return  # no recognizable distro packages (e.g. deb-only or non-OS SBOM)

    components.append({
        "type": "operating-system",
        "name": os_info["name"],
        "version": os_info["version"],
        "bom-ref": "bomlens-os-context",
    })
    _write(path, doc)
    print(f"[os-context] synthesized operating-system component "
          f"{os_info['name']} {os_info['version']} "
          f"({os_info['votes']}/{os_info['total']} distro packages) for CVE matching.")


def _write(path, doc):
    with open(path, "w") as f:
        json.dump(doc, f, ensure_ascii=False)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: enrich-os-context.py <sbom.json>", file=sys.stderr)
        sys.exit(2)
    enrich(sys.argv[1])
