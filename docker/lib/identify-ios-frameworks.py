#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Read the frameworks an iOS app package ships.

Usage: identify-ios-frameworks.py <tree> > components.json

An app package carries no package database, and its binaries are Mach-O, which
the ELF passes cannot read. What it does carry is one bundle per shipped
framework, each with its own `Info.plist` naming it and giving its version. That
is the app's own record of what it ships, the same kind of evidence the Android
pass reads out of META-INF.

Measured on four packages, three public and one from a supplier submission: a
media app ships CocoaLumberjack 3.0.0, an FFmpeg wrapper and a commercial viewer;
three others ship OpenSSL at an exact version. All of those were previously
reported as nothing at all.

Two things the format does not settle, and this pass does not pretend otherwise:

  A framework can be the app's own code, split out rather than brought in. The
  bundle identifier usually says so — an app at `com.x.y` names its own framework
  `com.x.y.Core` — but that string is written by hand and one of the four packages
  measured spells it `com.kdtLiveContainerSwiftUI`, without the separator, so the
  rule quietly misses. Every framework is reported and the ones that look
  app-owned are marked, because a mark a reader can weigh is better than a
  component silently dropped.

  Nothing in the bundle says where the framework came from — CocoaPods, Swift
  Package Manager, or a vendor's zip — so no purl is written. Guessing an
  ecosystem would put a precise-looking identifier on a guess. The name and the
  version are what the package states, and the CPE table downstream recognises
  the names it knows.
"""
import json
import os
import plistlib
import re
import sys

APP_SUFFIX = ".app"
FRAMEWORK_SUFFIX = ".framework"
PLIST = "Info.plist"
# Swift Package Manager names a product's bundle
# `<Name>_<hash>_PackageProduct.framework`. The hash is local to one build, so it
# is not part of the name of anything.
SPM_SUFFIX = re.compile(r"_[0-9A-F]{8,}_PackageProduct$", re.IGNORECASE)
MAX_FRAMEWORKS = int(os.environ.get("FW_IOS_MAX_FRAMEWORKS", "5000"))


def read_plist(path):
    """A property list as a dict, or None. Both the XML and binary forms."""
    try:
        with open(path, "rb") as fh:
            value = plistlib.load(fh)
    except (OSError, ValueError, plistlib.InvalidFileException):
        return None
    return value if isinstance(value, dict) else None


def bundle_name(plist, directory):
    """What to call the framework.

    The directory name is the fallback rather than the answer: a bundle can be
    named one thing and hold another (`CydiaSubstrate.framework` ships ElleKit),
    and an SPM product carries a build hash in its directory name.
    """
    for key in ("CFBundleName", "CFBundleExecutable"):
        value = (plist or {}).get(key)
        if isinstance(value, str) and value.strip():
            # The build hash reaches the bundle's own name as well as its
            # directory, so it is stripped wherever the name is read from.
            return SPM_SUFFIX.sub("", value.strip())
    return SPM_SUFFIX.sub("", directory[:-len(FRAMEWORK_SUFFIX)])


def bundle_version(plist):
    """The version the bundle states, preferring the one meant for people."""
    for key in ("CFBundleShortVersionString", "CFBundleVersion"):
        value = (plist or {}).get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def owning_app(path, apps):
    """The identifier of the app bundle this path sits inside, or None."""
    best = None
    for app_dir, identifier in apps.items():
        if path.startswith(app_dir + os.sep) and (best is None or len(app_dir) > len(best[0])):
            best = (app_dir, identifier)
    return best[1] if best else None


def app_bundles(tree):
    """`<app directory> -> bundle identifier` for every app in the tree."""
    out = {}
    for root, dirs, _files in os.walk(tree):
        for name in dirs:
            if not name.endswith(APP_SUFFIX):
                continue
            path = os.path.join(root, name)
            plist = read_plist(os.path.join(path, PLIST))
            identifier = (plist or {}).get("CFBundleIdentifier")
            if isinstance(identifier, str) and identifier.strip():
                out[path] = identifier.strip()
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    tree = sys.argv[1]

    apps = app_bundles(tree)
    found = {}
    unversioned = 0
    capped = False
    for root, dirs, _files in os.walk(tree):
        for name in dirs:
            if not name.endswith(FRAMEWORK_SUFFIX):
                continue
            if len(found) + unversioned >= MAX_FRAMEWORKS:
                capped = True
                break
            path = os.path.join(root, name)
            plist = read_plist(os.path.join(path, PLIST))
            version = bundle_version(plist)
            if not version:
                # In the package and not named by it: a different answer from the
                # framework not being there, so it is counted and said out loud.
                unversioned += 1
                continue
            component = bundle_name(plist, name)
            identifier = (plist or {}).get("CFBundleIdentifier") or ""
            owner = owning_app(path, apps)
            key = (component, version)
            if key not in found:
                found[key] = {
                    "path": path,
                    "identifier": identifier if isinstance(identifier, str) else "",
                    "app_owned": bool(owner and isinstance(identifier, str)
                                      and identifier.startswith(owner + ".")),
                }
        if capped:
            break

    components = []
    for (name, version) in sorted(found):
        record = found[(name, version)]
        props = [{"name": "bomlens:identifiedBy", "value": "ios-framework-plist"}]
        if record["identifier"]:
            props.append({"name": "bomlens:bundleIdentifier", "value": record["identifier"]})
        if record["app_owned"]:
            # The app's own code, split into a framework rather than brought in.
            # Marked instead of dropped: the rule reads a hand-written string.
            props.append({"name": "bomlens:appOwnedFramework", "value": "true"})
        components.append({
            "bom-ref": f"ios-framework:{name}@{version}",
            "type": "library",
            "name": name,
            "version": version,
            "properties": props,
            "evidence": {"occurrences": [{"location": record["path"]}]},
        })

    print(json.dumps(components, ensure_ascii=False))
    print(f"[ios] {len(components)} framework(s) the package ships.", file=sys.stderr)
    if unversioned:
        print(f"[ios] {unversioned} framework(s) stated no version and were left out.",
              file=sys.stderr)
    if capped:
        print(f"[ios] WARN: stopped at {MAX_FRAMEWORKS} frameworks; "
              f"raise FW_IOS_MAX_FRAMEWORKS to cover the rest.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
