#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Say which container image each component of a container store came from.

Usage: container-membership.py <docker-data-dir> <store.cdx.json> > out.cdx.json

The scan already reads the container image store a firmware carries beside its
rootfs, so its packages reach the SBOM. What the SBOM does not say is which
container each one belongs to, and on a switch OS that is most of what a reader
needs: `libssl` present somewhere in the image is a different fact from `libssl`
present in the routing daemon's container, and the vendor's own declaration
records exactly that, one scope per component.

Every fact needed is already in the store, so nothing here is inferred:

  image/<driver>/repositories.json   the images the store holds, by name and tag
  image/<driver>/imagedb/content/    each image's config, whose rootfs.diff_ids
                                     lists the layers it is built from
  image/<driver>/layerdb/sha256/     per layer, `diff` (its diff_id) and
                                     `cache-id` (its directory under <driver>/)

The indirection through layerdb is the part that is easy to get wrong: an image
config names its layers by diff_id, the digest of the layer's uncompressed
contents, while the directory the files actually sit in is named by cache-id,
which is local to this machine's store. The two are unrelated strings and only
layerdb joins them.

A component's layer comes from where syft read it. syft records that as
`syft:location:<n>:path`, relative to the directory it was pointed at, so a
component read out of a layer carries `/<driver>/<cache-id>/diff/...` — the
cache-id is in the path. A component can carry several locations, and a package
in a shared base layer belongs to every image built on it, so both properties
are emitted once per distinct value rather than joined into one string.

Components read out of a store also get the purl syft could not write. syft only
gives a deb package a purl when it knows which distribution the package came
from, and it looks for that in `/etc/os-release` relative to what it was pointed
at. A store holds each image's files under `<driver>/<cache-id>/diff/`, so the
scan points syft at a directory whose root has no os-release and every deb read
out of it arrives with a name, a version and no purl. Nothing downstream matches
CVEs against those: the vulnerability step keys on the purl. The distribution is
in the store all the same — in the base layer of the image the package belongs
to — so it is read from there and the purl is written in syft's own format, which
is what the stage after this one reads to fill in the rest of what the
vulnerability step needs. Measured on one switch OS: 192 packages arrived with no
purl; identified this way they bring 1,000 advisories the scan did not report
before, and 30 packages go from none to some.

The images themselves are emitted as `container` components. A container image is
distributed under its own name and version and carries its own notice
obligations, which is the same reason the distro is emitted as an
`operating-system` component. The version is the tag that is not `latest`: a
store tags each image twice, once with the build's real version and once as
`latest`, and only the former is worth putting in a purl.

Nothing here fails the scan. A store that has been partially extracted, or whose
layout differs from the one above, yields fewer memberships and no error; the
components still reach the SBOM without them, which is what they did before.
"""
import json
import pathlib
import re
import sys
import urllib.parse

# Property names. `image` is the membership a reader compares against a vendor
# declaration; `layer` is what makes that membership checkable, since it names the
# directory the files were read out of.
PROP_IMAGE = "bomlens:container:image"
PROP_LAYER = "bomlens:container:layer"
PROP_IMAGE_ID = "bomlens:container:imageId"
PROP_LAYER_COUNT = "bomlens:container:layers"
PROP_EVIDENCE = "bomlens:container:evidence"
# A purl this script wrote rather than one syft read, so a reader can tell the
# two apart and the claim can be checked against the layer it came from.
PROP_PURL_SOURCE = "bomlens:purlSource"
PURL_SOURCE = "container-store-distro"

SHA256_PREFIX = "sha256:"

# Where a distribution records what it is. `/etc/os-release` is the file to read;
# `/usr/lib/os-release` is where the standard says it may live instead.
OS_RELEASE_FILES = ("etc/os-release", "usr/lib/os-release")


def read_json(path):
    """Parse a JSON file, or return None. Absent and malformed are the same
    answer here: the membership cannot be established and the scan goes on."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def find_store(data_dir):
    """The storage driver whose image index this store carries, or None.

    Chosen by the index file rather than by trying driver names in a fixed order,
    for the same reason the scan finds the store by that file: a store built by
    any driver is recognised, and a directory that merely looks like one is not.
    """
    for index in sorted(pathlib.Path(data_dir).glob("image/*/repositories.json")):
        if index.is_file():
            return index.parent.name
    return None


def layer_dirs_by_diff_id(image_root):
    """diff_id -> cache-id, read out of layerdb."""
    out = {}
    for entry in sorted((image_root / "layerdb" / "sha256").glob("*")):
        try:
            diff_id = (entry / "diff").read_text(encoding="utf-8").strip()
            cache_id = (entry / "cache-id").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if diff_id and cache_id:
            out[diff_id] = cache_id
    return out


def pick_version(tags):
    """The tag worth calling the version.

    A store tags each image twice — with the build's version and as `latest` — so
    prefer whichever is not `latest`. If `latest` is all there is, say `latest`
    rather than inventing something.
    """
    named = [t for t in tags if not t.endswith(":latest")]
    tag = (sorted(named) or sorted(tags) or [""])[0]
    return tag.rsplit(":", 1)[1] if ":" in tag else ""


def images_of(data_dir):
    """[{name, version, id, diff_ids}] for every image the store holds."""
    driver = find_store(data_dir)
    if not driver:
        return [], None
    image_root = pathlib.Path(data_dir) / "image" / driver
    index = read_json(image_root / "repositories.json") or {}
    out = []
    for name, tags in sorted((index.get("Repositories") or {}).items()):
        if not isinstance(tags, dict) or not tags:
            continue
        # One repository name can hold more than one image, so group its tags by
        # the image each points at and emit one component per image. Collapsing a
        # repository to a single component would report one version and hide the
        # other, and the layers of the hidden one would be attributed to it.
        by_id = {}
        for tag, image_id in sorted(tags.items()):
            if isinstance(image_id, str) and image_id.startswith(SHA256_PREFIX):
                by_id.setdefault(image_id, []).append(tag)
        for image_id, id_tags in sorted(by_id.items()):
            config = read_json(image_root / "imagedb" / "content" / "sha256"
                               / image_id[len(SHA256_PREFIX):]) or {}
            diff_ids = ((config.get("rootfs") or {}).get("diff_ids") or [])
            out.append({"name": name, "version": pick_version(id_tags),
                        "id": image_id,
                        "diff_ids": [d for d in diff_ids if isinstance(d, str)]})
    return out, driver


def image_label(image):
    """How an image is named in the membership property."""
    return image["name"] + ("@" + image["version"] if image["version"] else "")


def membership(data_dir):
    """cache-id -> sorted list of "<image>@<version>" strings."""
    images, driver = images_of(data_dir)
    if not driver:
        return {}, [], None, {}
    by_diff_id = layer_dirs_by_diff_id(pathlib.Path(data_dir) / "image" / driver)
    out = {}
    for image in images:
        label = image_label(image)
        for diff_id in image["diff_ids"]:
            cache_id = by_diff_id.get(diff_id)
            if cache_id:
                out.setdefault(cache_id, set()).add(label)
    return {k: sorted(v) for k, v in out.items()}, images, driver, by_diff_id


def read_os_release(path):
    """`(ID, VERSION_ID)` out of an os-release file, or None.

    VERSION_ID is optional — a rolling distribution leaves it out — and an ID is
    the one field this cannot do without, so a file that has no ID is treated as
    no answer at all.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    found = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        key = key.strip()
        if sep and key in ("ID", "VERSION_ID"):
            found[key] = value.strip().strip('"').strip("'")
    return (found["ID"], found.get("VERSION_ID", "")) if found.get("ID") else None


def distro_by_image(data_dir, driver, images, by_diff_id):
    """"<image>@<version>" -> (ID, VERSION_ID) for images that say what they are.

    The layers are walked base first, so a layer that replaces the file wins over
    the one below it, the same way the running container would see it. An image
    whose layers carry no os-release is left out rather than being given the
    distribution of some other image in the store.
    """
    root = pathlib.Path(data_dir) / driver
    by_cache_id = {}

    def of_layer(cache_id):
        if cache_id not in by_cache_id:
            found = None
            for name in OS_RELEASE_FILES:
                found = read_os_release(root / cache_id / "diff" / name)
                if found:
                    break
            by_cache_id[cache_id] = found
        return by_cache_id[cache_id]

    out = {}
    for image in images:
        release = None
        for diff_id in image["diff_ids"]:
            cache_id = by_diff_id.get(diff_id)
            if cache_id:
                release = of_layer(cache_id) or release
        if release:
            out[image_label(image)] = release
    return out


def deb_purl(name, version, release, source, source_version):
    """The purl syft writes for a deb once it knows the distribution.

    syft's format is followed rather than approximated, because the purl is read
    on the way to the vulnerability step: the normalize stage takes the source
    package out of the `upstream` qualifier to fill in what Trivy needs to match
    a distribution advisory, which is keyed on the source name (`libssl3` is
    fixed by an `openssl` advisory) and not on the binary one. The architecture
    syft also records is not in the SBOM it wrote, so that qualifier is left out
    rather than guessed; it takes no part in matching.
    """
    ident, version_id = release
    quote = urllib.parse.quote
    distro = ident + ("-" + version_id if version_id else "")
    purl = "pkg:deb/{}/{}@{}?distro={}".format(
        quote(ident, safe=""), quote(name, safe=""),
        quote(version, safe=""), quote(distro, safe=""))
    if source:
        upstream = source + ("@" + source_version if source_version else "")
        purl += "&upstream=" + quote(upstream, safe="")
    return purl


def props(component):
    values = component.get("properties")
    if not isinstance(values, list):
        values = []
        component["properties"] = values
    return values


def add_prop(component, name, value):
    """Append a property unless the same name and value is already there."""
    values = props(component)
    if not any(p.get("name") == name and p.get("value") == value for p in values):
        values.append({"name": name, "value": value})


def layer_ids_of(component, layer_pattern):
    """The store layers this component was read out of, in the order syft
    recorded them."""
    seen = []
    for prop in component.get("properties") or []:
        if not str(prop.get("name", "")).startswith("syft:location:"):
            continue
        if not str(prop.get("name", "")).endswith(":path"):
            continue
        found = layer_pattern.search(str(prop.get("value", "")))
        if found and found.group(1) not in seen:
            seen.append(found.group(1))
    return seen


def prop_value(component, name):
    for prop in component.get("properties") or []:
        if prop.get("name") == name:
            return str(prop.get("value", ""))
    return ""


def write_deb_purl(component, labels, by_image):
    """Give a deb read out of a layer the purl its distribution decides.

    Only a package syft itself called a deb is touched, and only one that arrived
    without a purl, so this adds an identifier where there was none and never
    replaces one syft wrote. A package that sits in images running different
    distributions is left alone: the store says it is in both and nothing there
    says which build of it this is.
    """
    if component.get("purl") or prop_value(component, "syft:package:type") != "deb":
        return False
    name, version = component.get("name"), component.get("version")
    if not name or not version:
        return False
    releases = {by_image[label] for label in labels if label in by_image}
    if len(releases) != 1:
        return False
    component["purl"] = deb_purl(
        name, version, releases.pop(),
        prop_value(component, "syft:metadata:source"),
        prop_value(component, "syft:metadata:sourceVersion"))
    add_prop(component, PROP_PURL_SOURCE, PURL_SOURCE)
    return True


def container_components(images, index_path):
    out = []
    for image in images:
        purl = "pkg:oci/" + image["name"]
        if image["version"]:
            purl += "@" + image["version"]
        component = {
            "type": "container",
            "name": image["name"],
            "purl": purl,
            "properties": [
                {"name": PROP_IMAGE_ID, "value": image["id"]},
                {"name": PROP_LAYER_COUNT, "value": str(len(image["diff_ids"]))},
                {"name": PROP_EVIDENCE, "value": index_path},
            ],
        }
        # A store with no usable tag leaves the version out rather than carrying an
        # empty one. The conformance check measures name-and-version coverage as a
        # required row, so an absent version is reported instead of being papered
        # over by a field that is present and says nothing.
        if image["version"]:
            component["version"] = image["version"]
        out.append(component)
    return out


def main():
    if len(sys.argv) < 3:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    data_dir, sbom_path = sys.argv[1], sys.argv[2]

    doc = read_json(sbom_path)
    if not isinstance(doc, dict):
        print("{}", end="")
        return 0

    by_layer, images, driver, by_diff_id = membership(data_dir)
    if not driver:
        # No store here after all: hand the document back untouched rather than
        # dropping the components it holds.
        json.dump(doc, sys.stdout)
        return 0

    # The cache-id sits between the driver directory and `diff` in every path
    # syft recorded. Anchored on both so a component whose own file path happens
    # to contain the driver's name is not read as a layer.
    layer_pattern = re.compile("/" + re.escape(driver) + "/([^/]+)/diff(?:/|$)")

    by_image = distro_by_image(data_dir, driver, images, by_diff_id)

    components = doc.get("components")
    if not isinstance(components, list):
        components = []
    attributed = 0
    identified = 0
    for component in components:
        if not isinstance(component, dict):
            continue
        layers = layer_ids_of(component, layer_pattern)
        if not layers:
            continue
        for layer in layers:
            add_prop(component, PROP_LAYER, layer)
        labels = sorted({label for layer in layers for label in by_layer.get(layer, [])})
        for label in labels:
            add_prop(component, PROP_IMAGE, label)
        if labels:
            attributed += 1
        if write_deb_purl(component, labels, by_image):
            identified += 1

    index_path = str(pathlib.Path("image") / driver / "repositories.json")
    doc["components"] = components + container_components(images, index_path)
    print(f"[firmware] container store: {len(images)} image(s), "
          f"{attributed} component(s) attributed to one, "
          f"{identified} given a purl from the image's distribution.",
          file=sys.stderr)
    json.dump(doc, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
