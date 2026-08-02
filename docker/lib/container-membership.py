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

# Property names. `image` is the membership a reader compares against a vendor
# declaration; `layer` is what makes that membership checkable, since it names the
# directory the files were read out of.
PROP_IMAGE = "bomlens:container:image"
PROP_LAYER = "bomlens:container:layer"
PROP_IMAGE_ID = "bomlens:container:imageId"
PROP_LAYER_COUNT = "bomlens:container:layers"
PROP_EVIDENCE = "bomlens:container:evidence"

SHA256_PREFIX = "sha256:"


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


def membership(data_dir):
    """cache-id -> sorted list of "<image>@<version>" strings."""
    images, driver = images_of(data_dir)
    if not driver:
        return {}, [], None
    by_diff_id = layer_dirs_by_diff_id(pathlib.Path(data_dir) / "image" / driver)
    out = {}
    for image in images:
        label = image["name"] + ("@" + image["version"] if image["version"] else "")
        for diff_id in image["diff_ids"]:
            cache_id = by_diff_id.get(diff_id)
            if cache_id:
                out.setdefault(cache_id, set()).add(label)
    return {k: sorted(v) for k, v in out.items()}, images, driver


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

    by_layer, images, driver = membership(data_dir)
    if not driver:
        # No store here after all: hand the document back untouched rather than
        # dropping the components it holds.
        json.dump(doc, sys.stdout)
        return 0

    # The cache-id sits between the driver directory and `diff` in every path
    # syft recorded. Anchored on both so a component whose own file path happens
    # to contain the driver's name is not read as a layer.
    layer_pattern = re.compile("/" + re.escape(driver) + "/([^/]+)/diff(?:/|$)")

    components = doc.get("components")
    if not isinstance(components, list):
        components = []
    attributed = 0
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

    index_path = str(pathlib.Path("image") / driver / "repositories.json")
    doc["components"] = components + container_components(images, index_path)
    print(f"[firmware] container store: {len(images)} image(s), "
          f"{attributed} component(s) attributed to one.", file=sys.stderr)
    json.dump(doc, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
