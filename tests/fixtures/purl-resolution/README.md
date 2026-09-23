# purl-resolution fixtures

One file per coordinate `docker/lib/resolve-purl.py` is allowed to find, named
`<system>_<name>.json` with `/`, `@` and `:` replaced by `_` and `%40`. A
coordinate with no file here reads as "not found in the repository", which is
how the offline tests exercise the missing case without the network.
