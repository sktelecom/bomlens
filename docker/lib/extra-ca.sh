#!/bin/sh
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# extra-ca.sh - trust an extra CA bundle in this container.
#
# Behind a proxy that inspects TLS (it re-signs HTTPS with its own CA), every
# HTTPS call made in a scan container fails until that CA is trusted.
# BOMLENS_EXTRA_CA_CERTS names a PEM file in the container (the CLI mounts the
# host's SBOM_EXTRA_CA_CERTS read-only at /bomlens-ca/extra.pem). extra_ca_trust
# writes, under /tmp only (the root may be read-only):
#   bundle.pem  the system bundle plus the extra certificates, for
#               SSL_CERT_FILE (OpenSSL, Go, Python, .NET, Ruby, PHP),
#               REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE, CARGO_HTTP_CAINFO,
#               GIT_SSL_CAINFO and PIP_CERT
#   extra.pem   the extra certificates alone, for NODE_EXTRA_CA_CERTS
#   cacerts     a copy of the JDK trust store with them imported, named in
#               JAVA_TOOL_OPTIONS (Maven, Gradle and every other JVM)
# and exports those variables, so the package managers and the tools started
# afterwards inherit them.
#
# Sourced by entrypoint.sh. build-prep.sh runs alone in the cdxgen container,
# so it keeps its own copy of extra_ca_trust; tests/test-postprocess.sh checks
# the copies stay equal. POSIX sh, and safe under set -e: it never fails.

extra_ca_trust() {
    _ec_src="${BOMLENS_EXTRA_CA_CERTS:-}"
    [ -n "$_ec_src" ] || return 0
    # Applied once per container: a scan started inside this one inherits it.
    [ "${BOMLENS_EXTRA_CA_APPLIED:-}" != "$_ec_src" ] || return 0
    if [ ! -f "$_ec_src" ] || [ ! -r "$_ec_src" ]; then
        echo "[WARN] BOMLENS_EXTRA_CA_CERTS=$_ec_src is not a readable file in this container, so no extra CA is trusted. Mount the PEM bundle and point the variable at its path inside the container." >&2
        return 0
    fi
    if ! grep -q -- '-----BEGIN CERTIFICATE-----' "$_ec_src" 2>/dev/null; then
        echo "[WARN] BOMLENS_EXTRA_CA_CERTS=$_ec_src holds no PEM certificate (no -----BEGIN CERTIFICATE----- line), so no extra CA is trusted." >&2
        return 0
    fi
    if ! _ec_dir="$(mktemp -d /tmp/bomlens-ca.XXXXXX 2>/dev/null)"; then
        echo "[WARN] /tmp cannot be written, so the CA bundle in BOMLENS_EXTRA_CA_CERTS is not trusted. Mount a writable /tmp." >&2
        return 0
    fi
    # The certificates only: a private key in the same file is left behind.
    if ! awk '/-----BEGIN CERTIFICATE-----/ { p = 1 } p { print } /-----END CERTIFICATE-----/ { p = 0 }' "$_ec_src" \
            | tr -d '\r' > "$_ec_dir/extra.pem"; then
        echo "[WARN] could not read the certificates in BOMLENS_EXTRA_CA_CERTS=$_ec_src, so no extra CA is trusted." >&2
        return 0
    fi
    _ec_n="$(grep -c -- '-----BEGIN CERTIFICATE-----' "$_ec_dir/extra.pem" 2>/dev/null)" || _ec_n=0
    _ec_sys=""
    for _ec_f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem \
            /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/cert.pem; do
        if [ -s "$_ec_f" ]; then _ec_sys="$_ec_f"; break; fi
    done
    {
        if [ -n "$_ec_sys" ]; then cat "$_ec_sys"; echo; fi
        cat "$_ec_dir/extra.pem"
    } > "$_ec_dir/bundle.pem" 2>/dev/null || true
    if [ -z "$_ec_sys" ]; then
        echo "[WARN] no system CA bundle found in this image: only the certificates in BOMLENS_EXTRA_CA_CERTS are trusted for TLS outside Java and Node.js." >&2
    fi
    SSL_CERT_FILE="$_ec_dir/bundle.pem"
    REQUESTS_CA_BUNDLE="$_ec_dir/bundle.pem"
    CURL_CA_BUNDLE="$_ec_dir/bundle.pem"
    CARGO_HTTP_CAINFO="$_ec_dir/bundle.pem"
    GIT_SSL_CAINFO="$_ec_dir/bundle.pem"
    PIP_CERT="$_ec_dir/bundle.pem"
    export SSL_CERT_FILE REQUESTS_CA_BUNDLE CURL_CA_BUNDLE CARGO_HTTP_CAINFO GIT_SSL_CAINFO PIP_CERT
    # Node.js adds these to its own roots. One the image already names is kept.
    if [ -n "${NODE_EXTRA_CA_CERTS:-}" ] && [ -r "$NODE_EXTRA_CA_CERTS" ]; then
        { cat "$NODE_EXTRA_CA_CERTS"; echo; cat "$_ec_dir/extra.pem"; } > "$_ec_dir/node-extra.pem" 2>/dev/null || true
        NODE_EXTRA_CA_CERTS="$_ec_dir/node-extra.pem"
    else
        NODE_EXTRA_CA_CERTS="$_ec_dir/extra.pem"
    fi
    export NODE_EXTRA_CA_CERTS
    # Java: a copy of the JDK's cacerts (lib/security, or jre/lib/security on
    # Java 8) with each certificate imported, used by every JVM started from
    # here through JAVA_TOOL_OPTIONS. The JDK's own file is left untouched.
    _ec_java=""
    _ec_jh="${JAVA_HOME:-}"
    if [ -z "$_ec_jh" ] && command -v java >/dev/null 2>&1; then
        _ec_jbin="$(readlink -f "$(command -v java)" 2>/dev/null)" || _ec_jbin=""
        [ -z "$_ec_jbin" ] || _ec_jh="$(dirname "$(dirname "$_ec_jbin")")"
    fi
    _ec_cacerts=""
    if [ -n "$_ec_jh" ]; then
        for _ec_f in "$_ec_jh/lib/security/cacerts" "$_ec_jh/jre/lib/security/cacerts"; do
            if [ -f "$_ec_f" ]; then _ec_cacerts="$_ec_f"; break; fi
        done
    fi
    _ec_keytool=""
    if [ -n "$_ec_jh" ] && [ -x "$_ec_jh/bin/keytool" ]; then
        _ec_keytool="$_ec_jh/bin/keytool"
    elif command -v keytool >/dev/null 2>&1; then
        _ec_keytool="$(command -v keytool)"
    fi
    if [ -n "$_ec_cacerts" ] && [ -n "$_ec_keytool" ]; then
        _ec_java="no"
        if cp "$_ec_cacerts" "$_ec_dir/cacerts" 2>/dev/null && chmod 600 "$_ec_dir/cacerts" 2>/dev/null; then
            awk -v d="$_ec_dir" '/-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s/cert-%d.pem", d, n) }
                f != "" { print > f } /-----END CERTIFICATE-----/ { if (f != "") close(f); f = "" }' "$_ec_dir/extra.pem" 2>/dev/null || true
            _ec_i=0; _ec_ok=0
            for _ec_f in "$_ec_dir"/cert-*.pem; do
                [ -f "$_ec_f" ] || continue
                _ec_i=$((_ec_i + 1))
                # The JVM this keytool starts must not read a trust store set
                # by an earlier call, so JAVA_TOOL_OPTIONS is cleared for it.
                if JAVA_TOOL_OPTIONS="" "$_ec_keytool" -importcert -noprompt -trustcacerts \
                        -alias "bomlens-extra-ca-$_ec_i" -file "$_ec_f" \
                        -keystore "$_ec_dir/cacerts" -storepass changeit >/dev/null 2>&1; then
                    _ec_ok=$((_ec_ok + 1))
                fi
                rm -f "$_ec_f"
            done
            if [ "$_ec_ok" -gt 0 ]; then
                JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:+$JAVA_TOOL_OPTIONS }-Djavax.net.ssl.trustStore=$_ec_dir/cacerts -Djavax.net.ssl.trustStorePassword=changeit"
                export JAVA_TOOL_OPTIONS
                _ec_java="yes"
            fi
        fi
        if [ "$_ec_java" != "yes" ]; then
            echo "[WARN] could not import the certificates in BOMLENS_EXTRA_CA_CERTS into a copy of $_ec_cacerts (keytool failed, or its password is not changeit); Java builds do not trust them." >&2
        fi
    fi
    BOMLENS_EXTRA_CA_APPLIED="$_ec_src"
    export BOMLENS_EXTRA_CA_APPLIED
    echo "[INFO] Trusting $_ec_n extra CA certificate(s) from $_ec_src${_ec_java:+ (Java trust store: $_ec_java)}." >&2
    return 0
}
