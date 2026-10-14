#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# cdx-copy-as-1.6.sh: write a CycloneDX 1.6 copy of a CycloneDX 1.7 document,
# for a consumer that cannot read 1.7 (entrypoint.sh's Dependency-Track upload).
# The delivered SBOM is never changed; only the copy is.
#
# Usage: cdx-copy-as-1.6.sh <in.json> <out.json>
#
# Besides specVersion and $schema, the copy is made valid against the 1.6
# schema:
#   - A licenses array that mixes license and expression entries, or holds more
#     than one expression (1.6 allows a list of licenses or exactly one
#     expression), becomes one expression that joins every entry with AND when
#     each license entry has an SPDX id. Otherwise the license entries stay and
#     each expression becomes a license entry named after it. An expression
#     entry loses the fields 1.7 added to it (expressionDetails, licensing,
#     properties).
#   - Fields that 1.7 added are removed: the root citations, definitions.patents,
#     metadata.distributionConstraints, isExternal, versionRange and
#     patentAssertions on components and services, properties on an external
#     reference, and the cryptoProperties fields 1.6 does not define.
#   - Values 1.6 does not know are removed or mapped: external references of
#     type citation, patent, patent-assertion and patent-family, Streebog
#     hashes, IKEv2 transform entries written as objects, and the crypto
#     primitive key-wrap and the newer protocol types (both become "other").
set -e

IN="$1"
OUT="$2"
if [ -z "$IN" ] || [ -z "$OUT" ]; then
    echo "usage: cdx-copy-as-1.6.sh <in.json> <out.json>" >&2
    exit 2
fi

jq '
  def lic16:
    if type != "array" then .
    else
      [ .[] | select(type == "object" and has("expression")) ] as $ex
      | [ .[] | select(type == "object" and has("license")) ] as $li
      | if ($ex | length) == 0 then .
        elif ($ex | length) == 1 and ($li | length) == 0 then
          [ $ex[0] | with_entries(select(.key == "expression" or .key == "acknowledgement" or .key == "bom-ref")) ]
        elif all($li[]; (.license.id // "") != "") then
          [ { expression: (
              [ ($ex[] | .expression), ($li[] | .license.id) ]
              | reduce .[] as $e ([]; if index([$e]) then . else . + [$e] end)
              | map(if test(" ") then "(" + . + ")" else . end)
              | join(" AND ")) } ]
        else $li + [ $ex[] | { license: { name: .expression } } ]
        end
    end;
  def keep($keys): with_entries(select(.key as $k | $keys | index($k)));
  def crypto16:
    (if (.algorithmProperties | type) == "object" then
       .algorithmProperties |= (keep(["primitive","parameterSetIdentifier","curve","executionEnvironment","implementationPlatform","certificationLevel","mode","padding","cryptoFunctions","classicalSecurityLevel","nistQuantumSecurityLevel"])
         | if .primitive == "key-wrap" then .primitive = "other" else . end)
     else . end)
    | (if (.certificateProperties | type) == "object" then
         .certificateProperties |= keep(["subjectName","issuerName","notValidBefore","notValidAfter","signatureAlgorithmRef","subjectPublicKeyRef","certificateFormat","certificateExtension"])
       else . end)
    | (if (.relatedCryptoMaterialProperties | type) == "object" then
         .relatedCryptoMaterialProperties |= keep(["type","id","state","algorithmRef","creationDate","activationDate","updateDate","expirationDate","value","size","format","securedBy"])
       else . end)
    | (if (.protocolProperties | type) == "object" then
         .protocolProperties |= (keep(["type","version","cipherSuites","ikev2TransformTypes","cryptoRefArray"])
           | (if (.type | type) == "string" and ([.type] | inside(["tls","ssh","ipsec","ike","sstp","wpa","other","unknown"]) | not)
              then .type = "other" else . end)
           | (if (.cipherSuites | type) == "array" then .cipherSuites |= map(if type == "object" then keep(["name","algorithms","identifiers"]) else . end) else . end)
           | (if (.ikev2TransformTypes | type) == "object" then
                .ikev2TransformTypes |= with_entries(if (.value | type) == "array" then .value |= map(select(type != "object")) else . end)
              else . end))
       else . end);
  .specVersion = "1.6"
  | (if has("$schema") then ."$schema" = "http://cyclonedx.org/schema/bom-1.6.schema.json" else . end)
  | del(.citations, .definitions.patents, .metadata.distributionConstraints)
  | (if (.definitions | type) == "object" and (.definitions | length) == 0 then del(.definitions) else . end)
  | walk(
      if type == "object" then
        del(.isExternal, .versionRange, .patentAssertions)
        | (if (.licenses | type) == "array" then .licenses |= lic16 else . end)
        | (if (.externalReferences | type) == "array" then
             .externalReferences |= map(
               if type == "object" then
                 select((.type // "") as $t | ["citation","patent","patent-assertion","patent-family"] | index($t) | not)
                 | del(.properties)
               else . end)
           else . end)
        | (if (.hashes | type) == "array" then
             .hashes |= map(select(type != "object" or ((.alg // "") | startswith("Streebog") | not)))
           else . end)
        | (if (.cryptoProperties | type) == "object" then .cryptoProperties |= crypto16 else . end)
      else . end)
' "$IN" > "$OUT"
