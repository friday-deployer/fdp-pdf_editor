#!/usr/bin/env bash
# Generate or validate the Folioxide test PKI (test-only keys, never use them for anything real).
#
# Usage:
#   bash tools/gen-pki.sh [--dir DIR]           regenerate every file, then run the checks
#   bash tools/gen-pki.sh --check [--dir DIR]   validate the committed files (no regeneration)
#   bash tools/gen-pki.sh --derive [--dir DIR]  rewrite only the derived key files, then check
#   bash tools/gen-pki.sh --tsa-variants [--dir DIR]
#                                               issue only the TSA certificate variants, then check
#
# DIR defaults to fixtures/pki. Keys are random, so regeneration never reproduces the committed
# bytes; that is why --check validates properties instead of comparing output. Requires OpenSSL 3.x
# (the RC2-40 PKCS#12 needs the legacy provider). OpenSSL 3.0 has no `x509 -not_before`, so all
# certificates are issued with `openssl ca -startdate/-enddate`.
#
# Contract (docs/milestones/M0.md, "Test PKI"); the password of every encrypted key and .p12 is
# "folioxide":
#   root.pem / root.key.pem                  self-signed root CA, RSA-3072, sha256WithRSAEncryption
#   intermediate.pem / intermediate.key.pem  CA issued by the root, P-384, pathlen 0
#   signer-{rsa2048,rsa3072,p256,p384}.pem   end-entity signers issued by the intermediate
#                                            (ecdsa-with-SHA384), keyUsage digitalSignature +
#                                            nonRepudiation (critical)
#     .key.pem                               unencrypted PKCS#8 key
#     .key.enc.pem                           encrypted PKCS#8 key (PBES2, AES-256-CBC, PBKDF2-SHA256)
#   tsa.pem / tsa.key.pem                    TSA issued by the root, RSA-2048, EKU timeStamping (critical)
#   tsa-root.pem                             byte-identical copy of root.pem (a copy, not a symlink,
#                                            so Windows checkouts work)
#   expired.pem / expired.key.pem            signer whose validity (2025-01-01..2025-12-31) is past
#   wrong-ku.pem / wrong-ku.key.pem          signer with keyUsage keyEncipherment + dataEncipherment
#   signer-rsa2048-modern.p12                OpenSSL 3 defaults: PBES2/PBKDF2/AES-256-CBC, SHA-256 MAC
#   signer-rsa2048-3des.p12                  PBE-SHA1-3DES for key and certs, SHA-1 MAC
#   signer-rsa2048-rc2-40.p12                -legacy: certs RC2-40 (PBE-SHA1-RC2-40), key 3DES, SHA-1 MAC
#   signer-p256-modern.p12                   OpenSSL 3 defaults
#   signer-{rsa2048,rsa3072}.key.pkcs1.pem   derived: the same RSA keys as PKCS#1 (BEGIN RSA PRIVATE KEY)
#   signer-{p256,p384}.key.sec1.pem          derived: the same EC keys as SEC1 (BEGIN EC PRIVATE KEY)
#   tsa-{eku-noncritical,no-eku,eku-extra,ku-keyenc,not-yet-valid}.pem
#                                            TSA certificate variants (M4 brief D-21): issued by the
#                                            root for the existing tsa.key.pem, each breaking one
#                                            rule of RFC 3161 §2.3 / OpenSSL's timestamping purpose
#                                            (non-critical EKU, no EKU, EKU timeStamping + codeSigning,
#                                            KU digitalSignature + keyEncipherment, valid only from
#                                            2070); --tsa-variants adds them without touching any
#                                            other file
# Every .p12 holds the signer key and certificate plus the intermediate and root certificates.
# The derived files are a deterministic function of the committed keys (M3 brief §2, WP3.1B), so
# --derive can add them without regenerating, and --check verifies they are up to date.
# Non-expired certificates are valid from 2025-01-01 to 2075-12-31.
set -euo pipefail

PASS="folioxide"
NOT_BEFORE="20250101000000Z"
NOT_AFTER="20751231235959Z"
EXPIRED_NOT_AFTER="20251231235959Z"
# The TSA variant that is not yet valid (M4 brief D-21) is valid from 2070 only.
TSA_NOT_YET_VALID_FROM="20700101000000Z"
TSA_VARIANTS=(tsa-eku-noncritical tsa-no-eku tsa-eku-extra tsa-ku-keyenc tsa-not-yet-valid)
# 2075-01-01T00:00:00Z as a Unix timestamp: long-lived certificates must not expire before it.
LONG_VALIDITY_EPOCH=3313526400
DN_PREFIX="/O=Folioxide Test PKI/OU=TEST ONLY - DO NOT TRUST"
SIGNERS=(signer-rsa2048 signer-rsa3072 signer-p256 signer-p384)
RSA_SIGNERS=(signer-rsa2048 signer-rsa3072)
EC_SIGNERS=(signer-p256 signer-p384)

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pki_dir="$repo_root/fixtures/pki"
mode="generate"

usage() {
    sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --check) mode="check" ;;
        --derive) mode="derive" ;;
        --tsa-variants) mode="tsa-variants" ;;
        --dir)
            [ $# -ge 2 ] || { usage >&2; exit 2; }
            pki_dir="$2"
            shift
            ;;
        -h | --help) usage; exit 0 ;;
        *) echo "gen-pki: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

if ! command -v openssl >/dev/null 2>&1; then
    echo "gen-pki: openssl not found" >&2
    exit 2
fi
case "$(openssl version)" in
    "OpenSSL 3."*) ;;
    *) echo "gen-pki: OpenSSL 3.x is required, found: $(openssl version)" >&2; exit 2 ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# ---------------------------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------------------------

write_ca_config() {
    mkdir -p "$work/ca/newcerts"
    : > "$work/ca/index.txt"
    cat > "$work/ca/ca.cnf" <<EOF
[ ca ]
default_ca = fx_ca

[ fx_ca ]
database        = $work/ca/index.txt
new_certs_dir   = $work/ca/newcerts
serial          = $work/ca/serial
default_md      = sha256
policy          = fx_policy
unique_subject  = no
copy_extensions = none
email_in_dn     = no

[ fx_policy ]
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied

[ req ]
distinguished_name = req_dn

[ req_dn ]

[ ext_root ]
basicConstraints     = critical, CA:TRUE
keyUsage             = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[ ext_intermediate ]
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

[ ext_signer ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, nonRepudiation
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

[ ext_tsa ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, nonRepudiation
extendedKeyUsage       = critical, timeStamping
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

[ ext_wrong_ku ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, keyEncipherment, dataEncipherment
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

[ ext_tsa_eku_noncritical ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, nonRepudiation
extendedKeyUsage       = timeStamping
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

[ ext_tsa_no_eku ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, nonRepudiation
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

[ ext_tsa_eku_extra ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, nonRepudiation
extendedKeyUsage       = critical, timeStamping, codeSigning
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

[ ext_tsa_ku_keyenc ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = critical, timeStamping
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
EOF
}

# tsa_variant_spec <name>: "<extension section>|<CN>|<notBefore>"
tsa_variant_spec() {
    case "$1" in
        tsa-eku-noncritical) echo "ext_tsa_eku_noncritical|Folioxide Test TSA (non-critical EKU)|$NOT_BEFORE" ;;
        tsa-no-eku) echo "ext_tsa_no_eku|Folioxide Test TSA (no EKU)|$NOT_BEFORE" ;;
        tsa-eku-extra) echo "ext_tsa_eku_extra|Folioxide Test TSA (EKU timeStamping and codeSigning)|$NOT_BEFORE" ;;
        tsa-ku-keyenc) echo "ext_tsa_ku_keyenc|Folioxide Test TSA (KU keyEncipherment)|$NOT_BEFORE" ;;
        tsa-not-yet-valid) echo "ext_tsa|Folioxide Test TSA (not yet valid)|$TSA_NOT_YET_VALID_FROM" ;;
        *) echo "gen-pki: unknown TSA variant $1" >&2; exit 2 ;;
    esac
}

# tsa_variants <dir>: issue the TSA certificate variants for <dir>/tsa.key.pem from <dir>/root.pem
# (M4 brief D-21). Only the variant certificates are written; every other file stays unchanged.
tsa_variants() {
    local d="$1" name spec ext cn nb f
    [ -f "$work/ca/ca.cnf" ] || write_ca_config
    for f in root.pem root.key.pem tsa.key.pem; do
        [ -f "$d/$f" ] || { echo "gen-pki: --tsa-variants needs $d/$f" >&2; exit 1; }
    done
    for name in "${TSA_VARIANTS[@]}"; do
        spec="$(tsa_variant_spec "$name")"
        ext="${spec%%|*}"
        cn="${spec#*|}"
        cn="${cn%|*}"
        nb="${spec##*|}"
        openssl req -new -config "$work/ca/ca.cnf" -key "$d/tsa.key.pem" \
            -subj "$DN_PREFIX/CN=$cn" -out "$work/$name.csr"
        openssl ca -batch -notext -rand_serial -config "$work/ca/ca.cnf" \
            -cert "$d/root.pem" -keyfile "$d/root.key.pem" -md sha256 -extensions "$ext" \
            -startdate "$nb" -enddate "$NOT_AFTER" -in "$work/$name.csr" -out "$work/$name.pem" \
            2>"$work/$name.ca.log" || { cat "$work/$name.ca.log" >&2; exit 1; }
        cp "$work/$name.pem" "$d/$name.pem"
    done
    echo "gen-pki: wrote ${#TSA_VARIANTS[@]} TSA certificate variants to $d"
}

# gen_key <out.key.pem> rsa:<bits>|ec:<curve>  -> unencrypted PKCS#8
gen_key() {
    local out="$1" spec="$2"
    case "$spec" in
        rsa:*) openssl genpkey -quiet -algorithm RSA -pkeyopt "rsa_keygen_bits:${spec#rsa:}" -out "$out" ;;
        ec:*)
            openssl genpkey -quiet -algorithm EC -pkeyopt "ec_paramgen_curve:${spec#ec:}" \
                -pkeyopt ec_param_enc:named_curve -out "$out"
            ;;
        *) echo "gen-pki: bad key spec $spec" >&2; exit 2 ;;
    esac
}

# issue <name> <key spec> <CN> <extension section> <issuer name|self> <md> [notBefore notAfter]
issue() {
    local name="$1" spec="$2" cn="$3" ext="$4" issuer="$5" md="$6"
    local nb="${7:-$NOT_BEFORE}" na="${8:-$NOT_AFTER}"
    local out="$work/out"
    gen_key "$out/$name.key.pem" "$spec"
    openssl req -new -config "$work/ca/ca.cnf" -key "$out/$name.key.pem" \
        -subj "$DN_PREFIX/CN=$cn" -out "$work/$name.csr"
    local signing=()
    if [ "$issuer" = "self" ]; then
        signing=(-selfsign -keyfile "$out/$name.key.pem")
    else
        signing=(-cert "$out/$issuer.pem" -keyfile "$out/$issuer.key.pem")
    fi
    openssl ca -batch -notext -rand_serial -config "$work/ca/ca.cnf" "${signing[@]}" \
        -md "$md" -extensions "$ext" -startdate "$nb" -enddate "$na" \
        -in "$work/$name.csr" -out "$out/$name.pem" 2>"$work/$name.ca.log" \
        || { cat "$work/$name.ca.log" >&2; exit 1; }
}

encrypt_key() {
    local name="$1" out="$work/out"
    openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -in "$out/$name.key.pem" \
        -passout "pass:$PASS" -out "$out/$name.key.enc.pem"
}

generate() {
    local out="$work/out"
    mkdir -p "$out"
    write_ca_config

    issue root rsa:3072 "Folioxide Test Root CA" ext_root self sha256
    issue intermediate ec:P-384 "Folioxide Test Intermediate CA" ext_intermediate root sha256
    issue signer-rsa2048 rsa:2048 "Folioxide Test Signer RSA-2048" ext_signer intermediate sha384
    issue signer-rsa3072 rsa:3072 "Folioxide Test Signer RSA-3072" ext_signer intermediate sha384
    issue signer-p256 ec:P-256 "Folioxide Test Signer P-256" ext_signer intermediate sha384
    issue signer-p384 ec:P-384 "Folioxide Test Signer P-384" ext_signer intermediate sha384
    issue tsa rsa:2048 "Folioxide Test TSA" ext_tsa root sha256
    issue expired rsa:2048 "Folioxide Test Signer (expired)" ext_signer intermediate sha384 \
        "$NOT_BEFORE" "$EXPIRED_NOT_AFTER"
    issue wrong-ku rsa:2048 "Folioxide Test Signer (wrong key usage)" ext_wrong_ku intermediate sha384

    local s
    for s in "${SIGNERS[@]}"; do
        encrypt_key "$s"
    done
    cp "$out/root.pem" "$out/tsa-root.pem"

    cat "$out/intermediate.pem" "$out/root.pem" > "$work/chain.pem"
    local export_p12=(openssl pkcs12 -export -certfile "$work/chain.pem" -passout "pass:$PASS")
    "${export_p12[@]}" -inkey "$out/signer-rsa2048.key.pem" -in "$out/signer-rsa2048.pem" \
        -name "Folioxide Test Signer RSA-2048" -out "$out/signer-rsa2048-modern.p12"
    "${export_p12[@]}" -inkey "$out/signer-rsa2048.key.pem" -in "$out/signer-rsa2048.pem" \
        -name "Folioxide Test Signer RSA-2048" -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES \
        -macalg sha1 -out "$out/signer-rsa2048-3des.p12"
    "${export_p12[@]}" -legacy -inkey "$out/signer-rsa2048.key.pem" -in "$out/signer-rsa2048.pem" \
        -name "Folioxide Test Signer RSA-2048" -out "$out/signer-rsa2048-rc2-40.p12"
    "${export_p12[@]}" -inkey "$out/signer-p256.key.pem" -in "$out/signer-p256.pem" \
        -name "Folioxide Test Signer P-256" -out "$out/signer-p256-modern.p12"

    derive "$out"
    tsa_variants "$out"

    mkdir -p "$pki_dir"
    local f
    for f in "$out"/*; do
        cp "$f" "$pki_dir/"
    done
    echo "gen-pki: wrote $(find "$out" -type f | wc -l | tr -d ' ') files to $pki_dir"
}

# derive_rsa <key.pem> <out>: the RSA key as PKCS#1 (BEGIN RSA PRIVATE KEY)
derive_rsa() { openssl rsa -in "$1" -traditional -out "$2" 2>/dev/null; }
# derive_ec <key.pem> <out>: the EC key as SEC1 with named-curve parameters (BEGIN EC PRIVATE KEY)
derive_ec() { openssl ec -in "$1" -out "$2" 2>/dev/null; }

# derive <dir>: write the derived key files next to the unencrypted PKCS#8 keys in <dir>
derive() {
    local d="$1" s
    for s in "${RSA_SIGNERS[@]}"; do
        derive_rsa "$d/$s.key.pem" "$d/$s.key.pkcs1.pem"
    done
    for s in "${EC_SIGNERS[@]}"; do
        derive_ec "$d/$s.key.pem" "$d/$s.key.sec1.pem"
    done
}

# ---------------------------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------------------------

passed=0
failed=0

ok() { passed=$((passed + 1)); }
fail() { failed=$((failed + 1)); echo "FAIL: $*" >&2; }

# expect_ok <description> <command...>: the command must exit 0
expect_ok() {
    local what="$1"
    shift
    if "$@" >"$work/cmd.out" 2>&1; then ok; else fail "$what"; sed 's/^/    /' "$work/cmd.out" >&2; fi
}

pubkey_of_cert() { openssl x509 -in "$1" -noout -pubkey; }
pubkey_of_key() { openssl pkey -in "$1" -passin "pass:$PASS" -pubout; }

# ext_text <cert> <extension name>: the extension as printed by OpenSSL, on one line
ext_text() { openssl x509 -in "$1" -noout -ext "$2" 2>/dev/null | tr '\n' ' '; }

check_key_matches() {
    local cert="$1" key="$2"
    if [ "$(pubkey_of_cert "$cert")" = "$(pubkey_of_key "$key")" ]; then ok; else
        fail "$(basename "$key") does not match $(basename "$cert")"
    fi
}

check_key_type() {
    local key="$1" want="$2" text
    text="$(openssl pkey -in "$key" -passin "pass:$PASS" -noout -text 2>/dev/null)"
    case "$want" in
        rsa:*)
            if printf '%s' "$text" | grep -q "Private-Key: (${want#rsa:} bit, 2 primes)"; then ok; else
                fail "$(basename "$key") is not RSA-${want#rsa:}"
            fi
            ;;
        ec:*)
            if printf '%s' "$text" | grep -q "NIST CURVE: ${want#ec:}"; then ok; else
                fail "$(basename "$key") is not EC ${want#ec:}"
            fi
            ;;
    esac
}

check_pkcs8() {
    local key="$1" header="$2"
    if [ "$(head -n 1 "$key")" = "-----BEGIN $header-----" ]; then ok; else
        fail "$(basename "$key") is not PEM '$header'"
    fi
}

check_long_validity() {
    local cert="$1" now remaining
    now="$(date +%s)"
    remaining=$((LONG_VALIDITY_EPOCH - now))
    expect_ok "$(basename "$cert") must stay valid until 2075" \
        openssl x509 -in "$cert" -noout -checkend "$remaining"
    if [ "$(openssl x509 -in "$cert" -noout -startdate)" = "notBefore=Jan  1 00:00:00 2025 GMT" ]; then
        ok
    else
        fail "$(basename "$cert") notBefore is not 2025-01-01"
    fi
}

check_signer_ku() {
    local cert="$1" ku
    ku="$(ext_text "$cert" keyUsage)"
    case "$ku" in
        *critical*"Digital Signature, Non Repudiation"*) ok ;;
        *) fail "$(basename "$cert") keyUsage is not critical digitalSignature+nonRepudiation: $ku" ;;
    esac
}

check_p12() {
    local p12="$1" cert="$2" key="$3" algs="$4" legacy=()
    case "$p12" in *rc2-40*) legacy=(-legacy) ;; esac
    local base
    base="$(basename "$p12")"
    if ! openssl pkcs12 ${legacy[@]+"${legacy[@]}"} -in "$p12" -info -noout -passin "pass:$PASS" \
        >"$work/p12.info" 2>&1; then
        fail "$base does not open with: openssl pkcs12 ${legacy[*]-} -info -noout -passin pass:$PASS"
        sed 's/^/    /' "$work/p12.info" >&2
        return
    fi
    ok
    local pattern dumped=0
    while IFS= read -r pattern; do
        [ -n "$pattern" ] || continue
        if grep -qF -- "$pattern" "$work/p12.info"; then ok; else
            fail "$base: expected '$pattern' in pkcs12 -info"
            if [ "$dumped" = 0 ]; then sed 's/^/    /' "$work/p12.info" >&2; dumped=1; fi
        fi
    done <<<"$algs"
    # The leaf certificate and key inside must be the signer's.
    local leaf_fp want_fp
    leaf_fp="$(openssl pkcs12 ${legacy[@]+"${legacy[@]}"} -in "$p12" -passin "pass:$PASS" -nokeys -clcerts 2>/dev/null \
        | openssl x509 -noout -fingerprint -sha256)"
    want_fp="$(openssl x509 -in "$cert" -noout -fingerprint -sha256)"
    if [ "$leaf_fp" = "$want_fp" ]; then ok; else fail "$base: leaf certificate is not $(basename "$cert")"; fi
    local p12_pub
    p12_pub="$(openssl pkcs12 ${legacy[@]+"${legacy[@]}"} -in "$p12" -passin "pass:$PASS" -nocerts -nodes 2>/dev/null \
        | openssl pkey -pubout)"
    if [ "$p12_pub" = "$(pubkey_of_key "$key")" ]; then ok; else fail "$base: key is not $(basename "$key")"; fi
    # Chain certificates: intermediate and root.
    local cas
    cas="$(openssl pkcs12 ${legacy[@]+"${legacy[@]}"} -in "$p12" -passin "pass:$PASS" -nokeys -cacerts 2>/dev/null \
        | grep -c 'BEGIN CERTIFICATE' || true)"
    if [ "$cas" = "2" ]; then ok; else fail "$base: expected 2 CA certificates, found $cas"; fi
}

check() {
    local d="$pki_dir"
    local required=(root.pem root.key.pem intermediate.pem intermediate.key.pem tsa.pem tsa.key.pem
        tsa-root.pem expired.pem expired.key.pem wrong-ku.pem wrong-ku.key.pem
        signer-rsa2048-modern.p12 signer-rsa2048-3des.p12 signer-rsa2048-rc2-40.p12
        signer-p256-modern.p12)
    local s f
    # The README marks the committed keys as test-only.
    if [ "$d" = "$repo_root/fixtures/pki" ]; then
        required+=(README.md)
    fi
    for s in "${SIGNERS[@]}"; do
        required+=("$s.pem" "$s.key.pem" "$s.key.enc.pem")
    done
    for s in "${RSA_SIGNERS[@]}"; do
        required+=("$s.key.pkcs1.pem")
    done
    for s in "${EC_SIGNERS[@]}"; do
        required+=("$s.key.sec1.pem")
    done
    for s in "${TSA_VARIANTS[@]}"; do
        required+=("$s.pem")
    done
    local missing=0
    for f in "${required[@]}"; do
        if [ -f "$d/$f" ]; then ok; else fail "missing $d/$f"; missing=1; fi
    done
    if [ "$missing" = 1 ]; then
        echo "gen-pki --check: files are missing; run: bash tools/gen-pki.sh" >&2
        exit 1
    fi

    # Chain: root -> intermediate -> signers; root -> TSA.
    expect_ok "intermediate.pem does not verify against root.pem" \
        openssl verify -x509_strict -CAfile "$d/root.pem" "$d/intermediate.pem"
    for s in "${SIGNERS[@]}"; do
        local out
        out="$(openssl verify -x509_strict -CAfile "$d/root.pem" -untrusted "$d/intermediate.pem" \
            "$d/$s.pem" 2>&1 || true)"
        if [ "$out" = "$d/$s.pem: OK" ]; then ok; else fail "openssl verify $s.pem: $out"; fi
        check_key_matches "$d/$s.pem" "$d/$s.key.pem"
        check_key_matches "$d/$s.pem" "$d/$s.key.enc.pem"
        check_pkcs8 "$d/$s.key.pem" "PRIVATE KEY"
        check_pkcs8 "$d/$s.key.enc.pem" "ENCRYPTED PRIVATE KEY"
        # The encrypted key must not open without the password.
        if openssl pkey -in "$d/$s.key.enc.pem" -passin pass:wrong -noout >/dev/null 2>&1; then
            fail "$s.key.enc.pem opens with a wrong password"
        else
            ok
        fi
        check_signer_ku "$d/$s.pem"
        check_long_validity "$d/$s.pem"
    done
    # Derived key files: the right PEM type, the signer's key, and up to date with the PKCS#8 key.
    local derived
    for s in "${RSA_SIGNERS[@]}"; do
        derived="$d/$s.key.pkcs1.pem"
        check_pkcs8 "$derived" "RSA PRIVATE KEY"
        check_key_matches "$d/$s.pem" "$derived"
        derive_rsa "$d/$s.key.pem" "$work/derived.pem"
        if cmp -s "$derived" "$work/derived.pem"; then ok; else
            fail "$(basename "$derived") is not derived from $s.key.pem (run: bash tools/gen-pki.sh --derive)"
        fi
    done
    for s in "${EC_SIGNERS[@]}"; do
        derived="$d/$s.key.sec1.pem"
        check_pkcs8 "$derived" "EC PRIVATE KEY"
        check_key_matches "$d/$s.pem" "$derived"
        derive_ec "$d/$s.key.pem" "$work/derived.pem"
        if cmp -s "$derived" "$work/derived.pem"; then ok; else
            fail "$(basename "$derived") is not derived from $s.key.pem (run: bash tools/gen-pki.sh --derive)"
        fi
    done
    check_key_type "$d/signer-rsa2048.key.pem" rsa:2048
    check_key_type "$d/signer-rsa3072.key.pem" rsa:3072
    check_key_type "$d/signer-p256.key.pem" ec:P-256
    check_key_type "$d/signer-p384.key.pem" ec:P-384
    check_key_type "$d/root.key.pem" rsa:3072
    check_key_type "$d/intermediate.key.pem" ec:P-384
    check_key_type "$d/tsa.key.pem" rsa:2048
    for f in root intermediate tsa expired wrong-ku; do
        check_key_matches "$d/$f.pem" "$d/$f.key.pem"
        check_pkcs8 "$d/$f.key.pem" "PRIVATE KEY"
    done
    for f in root intermediate tsa wrong-ku; do
        check_long_validity "$d/$f.pem"
    done

    # TSA: issued by the root, EKU timeStamping only and critical (RFC 3161 §2.3).
    expect_ok "tsa.pem does not verify as a timestamp signer against root.pem" \
        openssl verify -x509_strict -purpose timestampsign -CAfile "$d/root.pem" "$d/tsa.pem"
    local eku
    eku="$(ext_text "$d/tsa.pem" extendedKeyUsage)"
    case "$eku" in
        "X509v3 Extended Key Usage: critical     Time Stamping ") ok ;;
        *) fail "tsa.pem EKU must be exactly 'critical, timeStamping', got: $eku" ;;
    esac
    if cmp -s "$d/root.pem" "$d/tsa-root.pem"; then ok; else fail "tsa-root.pem is not a copy of root.pem"; fi

    # TSA variants (M4 brief D-21): the TSA's key, issued by the root, and each refused by
    # OpenSSL's timestamping purpose for exactly its own reason.
    local v vout
    for v in "${TSA_VARIANTS[@]}"; do
        check_key_matches "$d/$v.pem" "$d/tsa.key.pem"
        vout="$(openssl verify -x509_strict -no_check_time -CAfile "$d/root.pem" "$d/$v.pem" 2>&1 || true)"
        if [ "$vout" = "$d/$v.pem: OK" ]; then ok; else fail "$v.pem chain: $vout"; fi
        vout="$(openssl verify -purpose timestampsign -CAfile "$d/root.pem" "$d/$v.pem" 2>&1 || true)"
        case "$v:$vout" in
            tsa-not-yet-valid:*"not yet valid"*) ok ;;
            tsa-not-yet-valid:*) fail "$v.pem must fail only because it is not yet valid: $vout" ;;
            *:*"unsuitable certificate purpose"*) ok ;;
            *) fail "$v.pem must fail OpenSSL's timestampsign purpose: $vout" ;;
        esac
    done
    eku="$(ext_text "$d/tsa-eku-noncritical.pem" extendedKeyUsage)"
    case "$eku" in
        *critical*) fail "tsa-eku-noncritical.pem EKU is critical: $eku" ;;
        *"Time Stamping"*) ok ;;
        *) fail "tsa-eku-noncritical.pem EKU: $eku" ;;
    esac
    if [ -z "$(ext_text "$d/tsa-no-eku.pem" extendedKeyUsage)" ]; then ok; else fail "tsa-no-eku.pem has an EKU"; fi
    case "$(ext_text "$d/tsa-eku-extra.pem" extendedKeyUsage)" in
        *critical*"Time Stamping, Code Signing"*) ok ;;
        *) fail "tsa-eku-extra.pem EKU is not critical timeStamping + codeSigning" ;;
    esac
    case "$(ext_text "$d/tsa-ku-keyenc.pem" keyUsage)" in
        *critical*"Digital Signature, Key Encipherment"*) ok ;;
        *) fail "tsa-ku-keyenc.pem keyUsage is not digitalSignature + keyEncipherment" ;;
    esac
    if [ "$(openssl x509 -in "$d/tsa-not-yet-valid.pem" -noout -startdate)" = "notBefore=Jan  1 00:00:00 2070 GMT" ]; then
        ok
    else
        fail "tsa-not-yet-valid.pem notBefore is not 2070-01-01"
    fi

    # Negative cases.
    if openssl x509 -in "$d/expired.pem" -noout -checkend 0 >/dev/null; then
        fail "expired.pem is not expired"
    else
        ok
    fi
    local out
    out="$(openssl verify -CAfile "$d/root.pem" -untrusted "$d/intermediate.pem" "$d/expired.pem" 2>&1 || true)"
    case "$out" in
        *"certificate has expired"*) ok ;;
        *) fail "expired.pem must fail verification only because it expired: $out" ;;
    esac
    check_signer_ku "$d/expired.pem"
    out="$(openssl verify -CAfile "$d/root.pem" -untrusted "$d/intermediate.pem" "$d/wrong-ku.pem" 2>&1 || true)"
    if [ "$out" = "$d/wrong-ku.pem: OK" ]; then ok; else fail "wrong-ku.pem chain: $out"; fi
    local ku
    ku="$(ext_text "$d/wrong-ku.pem" keyUsage)"
    case "$ku" in
        *"Digital Signature"* | *"Non Repudiation"*) fail "wrong-ku.pem must lack digitalSignature/nonRepudiation: $ku" ;;
        *"Key Encipherment"*) ok ;;
        *) fail "wrong-ku.pem keyUsage unexpected: $ku" ;;
    esac

    # PKCS#12 flavours: each opens with the documented flags and uses the documented algorithms.
    local modern="MAC: sha256
PKCS7 Encrypted data: PBES2, PBKDF2, AES-256-CBC
Shrouded Keybag: PBES2, PBKDF2, AES-256-CBC"
    check_p12 "$d/signer-rsa2048-modern.p12" "$d/signer-rsa2048.pem" "$d/signer-rsa2048.key.pem" "$modern"
    check_p12 "$d/signer-p256-modern.p12" "$d/signer-p256.pem" "$d/signer-p256.key.pem" "$modern"
    check_p12 "$d/signer-rsa2048-3des.p12" "$d/signer-rsa2048.pem" "$d/signer-rsa2048.key.pem" \
        "MAC: sha1
PKCS7 Encrypted data: pbeWithSHA1And3-KeyTripleDES-CBC
Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC"
    check_p12 "$d/signer-rsa2048-rc2-40.p12" "$d/signer-rsa2048.pem" "$d/signer-rsa2048.key.pem" \
        "MAC: sha1
PKCS7 Encrypted data: pbeWithSHA1And40BitRC2-CBC
Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC"

    if [ "$failed" -gt 0 ]; then
        echo "gen-pki --check: $failed failed, $passed passed ($d)" >&2
        exit 1
    fi
    echo "gen-pki --check: all $passed checks passed ($d)"
}

if [ "$mode" = "generate" ]; then
    generate
elif [ "$mode" = "derive" ]; then
    derive "$pki_dir"
    echo "gen-pki: wrote the derived key files to $pki_dir"
elif [ "$mode" = "tsa-variants" ]; then
    tsa_variants "$pki_dir"
fi
check
