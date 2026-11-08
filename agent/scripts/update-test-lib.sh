# shellcheck shell=bash
# Shared by the update tests (P1-AGENT-UPDATE): scripts/update-smoke.sh (the runner's systemd) and
# scripts/vm-test.sh (a Debian 13 VM). Sourced, not run. Everything it makes is throwaway: a CA, a
# server certificate, and releases signed with keys the CI job generates.

update_test_lib_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
UPDATE_TEST_TARGET=x86_64-unknown-linux-musl

# make_certs DIR NAME [DAYS]: a throwaway CA (DIR/ca.pem) and a server certificate for the DNS name NAME
# that it signs (DIR/cert.pem, DIR/key.pem), both valid for DAYS days (default 1). The agent rightly
# refuses a self-signed CA certificate presented as the server's own.
make_certs() {
    local d=$1 name=$2 days=${3:-1}
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days "$days" -subj "/CN=update test CA" \
        -keyout "$d/ca-key.pem" -out "$d/ca.pem" 2> /dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$name" \
        -keyout "$d/key.pem" -out "$d/server.csr" 2> /dev/null
    printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' "$name" > "$d/ext.cnf"
    openssl x509 -req -in "$d/server.csr" -CA "$d/ca.pem" -CAkey "$d/ca-key.pem" -CAcreateserial -days "$days" \
        -extfile "$d/ext.cnf" -out "$d/cert.pem" 2> /dev/null
}

# mkrelease RELEASES NAME VERSION BINARY KEY: a release signed with KEY, in RELEASES/NAME, for
# scripts/update-stub.py to serve.
mkrelease() {
    local d=$1/$2 version=$3 binary=$4 key=$5
    mkdir -p "$d"
    cp "$binary" "$d/fleet-agent"
    "$update_test_lib_dir/release-manifest.sh" "$version" "$UPDATE_TEST_TARGET" "$d/fleet-agent" > "$d/manifest.json"
    minisign -S -s "$key" -m "$d/manifest.json" -x "$d/manifest.json.minisig" -t "update test $2" > /dev/null
}

# mkscript FILE VERSION RUN_BODY: a "release" that passes its self-test and does RUN_BODY when run.
mkscript() {
    cat > "$1" << EOF
#!/bin/sh
case "\$1" in
    self-test) echo "self-test OK: fleet-agent $2 (agent schema 1)" ;;
    --version) echo "fleet-agent $2 (agent schema 1)" ;;
    run) $3 ;;
esac
EOF
    chmod 0755 "$1"
}
