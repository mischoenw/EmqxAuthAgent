#!/usr/bin/env bash
# Test EMQX mTLS authorization against mqtt.mmbr.dev:8884
# Requires: mosquitto-clients, openssl
set -uo pipefail

HOST=mqtt.mmbr.dev
PORT=8884
CERT=ssl/consumer.pub
KEY=ssl/consumer.key
CA=ssl/ca-chain.pem

for f in "$CERT" "$KEY" "$CA"; do
    [ -f "$f" ] || { echo "ERROR: missing file: $f"; exit 1; }
done

# Extract O and OU using multiline format to avoid O= / OU= ambiguity
SUBJECT=$(openssl x509 -in "$CERT" -noout -subject -nameopt multiline 2>/dev/null)
O=$(echo  "$SUBJECT" | grep '^\s*organizationName\s*='         | grep -v 'Unit' | sed 's/.*= //' | head -1)
OU=$(echo "$SUBJECT" | grep '^\s*organizationalUnitName\s*='                    | sed 's/.*= //' | head -1)

if [ -z "$O" ] || [ -z "$OU" ]; then
    echo "ERROR: could not extract O or OU from $CERT"
    echo "$SUBJECT"
    exit 1
fi

OWN="/$O/$OU"
FOREIGN="/other000/0000-0000"
PROBE="$OWN/authz-probe"

echo "Certificate  O=$O  OU=$OU"
echo "Broker       $HOST:$PORT"
echo "Own topic    $OWN/#"
echo ""

PASS=0
FAIL=0

TLS="--cert $CERT --key $KEY --cafile $CA"
PUB="mosquitto_pub  -h $HOST -p $PORT $TLS -q 1 -W 5"
SUB="mosquitto_sub  -h $HOST -p $PORT $TLS -q 1"

# Remove the retained probe message on exit
cleanup() { $PUB -t "$PROBE" -m "" -r 2>/dev/null || true; }
trap cleanup EXIT

check() {
    local desc="$1" expected="$2"
    shift 2
    if "$@" 2>/dev/null; then actual=allow; else actual=deny; fi
    if [ "$actual" = "$expected" ]; then
        printf "PASS  %s\n" "$desc"
        PASS=$((PASS + 1))
    else
        printf "FAIL  %-52s (expected %s, got %s)\n" "$desc" "$expected" "$actual"
        FAIL=$((FAIL + 1))
    fi
}

echo "--- publish ---"
check "own ns root  $OWN/test"       allow  $PUB -t "$OWN/test"       -m "authz-test"
check "own ns deep  $OWN/a/b/c"     allow  $PUB -t "$OWN/a/b/c"     -m "authz-test"
check "foreign ns   $FOREIGN/test"  deny   $PUB -t "$FOREIGN/test"  -m "authz-test"
check "bare topic   /test"          deny   $PUB -t "/test"           -m "authz-test"

# Publish a retained message so the subscribe test gets an immediate reply
$PUB -t "$PROBE" -m "probe" -r 2>/dev/null

echo ""
echo "--- subscribe ---"
check "own ns       $OWN/#"         allow  $SUB -t "$OWN/#"         -C 1 -W 3
check "foreign ns   $FOREIGN/#"    deny   $SUB -t "$FOREIGN/#"     -C 1 -W 3

echo ""
printf "Results: %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
