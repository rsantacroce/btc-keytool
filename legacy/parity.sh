#!/usr/bin/env bash
# Checks that the Rust CLI reproduces the original Python tool exactly:
# same key/address output, and byte-identical signed transactions.
# Usage: legacy/parity.sh   (after `cargo build -p btc-keytool`)
set -euo pipefail
cd "$(dirname "$0")/.."
B=./target/debug/btc-keytool
PY="python3 legacy/btc_keytool.py"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0

for k in 1 0xabc 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf \
         619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9 123456789012345678901234567890; do
  # regtest is skipped: the Python tool crashes on bcrt1 addresses (the Rust one does not)
  for n in mainnet testnet signet; do
    diff <($PY key "$k" --json --network $n) <($B key "$k" --json --network $n) >/dev/null \
      || { echo "DIFF key $k $n"; fail=1; }
  done
done
echo "key output: compared 15 key/network combinations"

for t in bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH \
         3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9 \
         0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798; do
  # a 32-byte x-only key is deliberately not compared: the Rust tool shows only its taproot
  # address (the Python one guesses a parity and lists legacy/segwit addresses that may be wrong)
  diff <($PY addr $t --json) <($B addr $t --json) >/dev/null || { echo "DIFF addr $t"; fail=1; }
done
echo "addr output: compared 5 targets"

$PY key 0xabc --json > "$T/k.json"
python3 - "$T" <<'PYEOF'
import json, sys
T = sys.argv[1]; k = json.load(open(T + '/k.json')); a = k['addresses']
spec = {"network": "mainnet", "key": k['private_key_hex'], "locktime": 800000,
  "inputs": [
    {"txid": "b"*64, "vout": 0, "amount_sat": 50000, "address": a['p2tr']},
    {"txid": "c"*64, "vout": 1, "amount_sat": 60000, "address": a['p2wpkh']},
    {"txid": "d"*64, "vout": 2, "amount_sat": 70000, "address": a['p2pkh']},
    {"txid": "e"*64, "vout": 7, "amount_sat": 80000, "address": a['p2sh_p2wpkh'], "sequence": 4294967295},
    {"txid": "f"*64, "vout": 0, "amount_sat": 90000, "address": a['p2pkh_uncomp']},
    {"txid": "1"*64, "vout": 0, "amount_sat": 10000, "script_pubkey": "21" + k['public_key_compressed'] + "ac"},
    {"txid": "2"*64, "vout": 5, "amount_sat": 30000, "address": a['p2tr'], "sighash": 1},
    {"txid": "3"*64, "vout": 6, "amount_sat": 20000, "address": a['p2wpkh'], "sighash": 129}],
  "outputs": [
    {"address": a['p2tr'], "amount_sat": 100000}, {"op_return": "btc-keytool"},
    {"address": "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN", "amount_sat": 200000},
    {"op_return": "deadbeef", "hex": True}, {"script_pubkey": "0014" + "11"*20, "amount_sat": 55000}]}
json.dump(spec, open(T + '/spec.json', 'w'))
PYEOF
raw() { python3 -c "import json,sys; print(json.load(sys.stdin)['raw'])"; }
$PY build "$T/spec.json" --json | raw > "$T/py.hex"
$B  build "$T/spec.json" --json | raw > "$T/rs.hex"
if cmp -s "$T/py.hex" "$T/rs.hex"; then
  echo "build: 8-input mixed transaction is byte-identical ($(($(wc -c < "$T/rs.hex") / 2)) bytes)"
else echo "DIFF build"; fail=1; fi
$PY verify "$T/rs.hex" "$T/spec.json" >/dev/null && echo "python verifies the rust transaction" || { echo "python REJECTS rust tx"; fail=1; }
$B  verify "$T/py.hex" "$T/spec.json" >/dev/null && echo "rust verifies the python transaction" || { echo "rust REJECTS python tx"; fail=1; }
diff <($PY decode "$T/py.hex" --json) <($B decode "$T/rs.hex" --json) >/dev/null && echo "decode output: identical" || { echo "DIFF decode"; fail=1; }
[ $fail = 0 ] && echo "PARITY OK" || { echo "PARITY FAILED"; exit 1; }
