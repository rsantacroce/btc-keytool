# btc-keytool

An offline Bitcoin key and transaction tool. One file, no dependencies, no network.

- Derive the public key and **every** address type from a private key.
- Build and **sign** a real transaction offline. You get raw hex; nothing is broadcast.
- Decode and verify transactions.

## Offline by construction

Three separate reasons nothing can leak:

1. **No network code exists.** No `urllib`, no `requests`, no sockets anywhere in the file.
2. **Sockets are disabled at startup.** `_airgap()` replaces `socket.socket`,
   `create_connection`, `getaddrinfo` and friends with functions that raise. Even a
   dependency trying to dial out would fail.
3. **No dependencies.** Only the Python standard library, so there is no third-party
   code to audit or trust. secp256k1, RIPEMD-160, base58 and bech32 are implemented
   here, in ~700 readable lines.

Broadcasting is deliberately left to you: copy the hex to an online machine and paste
it into any node or explorer's "submit raw transaction" form.

## Verifying it is correct

```bash
python3 btc_keytool.py selftest        # 101 checks
python3 btc_keytool.py selftest -v     # show each one
```

It runs the official BIP143 sighash and signature vector, BIP173/BIP350 bech32 and
bech32m vectors, RIPEMD-160 vectors, the BIP86 taproot address vector, the genesis
coinbase transaction (parsed and re-serialised to the byte), plus build→sign→verify
round-trips for every supported input type and negative tests (wrong key, overspend,
absurd fee, tampered amount).

If `python-ecdsa` or `coincurve` happen to be installed, it also checks our
signatures against them — `coincurve` is Bitcoin Core's own libsecp256k1.

## Your private key

```bash
# the canonical 'private key = 1' test key - public knowledge, never fund it
python3 btc_keytool.py key KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
python3 btc_keytool.py key --file key.txt          # keeps it out of your shell history
python3 btc_keytool.py key <key> --json
```

Accepts WIF (compressed or not), 64-character hex, `0x…` hex, or a decimal integer,
and prints the private key, both WIFs, the compressed / uncompressed / x-only public
key, and five addresses:

| Type | Looks like | Notes |
|---|---|---|
| P2PKH | `1…` | original legacy address |
| P2PKH uncompressed | `1…` | different address, same key — old wallets |
| P2SH-P2WPKH | `3…` | segwit wrapped for old senders |
| P2WPKH | `bc1q…` | native segwit, cheapest common type |
| P2TR | `bc1p…` | taproot, key-path (BIP86 tweak) |

**A key has all of these at once.** If you are looking for coins, check every one —
funds sit at whichever address the sender used.

`--file` is the safer habit: an argument shows up in `ps` and your shell history.

## Building a transaction

Write a JSON spec (see `examples/`) and run:

```bash
python3 btc_keytool.py build examples/simple.json
python3 btc_keytool.py build spec.json -o signed.hex --json
```

You need, for every input: `txid`, `vout`, `amount_sat`, the address or
`script_pubkey` it pays to, and a key. The amount is not optional — segwit and
taproot signatures commit to the input value, so a wrong amount silently produces an
invalid signature.

Fees: give `fee_rate` (sat/vB) with either a `change_address` or one output set to
`"amount_sat": "all"`. The tool signs a scratch copy to measure the true vsize,
solves for the fee, and re-signs — so the rate you asked for is the rate you get.
Change below the dust limit is dropped into the fee. Or omit both and set exact
amounts; the remainder is the fee.

Supported inputs: P2PKH, P2PK, P2SH-P2WPKH, P2WPKH, P2TR key-path.
Outputs can be any address type, a raw `script_pubkey`, or `op_return`.

### Spec reference

```jsonc
{
  "network": "mainnet",          // mainnet | testnet | signet | regtest
  "version": 2,
  "locktime": 0,
  "key": "WIF",                  // default key; inputs may override

  "inputs": [{
    "txid": "…", "vout": 0,
    "amount_sat": 250000,        // required
    "address": "bc1q…",          // or "script_pubkey": "0014…"
    "key": "WIF",                // optional per-input override
    "sequence": 4294967293,      // optional, default RBF-enabled
    "sighash": 1                 // optional; taproot default is 0
  }],

  "outputs": [
    { "address": "bc1q…", "amount_sat": 100000 },
    { "address": "bc1q…", "amount_sat": "all" },   // sweep the remainder
    { "op_return": "hello" },                      // add "hex": true for raw bytes
    { "script_pubkey": "0014…", "amount_sat": 1000 }
  ],

  "change_address": "bc1q…",
  "fee_rate": 8                  // sat/vB
}
```

## Checking your work

```bash
python3 btc_keytool.py decode signed.hex
python3 btc_keytool.py verify signed.hex spec.json
python3 btc_keytool.py addr bc1q…          # address -> scriptPubKey, dust limit
python3 btc_keytool.py addr 02abc…         # pubkey -> all its addresses
```

`build` already verifies every signature it produces before showing you the hex, and
refuses to sign if a key does not match its input, if outputs exceed inputs, or if the
fee looks like a fat-finger (over 50% of input or 100k sat — `--force` overrides).

## Safety

- The tool never asks for and never stores a seed phrase; it works on one key at a time.
- For real money, run this on a machine that has never been online, and move the signed
  hex off by hand.
- A signed transaction is **bearer-spendable**: anyone holding the hex can broadcast it.
- `newkey` uses `os.urandom`. Fine for testing. For savings, use hardware.
