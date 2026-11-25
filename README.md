# btc-keytool

An offline Bitcoin key, multisig and transaction tool, written in Rust.

- **CLI** (`btc-keytool`) and **desktop app** (Tauri), both thin shells over one library, `btc-keytool-core`.
- Derive the public key and **every** address type from a private key.
- Build and **sign** transactions offline. You get raw hex; nothing is broadcast.
- **Multisig**: create k-of-n addresses, sign in turns, combine, finalise (PSBT).
- **Every signature is verified** before you see it, and a finished transaction is checked
  a second time by Bitcoin Core's own script interpreter.
- Sign and verify text messages.

```
crates/core   btc-keytool-core   all logic: keys, scripts, PSBT signing, verification
crates/cli    btc-keytool        command-line tool
src-tauri     btc-keytool-app    desktop app (Rust side)
ui/                              desktop app (static HTML/JS, no build step, no npm)
legacy/                          the original Python tool, kept as a reference oracle
site/                            the project page (GitHub Pages)
```

## Build

```bash
cargo build --release -p btc-keytool        # CLI  -> target/release/btc-keytool
cargo tauri build                           # app  -> target/release/bundle/   (needs `cargo install tauri-cli`)
cargo tauri dev                             # app, development mode
cargo test --workspace
```

Prebuilt binaries for Linux, macOS and Windows are attached to each
[release](https://github.com/rsantacroce/btc-keytool/releases) together with `SHA256SUMS.txt`.
They are not code-signed, so macOS and Windows warn on first launch.

### CI and releases

| Workflow | When | What |
|---|---|---|
| `ci.yml` | every PR and push to `main` | rustfmt, clippy, tests and self-test on Linux, macOS and Windows; parity check against the Python original |
| `build.yml` | every PR, push to `main`, and `v*` tags | CLI for Linux x86_64/arm64, macOS arm64/x86_64, Windows x86_64; desktop app as `.deb`/AppImage, universal `.dmg`, Windows installer. On a tag the files go into a **draft** release |
| `pages.yml` | pushes to `main` touching `site/` | publishes `site/` to <https://rsantacroce.github.io/btc-keytool/> |

To cut a release: `git tag v0.2.0 && git push origin v0.2.0`, then review and publish the draft.

## Signing is always followed by verification

This is the rule the tool is built around:

1. **At signing time** each signature is verified against its public key the moment it is made.
2. **In a PSBT** every signature already present - yours or a cosigner's - is verified before
   it is counted. A bad one is an error naming the key, never a silent drop.
3. **A finished transaction** is verified twice before it is printed:
   - by this tool's own checker, which reports who signed what and enforces low-S;
   - by **libbitcoinconsensus**, Bitcoin Core's script interpreter, with every consensus
     rule up to taproot enabled.

   If either check fails the transaction is **not output at all**.
4. `verify` repeats all of that later, on any transaction or PSBT:

```bash
btc-keytool verify signed.hex spec.json     # raw tx: needs the spec (amounts + scripts being spent)
btc-keytool verify partial.psbt             # PSBT: carries that itself
```

`verify` exits 0 only for a fully signed transaction whose every signature is valid.

## Keys

```bash
# the canonical 'private key = 1' test key - public knowledge, never fund it
btc-keytool key KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
btc-keytool key --file key.txt          # keeps it out of your shell history and `ps`
btc-keytool newkey
btc-keytool addr bc1q…                  # address -> scriptPubKey, type, dust limit
btc-keytool addr 02abc…                 # public key -> all its addresses
```

Accepts WIF, 64-character hex, `0x…` hex or a decimal integer. Add `--json` to any command
for machine-readable output, `--network testnet|signet|regtest` to leave mainnet.

| Type | Looks like | Notes |
|---|---|---|
| P2PKH | `1…` | original legacy address |
| P2PKH uncompressed | `1…` | different address, same key - old wallets |
| P2SH-P2WPKH | `3…` | segwit wrapped for old senders |
| P2WPKH | `bc1q…` | native segwit |
| P2TR | `bc1p…` | taproot, key-path (BIP86 tweak) |

**A key has all of these at once.** If you are looking for coins, check every one.

## Building a transaction

```bash
btc-keytool build examples/simple.json
btc-keytool build spec.json -o signed.hex --json
```

For every input you need `txid`, `vout`, `amount_sat`, the address (or `script_pubkey`) it pays
to, and a key. The amount is not optional: segwit and taproot signatures commit to it.

Fees: give `fee_rate` (sat/vB) with either a `change_address` or one output set to
`"amount_sat": "all"`. The fee is computed from the worst-case signed size, so the rate you
get is never below the rate you asked for. Change below the dust limit goes to the fee.

`build` refuses to continue if a key does not match its input, if outputs exceed inputs, if
the fee looks like a fat-finger (over 50% of the input or 100k sat; `--force` overrides), or if
the spec contains a field it does not know (so a typo such as `change_adress` cannot turn your
change into fee). Keys beginning with `_` are comments.

Single-key inputs: P2PKH, P2PK, P2SH-P2WPKH, P2WPKH, P2TR key-path.
Outputs: any address type, a raw `script_pubkey`, or `op_return`.

### Spec reference

```jsonc
{
  "network": "mainnet",          // mainnet | testnet | signet | regtest
  "version": 2,
  "locktime": 0,
  "key": "WIF",                  // default key, tried on every input
  "keys": ["WIF", "WIF"],        // more default keys (multisig)

  "inputs": [{
    "txid": "…", "vout": 0,
    "amount_sat": 250000,        // required (or give prev_tx)
    "address": "bc1q…",          // or "script_pubkey": "0014…"
    "prev_tx": "0200…",          // optional: full previous tx hex; amount and script are read from it
    "key": "WIF",                // key for this input ("keys": [...] for several)
    "sequence": 4294967293,      // optional, default RBF-enabled
    "sighash": 1,                // optional; taproot default is 0

    "multisig": {                // for a multisig input
      "threshold": 2,
      "pubkeys": ["02…", "03…", "02…"],
      "sorted": true,            // BIP67 order (sortedmulti). Default true
      "type": "p2wsh"            // p2wsh | p2sh-p2wsh | p2sh. Inferred from the address if omitted
    }
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

## Multisig

**1. Create the address** from the cosigners' *public* keys:

```bash
btc-keytool multisig -k 2 -p 02aa… -p 03bb… -p 02cc…            # 2-of-3, P2WSH
btc-keytool multisig -k 2 -p … -p … -p … --type p2sh-p2wsh      # or p2sh
```

It prints the address, the witness/redeem script and a checksummed output descriptor
(`wsh(sortedmulti(2,…))#…`) you can import into Bitcoin Core or Sparrow as watch-only.
Keys are BIP67-sorted by default, so everyone gets the same address whatever order they
type the keys in. **Each cosigner should run this themselves and compare the address.**

**2. Build the spend.** Put a `multisig` block on the input (see `examples/multisig.json`)
and list whatever private keys you hold - possibly none:

```bash
btc-keytool build spend.json -o spend.psbt
```

With enough keys you get a finished, verified transaction. Otherwise you get a **PSBT**
and a table of who has signed and who has not.

**3. Each cosigner signs**, on their own machine:

```bash
btc-keytool decode spend.psbt                        # review outputs and fee first
btc-keytool sign spend.psbt --key-file my.key -o spend.psbt
```

The moment the threshold is reached, `sign` finalises the transaction, verifies it both
ways and prints the raw hex instead of a PSBT.

**4. Or sign in parallel and merge:**

```bash
btc-keytool combine alice.psbt bob.psbt -o signed.hex
```

A key that is not a cosigner is refused, and a signature filed under the wrong key is detected.

Supported: k-of-n `OP_CHECKMULTISIG` with compressed keys in P2WSH, P2SH-P2WSH (up to 20 keys)
and legacy P2SH (up to 15). Not supported: taproot script-path multisig (`multi_a`) and MuSig.

## Messages

```bash
btc-keytool msg sign "I control this address" --key-file key.txt
btc-keytool msg verify <address> <signature> "I control this address"
```

BIP137 compact signatures, verified before they are printed. Works for P2PKH, P2SH-P2WPKH and
P2WPKH addresses (`--address` picks which); taproot addresses would need BIP322.

## The desktop app

Same functions as the CLI, one tab each: Key, Address, Multisig, Build & sign, Sign PSBT,
Combine, Verify, Decode, Message, Self-test. The UI is static HTML/CSS/JS with no bundler and
no third-party JavaScript; every button calls a Rust command in `src-tauri/src/main.rs`,
which forwards to the core library. Private-key fields are masked until you tick "show".

## Offline by construction

- **The CLI and the core library contain no network code and no network-capable dependency.**
  Check it yourself: `cargo tree -p btc-keytool` lists no HTTP, TLS, socket or async-runtime crate.
- **The app** loads no Tauri plugins (no HTTP, shell, filesystem or updater), grants its window
  no Tauri API permissions beyond its own commands, and ships a Content-Security-Policy of
  `default-src 'none'` with `connect-src` limited to Tauri's local IPC, so the page cannot
  fetch anything. (Tauri itself pulls in the tokio runtime, built without its `net` feature.)
- Broadcasting is deliberately left to you: copy the hex to an online machine and paste it
  into any node or explorer's "send raw transaction" form.

Unlike the Python original, the process does not booby-trap its own socket API - there is no
equivalent in a compiled binary. For real money the answer is the same as before: run it on a
machine that is not connected.

## Verifying the tool itself

```bash
btc-keytool selftest        # 99 checks, also available in the app
btc-keytool selftest -v
cargo test --workspace      # the same checks, plus cross-checks against rust-miniscript
legacy/parity.sh            # compares against the original Python implementation
```

The self-test runs the official BIP143 sighash/signature vector, BIP173/BIP350 address
vectors, the BIP86 taproot vector, a BIP67 multisig vector and the genesis coinbase, then
build -> sign -> verify round-trips for every input type and every multisig wrapping, and
negative tests: wrong key, non-cosigner key, forged cosigner signature, overspend, absurd fee,
misspelled field, tampered amount.

Cryptography is not implemented here: keys, ECDSA (RFC 6979, low-S) and Schnorr (BIP340)
come from libsecp256k1 via `rust-bitcoin`. Signing is deterministic, so the same spec always
yields the same bytes - and, for single-key transactions, the same bytes the Python tool produced.

## Safety

- The tool never asks for and never stores a seed phrase; it works on individual keys.
- Nothing is written to disk unless you pass `-o`.
- A signed transaction is **bearer-spendable**: anyone holding the hex can broadcast it.
- A PSBT contains no private keys, but it does reveal the addresses and amounts involved.
- PSBTs made here carry the spent output's amount and script (`witness_utxo`) for every input.
  Other wallets may insist on the full previous transaction for legacy P2SH inputs; supply
  `prev_tx` in the spec if you need that interoperability.
- `newkey` uses the operating system's entropy source. Fine for testing. For savings, use hardware.
