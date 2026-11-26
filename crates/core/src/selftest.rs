//! Built-in test vectors. Run them on the machine you are about to trust
//! with a key: `btc-keytool selftest`.

use bitcoin::secp256k1::SecretKey;
use bitcoin::{Amount, Network, ScriptBuf, TxOut};
use serde::Serialize;
use serde_json::{json, Value};

use crate::decode::{decode, parse_psbt, parse_tx_or_psbt, verify, Parsed};
use crate::keys::{addresses_for_pubkey, key_info, parse_key, parse_pubkey};
use crate::message::{sign_message, verify_message};
use crate::script::{dust_threshold, parse_address, Kind, Multisig, Wrap};
use crate::sign::{combine, ecdsa_sighash, sign_and_report, Outcome, Policy};
use crate::spec::build;
use crate::verify::{consensus_verify, verify_tx};
use crate::{hx, secp, unhx, Result};

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Default)]
struct T(Vec<Check>);

impl T {
    fn ok(&mut self, name: impl Into<String>, cond: bool) {
        self.0.push(Check {
            name: name.into(),
            ok: cond,
            detail: String::new(),
        });
    }
    fn eq<A: PartialEq + std::fmt::Debug>(&mut self, name: &str, got: A, want: A) {
        let ok = got == want;
        let detail = if ok {
            String::new()
        } else {
            format!("got {got:?}, want {want:?}")
        };
        self.0.push(Check {
            name: name.into(),
            ok,
            detail,
        });
    }
    /// The closure must succeed and return true.
    fn run(&mut self, name: impl Into<String>, f: impl FnOnce() -> Result<bool>) {
        let (ok, detail) = match f() {
            Ok(b) => (b, String::new()),
            Err(e) => (false, e.0),
        };
        self.0.push(Check {
            name: name.into(),
            ok,
            detail,
        });
    }
    /// The closure must fail: a refusal is the correct behaviour.
    fn refuses<X>(&mut self, name: &str, f: impl FnOnce() -> Result<X>) {
        self.ok(name, f().is_err());
    }
}

fn key(n: u64) -> SecretKey {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&n.to_be_bytes());
    SecretKey::from_slice(&b).expect("small non-zero scalar")
}

fn pub_hex(sk: &SecretKey) -> String {
    hx(&sk.public_key(secp()).serialize())
}

fn txid(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

fn built(spec: Value) -> Result<Outcome> {
    build(&spec.to_string(), false)
}

pub fn run() -> Vec<Check> {
    let mut t = T::default();
    let net = Network::Bitcoin;

    // --- keys and addresses (the well-known private key 1) -----------------
    let k1 = key(1);
    let info = key_info(&k1, net).expect("key info");
    t.eq(
        "privkey 1 -> compressed pubkey",
        info.public_key_compressed.as_str(),
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    );
    t.eq(
        "privkey 1 -> P2PKH",
        info.addresses.p2pkh.as_str(),
        "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
    );
    t.eq(
        "privkey 1 -> P2PKH uncompressed",
        info.addresses.p2pkh_uncomp.as_str(),
        "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
    );
    t.eq(
        "privkey 1 -> P2SH-P2WPKH",
        info.addresses.p2sh_p2wpkh.as_str(),
        "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN",
    );
    t.eq(
        "privkey 1 -> P2WPKH (BIP173 vector)",
        info.addresses.p2wpkh.as_str(),
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    );
    t.eq(
        "privkey 1 -> P2TR (BIP86 tweak)",
        info.addresses.p2tr.as_str(),
        "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9",
    );
    t.eq(
        "privkey 1 -> WIF",
        info.wif_compressed.as_str(),
        "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
    );
    t.eq(
        "privkey 1 -> WIF uncompressed",
        info.wif_uncompressed.as_str(),
        "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf",
    );
    t.eq(
        "P2PKH scriptPubKey",
        info.script_pubkeys.p2pkh.as_str(),
        "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
    );
    for (name, text) in [
        ("WIF", info.wif_compressed.as_str()),
        ("uncompressed WIF", info.wif_uncompressed.as_str()),
        ("64-char hex", info.private_key_hex.as_str()),
        ("0x-hex", "0x1"),
        ("decimal", "1"),
    ] {
        t.run(format!("parse key from {name}"), || {
            Ok(parse_key(text)? == k1)
        });
    }
    t.refuses("rejects private key 0", || parse_key("0"));
    t.refuses("rejects private key >= n", || {
        parse_key("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
    });
    t.refuses("rejects a WIF with a bad checksum", || {
        parse_key("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWm")
    });
    t.refuses("rejects a mainnet address on testnet", || {
        parse_address(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            Network::Testnet,
        )
    });
    t.refuses("rejects a v1 address encoded as bech32", || {
        parse_address("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh", net)
    });
    t.refuses("rejects a bech32 address with a bad checksum", || {
        parse_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", net)
    });

    // --- BIP143 official P2WPKH vector: sighash and signature ---------------
    t.run("BIP143 sighash + RFC6979 signature vector", || {
        let raw = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f\
                   0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b9\
                   0ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a\
                   783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167f\
                   aa815988ac11000000";
        let Parsed::Tx(tx) = parse_tx_or_psbt(raw)? else {
            return Ok(false);
        };
        let utxo = TxOut {
            value: Amount::from_sat(600_000_000),
            script_pubkey: ScriptBuf::from(unhx("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1")?),
        };
        let msg = ecdsa_sighash(&tx, 1, &Kind::P2wpkh, &utxo, None, 1)?;
        let sk = parse_key("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")?;
        let sig = secp().sign_ecdsa(&msg, &sk);
        Ok(
            hx(msg.as_ref()) == "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
                && hx(&sig.serialize_der())
                    == "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a\
                    0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee",
        )
    });

    // --- a real transaction: the genesis coinbase ---------------------------
    t.run("genesis coinbase decodes to the right txid", || {
        let raw = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d\
                   04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f\
                   6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2\
                   052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649\
                   f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
        let d = decode(raw, net)?;
        let Parsed::Tx(tx) = parse_tx_or_psbt(raw)? else { return Ok(false) };
        Ok(d["txid"] == "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
            && d["outputs"][0]["type"] == "p2pk"
            && d["outputs"][0]["amount_sat"] == 5_000_000_000u64
            && bitcoin::consensus::encode::serialize_hex(&tx) == raw)
    });

    // --- single-key build -> sign -> verify, every input type ---------------
    let k = key(0xabc);
    let ad = addresses_for_pubkey(&k.public_key(secp()), net);
    let kh = hx(&k.secret_bytes());
    let p2pk = format!("21{}ac", pub_hex(&k));
    let inputs: Vec<(&str, Value)> = vec![
        ("p2pkh", json!({"address": ad.p2pkh})),
        ("p2pkh uncompressed", json!({"address": ad.p2pkh_uncomp})),
        ("p2sh-p2wpkh", json!({"address": ad.p2sh_p2wpkh})),
        ("p2wpkh", json!({"address": ad.p2wpkh})),
        ("p2tr", json!({"address": ad.p2tr})),
        ("p2pk", json!({"script_pubkey": p2pk})),
    ];
    for (name, extra) in &inputs {
        let mut input = json!({"txid": txid('a'), "vout": 0, "amount_sat": 100_000});
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let spec = json!({"network": "mainnet", "key": kh, "inputs": [input], "fee_rate": 5,
                          "outputs": [{"address": ad.p2wpkh, "amount_sat": "all"}]});
        match built(spec.clone()) {
            Err(e) => t.0.push(Check {
                name: format!("sign {name}"),
                ok: false,
                detail: e.0,
            }),
            Ok(oc) => {
                t.ok(
                    format!("sign + verify {name}"),
                    oc.complete && oc.verify.iter().all(|c| c.ok),
                );
                t.ok(
                    format!("Bitcoin Core interpreter accepts {name}"),
                    oc.consensus.as_deref() == Some("ok"),
                );
                t.ok(
                    format!("fee rate honoured {name}"),
                    oc.fee_rate >= 5.0 && oc.fee_rate <= 5.3,
                );
                let raw = oc.raw.clone().unwrap_or_default();
                t.run(format!("standalone verify {name}"), || {
                    Ok(verify(&raw, Some(&spec.to_string()), net)?.valid)
                });
                t.run(format!("signing is deterministic {name}"), || {
                    Ok(built(spec)?.raw == oc.raw)
                });
            }
        }
    }

    // --- mixed inputs: taproot commits to every prevout ---------------------
    let mixed = json!({
        "network": "mainnet", "key": kh,
        "inputs": [
            {"txid": txid('b'), "vout": 0, "amount_sat": 50_000, "address": ad.p2tr},
            {"txid": txid('c'), "vout": 1, "amount_sat": 60_000, "address": ad.p2wpkh},
            {"txid": txid('d'), "vout": 2, "amount_sat": 70_000, "address": ad.p2pkh}],
        "outputs": [{"address": ad.p2tr, "amount_sat": 100_000}, {"op_return": "btc-keytool"}],
        "change_address": ad.p2wpkh, "fee_rate": 12});
    let mixed_oc = built(mixed.clone());
    t.run(
        "mixed-input tx verifies, change added, OP_RETURN present",
        || {
            let oc = mixed_oc.clone()?;
            Ok(oc.complete
                && oc.notes.iter().any(|n| n.contains("change output"))
                && oc.outputs.iter().any(|o| o.kind == "op_return")
                && oc.fee_rate >= 12.0
                && oc.fee_rate <= 12.5)
        },
    );

    // --- tampering must be caught by both verifiers -------------------------
    t.run("an edited amount invalidates every signature", || {
        let oc = mixed_oc.clone()?;
        let Parsed::Tx(mut tx) = parse_tx_or_psbt(oc.raw.as_deref().unwrap_or(""))? else {
            return Ok(false);
        };
        let prevouts: Vec<TxOut> = crate::spec::prevouts_from_spec(&mixed.to_string())?
            .1
            .into_iter()
            .map(|r| r.txout)
            .collect();
        let before = verify_tx(&tx, &prevouts).iter().all(|c| c.ok);
        tx.output[0].value += Amount::from_sat(1);
        Ok(before
            && verify_tx(&tx, &prevouts).iter().all(|c| !c.ok)
            && consensus_verify(&tx, &prevouts).is_err())
    });
    t.run("verify rejects a wrong input amount in the spec", || {
        let oc = mixed_oc.clone()?;
        let mut wrong = mixed.clone();
        wrong["inputs"][1]["amount_sat"] = json!(60_001);
        Ok(!verify(
            oc.raw.as_deref().unwrap_or(""),
            Some(&wrong.to_string()),
            net,
        )?
        .valid)
    });

    // --- fee targeting never lands below the requested rate -----------------
    for rate in [1.0, 7.0, 57.0, 300.0, 1000.0] {
        for sweep in [false, true] {
            let mut spec = json!({
                "network": "mainnet", "key": kh, "fee_rate": rate,
                "inputs": [
                    {"txid": txid('a'), "vout": 0, "amount_sat": 900_000, "address": ad.p2wpkh},
                    {"txid": txid('b'), "vout": 1, "amount_sat": 800_000, "address": ad.p2tr},
                    {"txid": txid('c'), "vout": 2, "amount_sat": 700_000, "address": ad.p2pkh}],
                "outputs": [{"address": ad.p2tr, "amount_sat": if sweep { json!("all") } else { json!(500_000) }}]});
            if !sweep {
                spec["change_address"] = json!(ad.p2wpkh);
            }
            t.run(
                format!(
                    "fee rate {rate} {} on target",
                    if sweep { "sweep" } else { "change" }
                ),
                || {
                    let oc = build(&spec.to_string(), true)?;
                    Ok(oc.fee_rate >= rate && oc.fee_rate <= rate * 1.05)
                },
            );
        }
    }

    // --- dust thresholds match Bitcoin Core ---------------------------------
    for (name, addr, want) in [
        ("p2pkh", &ad.p2pkh, 546u64),
        ("p2sh", &ad.p2sh_p2wpkh, 540),
        ("p2wpkh", &ad.p2wpkh, 294),
        ("p2tr", &ad.p2tr, 330),
    ] {
        t.eq(
            &format!("dust threshold {name}"),
            parse_address(addr, net).map(|s| dust_threshold(&s)),
            Ok(want),
        );
    }

    // --- refusals ------------------------------------------------------------
    let one_in = |amount: u64| json!([{"txid": txid('e'), "vout": 0, "amount_sat": amount, "address": ad.p2wpkh}]);
    t.refuses("refuses a key that does not match the input", || {
        built(json!({"key": "2", "inputs": one_in(5000), "fee_rate": 1,
                     "outputs": [{"address": ad.p2wpkh, "amount_sat": "all"}]}))
    });
    t.refuses("refuses to overspend", || {
        built(json!({"key": kh, "inputs": one_in(1000), "outputs": [{"address": ad.p2wpkh, "amount_sat": 2000}]}))
    });
    t.refuses("refuses an absurd fee", || {
        built(json!({"key": kh, "inputs": one_in(10_000_000), "outputs": [{"address": ad.p2wpkh, "amount_sat": 1000}]}))
    });
    t.refuses("refuses a misspelled spec field", || {
        built(
            json!({"key": kh, "inputs": one_in(100_000), "fee_rate": 2, "change_adress": ad.p2wpkh,
                     "outputs": [{"address": ad.p2wpkh, "amount_sat": 1000}]}),
        )
    });
    t.run(
        "a spec with no key yields an unsigned PSBT, not a transaction",
        || {
            let oc = built(json!({"inputs": one_in(100_000), "fee_rate": 2,
                              "outputs": [{"address": ad.p2wpkh, "amount_sat": "all"}]}))?;
            Ok(!oc.complete && oc.raw.is_none() && oc.psbt.is_some())
        },
    );

    // --- multisig -------------------------------------------------------------
    t.run("BIP67 sorted 2-of-2 vector", || {
        let ms = Multisig::new(
            2,
            vec![
                parse_pubkey("02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8")?,
                parse_pubkey("02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f")?,
            ],
            true,
        )?;
        Ok(hx(ms.script().as_bytes())
            == "522102fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f\
                2102ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f852ae"
            && crate::script::script_address(&ms.script_pubkey(Wrap::P2sh)?, net).as_deref()
                == Some("39bgKC7RFbpoCRbtD5KEdkYKtNyhpsNa3Z")
            && Multisig::parse(&ms.script()) == Some(ms))
    });
    t.refuses("multisig rejects threshold > keys", || {
        Multisig::new(3, vec![parse_pubkey(&pub_hex(&k))?], true)
    });
    t.refuses("multisig rejects a duplicated key", || {
        Multisig::new(
            1,
            vec![parse_pubkey(&pub_hex(&k))?, parse_pubkey(&pub_hex(&k))?],
            true,
        )
    });

    let cosigners = [key(0x1001), key(0x1002), key(0x1003)];
    let pubs: Vec<String> = cosigners.iter().map(pub_hex).collect();
    let khex = |i: usize| hx(&cosigners[i].secret_bytes());
    // Legacy P2SH carries no proof of its amount unless the previous
    // transaction is supplied; these flow tests accept that explicitly.
    let trusting = Policy {
        trust_amounts: true,
        ..Policy::default()
    };
    for wrap in Wrap::ALL {
        let w = wrap.name();
        let spec = |keys: Value| {
            json!({
            "network": "mainnet", "keys": keys, "fee_rate": 9,
            "inputs": [{"txid": txid('f'), "vout": 3, "amount_sat": 400_000,
                        "multisig": {"threshold": 2, "pubkeys": pubs, "type": w}}],
            "outputs": [{"address": ad.p2wpkh, "amount_sat": 150_000}],
            "change_address": ad.p2tr})
        };
        t.run(
            format!("{w} 2-of-3: one key gives a PSBT, never a transaction"),
            || {
                let oc = built(spec(json!([khex(0)])))?;
                Ok(!oc.complete
                    && oc.raw.is_none()
                    && oc.signatures[0].have == 1
                    && oc.signatures[0].need == 2)
            },
        );
        t.run(
            format!("{w} 2-of-3: second signer completes it, both verifiers pass"),
            || {
                let half = built(spec(json!([khex(2)])))?;
                let mut psbt = parse_psbt(half.psbt.as_deref().unwrap_or(""))?;
                let oc = sign_and_report(&mut psbt, &[cosigners[0]], net, &trusting)?;
                let direct = built(spec(json!([khex(0), khex(2)])))?;
                Ok(oc.complete
                    && oc.verify.iter().all(|c| c.ok)
                    && oc.consensus.as_deref() == Some("ok")
                    && oc.fee_rate >= 9.0
                    && oc.fee_rate <= 9.3
                    && oc.raw == direct.raw
                    && verify(
                        oc.raw.as_deref().unwrap_or(""),
                        Some(&spec(json!([])).to_string()),
                        net,
                    )?
                    .valid)
            },
        );
        t.run(
            format!("{w} 2-of-3: PSBTs signed apart combine into the same transaction"),
            || {
                let a = parse_psbt(built(spec(json!([khex(1)])))?.psbt.as_deref().unwrap_or(""))?;
                let b = parse_psbt(built(spec(json!([khex(2)])))?.psbt.as_deref().unwrap_or(""))?;
                let oc = combine(vec![a, b], net, false)?;
                Ok(oc.complete && oc.raw == built(spec(json!([khex(1), khex(2)])))?.raw)
            },
        );
        t.refuses(
            &format!("{w} 2-of-3: refuses a key that is not a cosigner"),
            || {
                let mut psbt =
                    parse_psbt(built(spec(json!([khex(0)])))?.psbt.as_deref().unwrap_or(""))?;
                sign_and_report(&mut psbt, &[key(0x9999)], net, &trusting)
            },
        );
        t.refuses(
            &format!("{w} 2-of-3: a forged cosigner signature is detected"),
            || {
                let mut psbt =
                    parse_psbt(built(spec(json!([khex(0)])))?.psbt.as_deref().unwrap_or(""))?;
                let (pk, sig) = psbt.inputs[0]
                    .partial_sigs
                    .iter()
                    .next()
                    .map(|(p, s)| (*p, *s))
                    .unwrap();
                let other = cosigners
                    .iter()
                    .map(|c| bitcoin::PublicKey::new(c.public_key(secp())))
                    .find(|p| *p != pk)
                    .unwrap();
                psbt.inputs[0].partial_sigs.insert(other, sig); // key 0's signature filed under another key
                crate::sign::outcome(&psbt, net, vec![], false)
            },
        );
    }
    t.run(
        "multisig address is inferred from the spec's address",
        || {
            let ms = Multisig::new(
                2,
                pubs.iter()
                    .map(|p| parse_pubkey(p))
                    .collect::<Result<_>>()?,
                true,
            )?;
            let addr =
                crate::script::script_address(&ms.script_pubkey(Wrap::P2shP2wsh)?, net).unwrap();
            let oc = built(json!({"keys": [khex(0), khex(1)], "fee_rate": 3,
            "inputs": [{"txid": txid('f'), "vout": 0, "amount_sat": 90_000, "address": addr,
                        "multisig": {"threshold": 2, "pubkeys": [pubs[2], pubs[0], pubs[1]]}}],
            "outputs": [{"address": ad.p2wpkh, "amount_sat": "all"}]}))?;
            Ok(oc.complete && oc.signatures[0].kind == "p2sh-p2wsh 2-of-3 multisig")
        },
    );
    t.refuses("multisig refuses keys that do not produce the address", || {
        built(json!({"keys": [khex(0)], "fee_rate": 3,
            "inputs": [{"txid": txid('f'), "vout": 0, "amount_sat": 90_000, "address": ad.p2sh_p2wpkh,
                        "multisig": {"threshold": 2, "pubkeys": pubs}}],
            "outputs": [{"address": ad.p2wpkh, "amount_sat": "all"}]}))
    });

    // --- a PSBT from someone else is not trusted ---------------------------
    let strict = Policy::default();
    let ms_spec = |w: &str, extra: Value| {
        let mut input = json!({"txid": txid('f'), "vout": 3, "amount_sat": 400_000,
                               "multisig": {"threshold": 2, "pubkeys": pubs, "type": w}});
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        json!({"network": "mainnet", "keys": [khex(0)], "fee_rate": 9, "inputs": [input],
               "outputs": [{"address": ad.p2wpkh, "amount_sat": 150_000}], "change_address": ad.p2tr})
    };
    let half = |spec: Value| -> Result<bitcoin::psbt::Psbt> {
        parse_psbt(built(spec)?.psbt.as_deref().unwrap_or(""))
    };
    for (name, ty) in [("NONE", 2u32), ("SINGLE", 3), ("ALL|ANYONECANPAY", 0x81)] {
        t.refuses(
            &format!("sign refuses a PSBT asking for SIGHASH_{name}"),
            || {
                let mut psbt = half(ms_spec("p2wsh", json!({})))?;
                psbt.inputs[0].sighash_type = Some(bitcoin::psbt::PsbtSighashType::from_u32(ty));
                // amounts trusted, so that the sighash is the only reason to refuse
                sign_and_report(&mut psbt, &[cosigners[1]], net, &trusting)
            },
        );
    }
    t.run(
        "a non-ALL sighash is signed only on request, and then flagged",
        || {
            let mut psbt = half(ms_spec("p2wsh", json!({})))?;
            psbt.inputs[0].sighash_type = Some(bitcoin::psbt::PsbtSighashType::from_u32(0x81));
            let allow = Policy {
                allow_sighash: true,
                ..trusting
            };
            let oc = sign_and_report(&mut psbt, &[cosigners[1]], net, &allow)?;
            Ok(oc
                .notes
                .iter()
                .any(|n| n.starts_with("WARNING") && n.contains("0x81")))
        },
    );
    t.refuses("never signs SIGHASH_SINGLE without a matching output (replayable signature)", || {
        // two legacy inputs, one output: input 1 would sign the constant hash "1"
        let spec = json!({"key": kh, "inputs": [
            {"txid": txid('a'), "vout": 0, "amount_sat": 50_000, "address": ad.p2pkh},
            {"txid": txid('b'), "vout": 0, "amount_sat": 50_000, "address": ad.p2pkh, "sighash": 3}],
            "outputs": [{"address": ad.p2wpkh, "amount_sat": 99_000}]});
        built(spec)
    });
    t.refuses(
        "sign refuses a legacy input whose amount nothing proves",
        || {
            let mut psbt = half(ms_spec("p2sh", json!({})))?;
            sign_and_report(&mut psbt, &[cosigners[1]], net, &strict)
        },
    );
    t.run(
        "a legacy input is signed without override when prev_tx proves the amount",
        || {
            let ms = Multisig::new(
                2,
                pubs.iter()
                    .map(|p| parse_pubkey(p))
                    .collect::<Result<_>>()?,
                true,
            )?;
            let prev = bitcoin::Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![bitcoin::TxIn::default()],
                output: vec![TxOut {
                    value: Amount::from_sat(400_000),
                    script_pubkey: ms.script_pubkey(Wrap::P2sh)?,
                }],
            };
            let mut spec = ms_spec(
                "p2sh",
                json!({"prev_tx": bitcoin::consensus::encode::serialize_hex(&prev)}),
            );
            spec["inputs"][0]["txid"] = json!(prev.compute_txid().to_string());
            spec["inputs"][0]["vout"] = json!(0);
            let mut lying = spec.clone();
            lying["inputs"][0]["amount_sat"] = json!(1_000);
            let mut psbt = half(spec)?;
            let oc = sign_and_report(&mut psbt, &[cosigners[1]], net, &strict)?;
            Ok(oc.complete && oc.signatures[0].amount_verified && built(lying).is_err())
        },
    );
    t.refuses(
        "sign refuses a segwit v0 input whose amount nothing proves",
        || {
            let mut psbt = half(ms_spec("p2wsh", json!({})))?;
            sign_and_report(&mut psbt, &[cosigners[1]], net, &strict)
        },
    );
    t.run(
        "a segwit v0 input is signed without override when prev_tx proves the amount",
        || {
            let ms = Multisig::new(
                2,
                pubs.iter()
                    .map(|p| parse_pubkey(p))
                    .collect::<Result<_>>()?,
                true,
            )?;
            let prev = bitcoin::Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![bitcoin::TxIn::default()],
                output: vec![TxOut {
                    value: Amount::from_sat(400_000),
                    script_pubkey: ms.script_pubkey(Wrap::P2wsh)?,
                }],
            };
            let mut spec = ms_spec(
                "p2wsh",
                json!({"prev_tx": bitcoin::consensus::encode::serialize_hex(&prev)}),
            );
            spec["inputs"][0]["txid"] = json!(prev.compute_txid().to_string());
            spec["inputs"][0]["vout"] = json!(0);
            let mut psbt = half(spec)?;
            let oc = sign_and_report(&mut psbt, &[cosigners[1]], net, &strict)?;
            Ok(oc.complete && oc.signatures[0].amount_verified && oc.notes.is_empty())
        },
    );
    t.run(
        "an unproven segwit v0 amount is flagged when signed on trust",
        || {
            let mut psbt = half(ms_spec("p2wsh", json!({})))?;
            let oc = sign_and_report(&mut psbt, &[cosigners[1]], net, &trusting)?;
            Ok(!oc.signatures[0].amount_verified
                && oc.notes.iter().any(|n| n.contains("taken on trust")))
        },
    );
    t.run("a taproot input needs no proof of its amount", || {
        let oc = built(json!({"fee_rate": 2,
            "inputs": [{"txid": txid('a'), "vout": 0, "amount_sat": 50_000, "address": ad.p2tr}],
            "outputs": [{"address": ad.p2wpkh, "amount_sat": "all"}]}))?;
        let mut psbt = parse_psbt(oc.psbt.as_deref().unwrap_or(""))?;
        let oc = sign_and_report(&mut psbt, &[k], net, &strict)?;
        Ok(oc.complete && oc.notes.is_empty())
    });
    t.run(
        "decode does not call a PSBT complete on a claimed final signature",
        || {
            let mut psbt = half(ms_spec("p2wsh", json!({})))?;
            psbt.inputs[0].final_script_witness = Some(bitcoin::Witness::from_slice(&[[1u8; 72]]));
            let d = decode(&psbt.to_string(), net)?;
            Ok(d["complete"] == false
                && d["warnings"].as_array().is_some_and(|w| {
                    w.iter()
                        .any(|x| x.as_str().is_some_and(|s| s.contains("do NOT verify")))
                }))
        },
    );
    t.refuses("decode refuses output amounts that would overflow", || {
        let out = TxOut {
            value: Amount::from_sat(u64::MAX),
            script_pubkey: ScriptBuf::new(),
        };
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![out.clone(), out],
        };
        decode(&bitcoin::consensus::encode::serialize_hex(&tx), net)
    });
    t.run(
        "a private key in the wrong spec field is never echoed",
        || {
            let wif = key_info(&k, net)?.wif_compressed;
            let wrong_type =
                built(json!({"inputs": [{"txid": txid('a'), "vout": wif, "amount_sat": 1}]}));
            let as_address = built(json!({"inputs": [
            {"txid": txid('a'), "vout": 0, "amount_sat": 1, "address": wif}]}));
            let as_network = built(json!({"network": kh, "inputs": one_in(5000)}));
            Ok([wrong_type, as_address, as_network]
                .iter()
                .all(|r| matches!(r, Err(e) if !e.0.contains(&wif) && !e.0.contains(&kh))))
        },
    );
    t.ok(
        "a spec that names a key twice is refused",
        matches!(build(r#"{"inputs": [], "change_address": "a", "change_address": "b"}"#, false),
                 Err(e) if e.0.contains("twice"))
            && matches!(build(r#"{"_c": 1, "_c": 2, "inputs": []}"#, false),
                 Err(e) if e.0.contains("no inputs")),
    );
    t.run("a 32-byte key is inspected as taproot only", || {
        let v = crate::keys::inspect(&pub_hex(&k)[2..], net)?;
        Ok(v["p2tr"] == json!(ad.p2tr) && v.get("p2wpkh").is_none() && v.get("p2pkh").is_none())
    });
    t.run("build warns that a legacy amount is unverified", || {
        let oc = built(json!({"key": kh, "fee_rate": 2,
            "inputs": [{"txid": txid('a'), "vout": 0, "amount_sat": 50_000, "address": ad.p2pkh}],
            "outputs": [{"address": ad.p2wpkh, "amount_sat": "all"}]}))?;
        Ok(
            oc.notes.iter().any(|n| n.contains("NOT verified"))
                && !oc.signatures[0].amount_verified,
        )
    });
    t.refuses("sign refuses an absurd fee", || {
        let mut spec = ms_spec("p2wsh", json!({}));
        spec["inputs"][0]["amount_sat"] = json!(900_000_000u64);
        spec.as_object_mut().unwrap().remove("change_address");
        spec["keys"] = json!([]);
        let mut psbt = parse_psbt(
            build(&spec.to_string(), true)?
                .psbt
                .as_deref()
                .unwrap_or(""),
        )?;
        sign_and_report(&mut psbt, &[cosigners[1]], net, &strict)
    });
    t.refuses(
        "refuses a fee that is small in percent but absurd in rate",
        || {
            built(json!({"key": kh, "inputs": one_in(1_000_000_000),
                     "outputs": [{"address": ad.p2wpkh, "amount_sat": 600_000_000}]}))
        },
    );
    t.refuses("refuses amounts that would overflow", || {
        built(json!({"key": kh, "fee_rate": 1, "inputs": [
            {"txid": txid('a'), "vout": 0, "amount_sat": u64::MAX, "address": ad.p2wpkh},
            {"txid": txid('b'), "vout": 0, "amount_sat": 2001, "address": ad.p2wpkh}],
            "outputs": [{"address": ad.p2wpkh, "amount_sat": 1000}]}))
    });
    t.refuses("verify refuses a transaction with no inputs", || {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx)?;
        verify(&psbt.to_string(), None, net)
    });
    t.refuses("refuses an input listed twice", || {
        built(
            json!({"key": kh, "fee_rate": 1, "inputs": [one_in(5000)[0], one_in(5000)[0]],
                     "outputs": [{"address": ad.p2wpkh, "amount_sat": "all"}]}),
        )
    });
    t.refuses("refuses script_pubkey and address that disagree", || {
        built(json!({"key": kh, "inputs": one_in(100_000), "outputs": [
            {"address": ad.p2wpkh, "script_pubkey": "0014".to_string() + &"11".repeat(20), "amount_sat": 99_000}]}))
    });
    t.refuses("multisig refuses an x-only (32-byte) public key", || {
        crate::script::multisig_info(1, &[pubs[0][2..].to_string()], "p2wsh", true, net)
    });
    t.run(
        "verify reports what the transaction pays, and its fee",
        || {
            let oc = mixed_oc.clone()?;
            let r = verify(
                oc.raw.as_deref().unwrap_or(""),
                Some(&mixed.to_string()),
                net,
            )?;
            Ok(r.valid
                && r.fee == oc.fee
                && r.outputs.len() == oc.outputs.len()
                && r.warnings.iter().any(|w| w.contains("on trust")))
        },
    );

    // --- message signing -------------------------------------------------------
    for (name, addr) in [
        ("p2pkh", &ad.p2pkh),
        ("p2pkh uncompressed", &ad.p2pkh_uncomp),
        ("p2sh-p2wpkh", &ad.p2sh_p2wpkh),
        ("p2wpkh", &ad.p2wpkh),
    ] {
        t.run(format!("message sign + verify {name}"), || {
            let s = sign_message(&k, "btc-keytool selftest", Some(addr), net)?;
            Ok(verify_message(addr, &s.signature, "btc-keytool selftest")?
                && !verify_message(addr, &s.signature, "btc-keytool selftesT")?
                && !verify_message(&info.addresses.p2pkh, &s.signature, "btc-keytool selftest")?)
        });
    }
    t.refuses("message signing refuses an address of another key", || {
        sign_message(&k, "x", Some(&info.addresses.p2pkh), net)
    });
    t.0
}

#[cfg(test)]
mod tests {
    #[test]
    fn selftest_passes() {
        let failed: Vec<_> = super::run().into_iter().filter(|c| !c.ok).collect();
        assert!(failed.is_empty(), "{failed:#?}");
    }
}
