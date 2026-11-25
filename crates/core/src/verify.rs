//! Signature verification of signed transactions, done two independent ways:
//!
//! 1. `verify_tx` - our own per-input check, which explains *what* was signed
//!    by *whom* and also enforces the low-S relay rule.
//! 2. `consensus_verify` - Bitcoin Core's script interpreter
//!    (libbitcoinconsensus), the same code that decides validity on mainnet.

use bitcoin::blockdata::script::Instruction;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{ecdsa, taproot, PublicKey, Script, ScriptBuf, Transaction, TxOut, XOnlyPublicKey};
use serde::Serialize;

use crate::script::{classify_input, script_type, Kind};
use crate::sign::{ecdsa_sighash, key_matches};
use crate::{secp, Result};

#[derive(Debug, Clone, Serialize)]
pub struct InputCheck {
    pub index: usize,
    #[serde(rename = "type")]
    pub kind: String,
    pub ok: bool,
    pub note: String,
}

/// Check every input's signature(s) against the outputs being spent.
pub fn verify_tx(tx: &Transaction, prevouts: &[TxOut]) -> Vec<InputCheck> {
    (0..tx.input.len())
        .map(|index| {
            if prevouts.len() != tx.input.len() {
                let note = format!(
                    "need the spent output of every input, got {} of {}",
                    prevouts.len(),
                    tx.input.len()
                );
                return InputCheck {
                    index,
                    kind: "?".into(),
                    ok: false,
                    note,
                };
            }
            match check_input(tx, index, prevouts) {
                Ok((kind, note)) => InputCheck {
                    index,
                    kind,
                    ok: true,
                    note,
                },
                Err(e) => InputCheck {
                    index,
                    kind: script_type(&prevouts[index].script_pubkey),
                    ok: false,
                    note: e.0,
                },
            }
        })
        .collect()
}

fn pushes(script: &Script) -> Result<Vec<Vec<u8>>> {
    script
        .instructions()
        .map(|i| match i {
            Ok(Instruction::PushBytes(b)) => Ok(b.as_bytes().to_vec()),
            _ => Err(err!("scriptSig is not push-only")),
        })
        .collect()
}

/// Verify one ECDSA signature (DER + sighash byte). Returns the sighash byte.
fn check_ecdsa(
    tx: &Transaction,
    i: usize,
    kind: &Kind,
    utxo: &TxOut,
    redeem: Option<&Script>,
    sig: &[u8],
    pk: &PublicKey,
) -> Result<u8> {
    let parsed = ecdsa::Signature::from_slice(sig).map_err(|e| err!("bad signature: {e}"))?;
    let hash_type = *sig.last().expect("from_slice rejects empty");
    let mut low = parsed.signature;
    low.normalize_s();
    if low != parsed.signature {
        bail!("signature is HIGH-S (non-standard, will not relay)");
    }
    let msg = ecdsa_sighash(tx, i, kind, utxo, redeem, hash_type as u32)?;
    secp()
        .verify_ecdsa(&msg, &parsed.signature, &pk.inner)
        .map_err(|_| err!("ECDSA signature does not verify"))?;
    Ok(hash_type)
}

fn check_input(tx: &Transaction, i: usize, prevouts: &[TxOut]) -> Result<(String, String)> {
    let utxo = &prevouts[i];
    let spk = &utxo.script_pubkey;
    let txin = &tx.input[i];
    let wit: Vec<&[u8]> = txin.witness.iter().collect();

    if spk.is_p2tr() {
        if wit.len() != 1 || !txin.script_sig.is_empty() {
            bail!("expected a 1-element key-path witness");
        }
        let sig = taproot::Signature::from_slice(wit[0]).map_err(|e| err!("bad signature: {e}"))?;
        let digest = SighashCache::new(tx).taproot_key_spend_signature_hash(
            i,
            &Prevouts::All(prevouts),
            sig.sighash_type,
        )?;
        let key = XOnlyPublicKey::from_slice(&spk.as_bytes()[2..])?;
        secp()
            .verify_schnorr(
                &sig.signature,
                &Message::from_digest(digest.to_byte_array()),
                &key,
            )
            .map_err(|_| err!("schnorr signature does not verify"))?;
        return Ok((
            "p2tr".into(),
            format!("schnorr key-path, sighash 0x{:02x}", sig.sighash_type as u8),
        ));
    }

    // Work out what is being spent, and pull the signatures out of the input.
    let ss = pushes(&txin.script_sig)?;
    let mut redeem: Option<ScriptBuf> = None;
    let mut witness_script: Option<ScriptBuf> = None;
    if spk.is_p2sh() {
        redeem = Some(ScriptBuf::from(
            ss.last().cloned().ok_or_else(|| err!("empty scriptSig"))?,
        ));
    }
    let segwit = spk.is_p2wsh() || redeem.as_ref().is_some_and(|r| r.is_p2wsh());
    if segwit {
        witness_script = Some(ScriptBuf::from(
            wit.last().ok_or_else(|| err!("empty witness"))?.to_vec(),
        ));
    }
    let kind = classify_input(spk, redeem.as_deref(), witness_script.as_deref())?;
    let redeem = redeem.as_deref();

    let via_witness = matches!(kind, Kind::P2wpkh | Kind::P2shP2wpkh) || segwit;
    let expected_script_sig = match (&kind, spk.is_p2sh()) {
        (Kind::P2pkh, _) => 2,
        (Kind::P2pk(_), _) => 1,
        (Kind::Multi { ms, .. }, true) if !segwit => ms.threshold + 2,
        (_, true) => 1,
        _ => 0,
    };
    if ss.len() != expected_script_sig {
        bail!(
            "scriptSig has {} elements, expected {expected_script_sig}",
            ss.len()
        );
    }
    if !via_witness && !wit.is_empty() {
        bail!("unexpected witness data on a legacy input");
    }

    if let Kind::Multi { ms, .. } = &kind {
        let sigs: Vec<&[u8]> = if segwit {
            if wit.len() != ms.threshold + 2 || !wit[0].is_empty() {
                bail!(
                    "witness must be: empty dummy, {} signatures, script",
                    ms.threshold
                );
            }
            wit[1..wit.len() - 1].to_vec()
        } else {
            if !ss[0].is_empty() {
                bail!("multisig dummy element must be empty (NULLDUMMY)");
            }
            ss[1..ss.len() - 1].iter().map(|s| s.as_slice()).collect()
        };
        // CHECKMULTISIG semantics: signatures must appear in key order.
        let mut next_key = 0;
        let mut signers = Vec::new();
        let mut hash_types = Vec::new();
        for sig in sigs {
            let mut last_err = err!("signature matches no remaining key");
            let mut matched = false;
            while next_key < ms.pubkeys.len() && !matched {
                match check_ecdsa(tx, i, &kind, utxo, redeem, sig, &ms.pubkeys[next_key]) {
                    Ok(ht) => {
                        signers.push(format!("#{}", next_key + 1));
                        hash_types.push(format!("0x{ht:02x}"));
                        matched = true;
                    }
                    Err(e) => last_err = e,
                }
                next_key += 1;
            }
            if !matched {
                return Err(last_err);
            }
        }
        hash_types.dedup();
        return Ok((
            kind.name(),
            format!(
                "ecdsa, signed by keys {}, sighash {}",
                signers.join(" "),
                hash_types.join(" ")
            ),
        ));
    }

    let (sig, pk_bytes): (&[u8], Vec<u8>) = match &kind {
        Kind::P2pk(pk) => (&ss[0], pk.to_bytes()),
        Kind::P2pkh => (&ss[0], ss[1].clone()),
        _ => {
            if wit.len() != 2 {
                bail!(
                    "witness has {} elements, expected signature and pubkey",
                    wit.len()
                );
            }
            (wit[0], wit[1].to_vec())
        }
    };
    let pk = PublicKey::from_slice(&pk_bytes).map_err(|e| err!("bad public key: {e}"))?;
    if !key_matches(&kind, utxo, redeem, &pk) {
        bail!("the public key supplied does not match the output being spent");
    }
    let ht = check_ecdsa(tx, i, &kind, utxo, redeem, sig, &pk)?;
    Ok((kind.name(), format!("ecdsa, sighash 0x{ht:02x}")))
}

/// Run every input through Bitcoin Core's script interpreter with all
/// consensus rules up to and including taproot.
pub fn consensus_verify(tx: &Transaction, prevouts: &[TxOut]) -> Result<()> {
    if prevouts.len() != tx.input.len() {
        bail!("need the spent output of every input");
    }
    let raw = bitcoin::consensus::serialize(tx);
    let spent: Vec<bitcoinconsensus::Utxo> = prevouts
        .iter()
        .map(|o| bitcoinconsensus::Utxo {
            script_pubkey: o.script_pubkey.as_bytes().as_ptr(),
            script_pubkey_len: o.script_pubkey.len() as u32,
            value: o.value.to_sat() as i64,
        })
        .collect();
    for (i, o) in prevouts.iter().enumerate() {
        bitcoinconsensus::verify(
            o.script_pubkey.as_bytes(),
            o.value.to_sat(),
            &raw,
            Some(&spent),
            i,
        )
        .map_err(|e| err!("input {i} rejected by Bitcoin Core's script interpreter: {e:?}"))?;
    }
    Ok(())
}
