//! PSBT signing, signature bookkeeping and finalisation.
//!
//! Every signature is verified the moment it is made, every signature found
//! in a PSBT is verified before it is counted, and a finished transaction is
//! verified twice more (see `verify`) before it is returned.

use bitcoin::blockdata::script::{Builder, PushBytes};
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{ecdsa, taproot, Network, PublicKey, Script, ScriptBuf, Transaction, TxOut, Witness};
use serde::Serialize;

use crate::script::{classify_input, dust_threshold, script_address, script_type, Kind, Wrap};
use crate::verify::{consensus_verify, verify_tx, InputCheck};
use crate::{hx, network_name, secp, Result};

/// The output an input spends, from the PSBT's UTXO fields.
pub fn utxo(psbt: &Psbt, i: usize) -> Result<TxOut> {
    let inp = &psbt.inputs[i];
    if let Some(prev) = &inp.non_witness_utxo {
        let op = psbt.unsigned_tx.input[i].previous_output;
        if prev.compute_txid() != op.txid {
            bail!("input {i}: the previous transaction supplied does not match its txid");
        }
        let out = prev
            .output
            .get(op.vout as usize)
            .ok_or_else(|| err!("input {i}: previous transaction has no output {}", op.vout))?;
        if inp.witness_utxo.as_ref().is_some_and(|w| w != out) {
            bail!("input {i}: amount/script disagree with the previous transaction supplied");
        }
        return Ok(out.clone());
    }
    inp.witness_utxo
        .clone()
        .ok_or_else(|| err!("input {i}: the PSBT carries no amount/script for this input"))
}

pub fn utxos(psbt: &Psbt) -> Result<Vec<TxOut>> {
    (0..psbt.inputs.len()).map(|i| utxo(psbt, i)).collect()
}

pub fn kind_of(psbt: &Psbt, i: usize) -> Result<Kind> {
    let inp = &psbt.inputs[i];
    classify_input(
        &utxo(psbt, i)?.script_pubkey,
        inp.redeem_script.as_deref(),
        inp.witness_script.as_deref(),
    )
    .map_err(|e| err!("input {i}: {e}"))
}

/// The digest an ECDSA signature on this input must commit to.
pub fn ecdsa_sighash(
    tx: &Transaction,
    i: usize,
    kind: &Kind,
    utxo: &TxOut,
    redeem: Option<&Script>,
    hash_type: u32,
) -> Result<Message> {
    let mut cache = SighashCache::new(tx);
    let v0 = EcdsaSighashType::from_consensus(hash_type);
    let digest = match kind {
        Kind::P2pkh | Kind::P2pk(_) => cache
            .legacy_signature_hash(i, &utxo.script_pubkey, hash_type)?
            .to_byte_array(),
        Kind::P2wpkh => cache
            .p2wpkh_signature_hash(i, &utxo.script_pubkey, utxo.value, v0)?
            .to_byte_array(),
        Kind::P2shP2wpkh => {
            let redeem = redeem.ok_or_else(|| err!("input {i}: missing redeem script"))?;
            cache
                .p2wpkh_signature_hash(i, redeem, utxo.value, v0)?
                .to_byte_array()
        }
        Kind::Multi {
            ms,
            wrap: Wrap::P2sh,
        } => cache
            .legacy_signature_hash(i, &ms.script(), hash_type)?
            .to_byte_array(),
        Kind::Multi { ms, .. } => cache
            .p2wsh_signature_hash(i, &ms.script(), utxo.value, v0)?
            .to_byte_array(),
        Kind::P2tr | Kind::P2shUnknown => bail!("input {i}: not an ECDSA input"),
    };
    Ok(Message::from_digest(digest))
}

/// Could `pk` be one of the keys that unlocks this output?
pub fn key_matches(kind: &Kind, utxo: &TxOut, redeem: Option<&Script>, pk: &PublicKey) -> bool {
    let wpkh = |script: &Script| {
        pk.wpubkey_hash()
            .map(|h| ScriptBuf::new_p2wpkh(&h) == *script)
            .unwrap_or(false)
    };
    match kind {
        Kind::P2pk(k) => k == pk,
        Kind::P2pkh => ScriptBuf::new_p2pkh(&pk.pubkey_hash()) == utxo.script_pubkey,
        Kind::P2wpkh => wpkh(&utxo.script_pubkey),
        Kind::P2shP2wpkh => redeem.is_some_and(wpkh),
        Kind::Multi { ms, .. } => ms.pubkeys.contains(pk),
        Kind::P2tr | Kind::P2shUnknown => false,
    }
}

fn both_pubkeys(sk: &SecretKey) -> [PublicKey; 2] {
    let pk = sk.public_key(secp());
    [PublicKey::new(pk), PublicKey::new_uncompressed(pk)]
}

/// Sign input `i` with `sk` if that key can unlock it. Returns whether this
/// key now has a signature on the input.
pub fn sign_input(psbt: &mut Psbt, i: usize, sk: &SecretKey) -> Result<bool> {
    let secp = secp();
    if psbt.inputs[i].final_script_sig.is_some() || psbt.inputs[i].final_script_witness.is_some() {
        return Ok(false);
    }
    let out = utxo(psbt, i)?;
    let mut kind = kind_of(psbt, i)?;
    let [pk_c, pk_u] = both_pubkeys(sk);

    if kind == Kind::P2shUnknown {
        // The only single-key P2SH form: P2WPKH nested in P2SH.
        let redeem = ScriptBuf::new_p2wpkh(&pk_c.wpubkey_hash()?);
        if ScriptBuf::new_p2sh(&redeem.script_hash()) != out.script_pubkey {
            return Ok(false);
        }
        psbt.inputs[i].redeem_script = Some(redeem);
        kind = Kind::P2shP2wpkh;
    }

    if kind == Kind::P2tr {
        let keypair = Keypair::from_secret_key(secp, sk);
        let (internal, _) = keypair.x_only_public_key();
        if ScriptBuf::new_p2tr(secp, internal, None) != out.script_pubkey {
            return Ok(false);
        }
        let ty = match psbt.inputs[i].sighash_type {
            Some(t) => t.taproot_hash_ty().map_err(|e| err!("input {i}: {e}"))?,
            None => TapSighashType::Default,
        };
        let prevouts = utxos(psbt)?;
        let digest = SighashCache::new(&psbt.unsigned_tx).taproot_key_spend_signature_hash(
            i,
            &Prevouts::All(&prevouts),
            ty,
        )?;
        let msg = Message::from_digest(digest.to_byte_array());
        let tweaked = keypair.tap_tweak(secp, None).to_keypair();
        let signature = secp.sign_schnorr_no_aux_rand(&msg, &tweaked);
        secp.verify_schnorr(&signature, &msg, &tweaked.x_only_public_key().0)
            .map_err(|_| err!("input {i}: schnorr self-verification failed"))?;
        psbt.inputs[i].tap_internal_key = Some(internal);
        psbt.inputs[i].tap_key_sig = Some(taproot::Signature {
            signature,
            sighash_type: ty,
        });
        return Ok(true);
    }

    let redeem = psbt.inputs[i].redeem_script.clone();
    let Some(pk) = [pk_c, pk_u]
        .into_iter()
        .find(|p| key_matches(&kind, &out, redeem.as_deref(), p))
    else {
        return Ok(false);
    };
    let ty = match psbt.inputs[i].sighash_type {
        Some(t) => t.ecdsa_hash_ty().map_err(|e| err!("input {i}: {e}"))?,
        None => EcdsaSighashType::All,
    };
    let msg = ecdsa_sighash(
        &psbt.unsigned_tx,
        i,
        &kind,
        &out,
        redeem.as_deref(),
        ty.to_u32(),
    )?;
    let signature = secp.sign_ecdsa(&msg, sk); // RFC 6979, low-S
    secp.verify_ecdsa(&msg, &signature, &pk.inner)
        .map_err(|_| err!("input {i}: ECDSA self-verification failed"))?;
    psbt.inputs[i].partial_sigs.insert(
        pk,
        ecdsa::Signature {
            signature,
            sighash_type: ty,
        },
    );
    Ok(true)
}

/// Sign every input each key can. Returns, per key, how many inputs it signed.
pub fn sign_psbt(psbt: &mut Psbt, keys: &[SecretKey]) -> Result<Vec<usize>> {
    let mut counts = vec![0; keys.len()];
    for i in 0..psbt.inputs.len() {
        for (n, sk) in keys.iter().enumerate() {
            if sign_input(psbt, i, sk)? {
                counts[n] += 1;
            }
        }
    }
    Ok(counts)
}

/// The valid ECDSA signatures present on an input, in script key order.
/// A signature that does not verify is an error, never silently dropped.
fn valid_sigs(
    psbt: &Psbt,
    i: usize,
    kind: &Kind,
    out: &TxOut,
) -> Result<Vec<(PublicKey, ecdsa::Signature)>> {
    let inp = &psbt.inputs[i];
    let redeem = inp.redeem_script.as_deref();
    let mut found = Vec::new();
    for (pk, sig) in &inp.partial_sigs {
        if !key_matches(kind, out, redeem, pk) {
            continue;
        }
        let msg = ecdsa_sighash(
            &psbt.unsigned_tx,
            i,
            kind,
            out,
            redeem,
            sig.sighash_type.to_u32(),
        )?;
        secp()
            .verify_ecdsa(&msg, &sig.signature, &pk.inner)
            .map_err(|_| err!("input {i}: the signature for key {pk} is INVALID"))?;
        found.push((*pk, *sig));
    }
    if let Kind::Multi { ms, .. } = kind {
        found.sort_by_key(|(pk, _)| ms.pubkeys.iter().position(|p| p == pk));
    }
    Ok(found)
}

fn valid_tap_sig(psbt: &Psbt, i: usize, out: &TxOut) -> Result<Option<taproot::Signature>> {
    let Some(sig) = psbt.inputs[i].tap_key_sig else {
        return Ok(None);
    };
    let prevouts = utxos(psbt)?;
    let digest = SighashCache::new(&psbt.unsigned_tx).taproot_key_spend_signature_hash(
        i,
        &Prevouts::All(&prevouts),
        sig.sighash_type,
    )?;
    let key = bitcoin::XOnlyPublicKey::from_slice(&out.script_pubkey.as_bytes()[2..])?;
    secp()
        .verify_schnorr(
            &sig.signature,
            &Message::from_digest(digest.to_byte_array()),
            &key,
        )
        .map_err(|_| err!("input {i}: the taproot signature is INVALID"))?;
    Ok(Some(sig))
}

/// Where one input stands: how many signatures it has and still needs.
#[derive(Debug, Clone, Serialize)]
pub struct SigStatus {
    pub index: usize,
    pub txid: String,
    pub vout: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub amount_sat: u64,
    pub have: usize,
    pub need: usize,
    /// Public keys with a valid signature on this input.
    pub signed_by: Vec<String>,
    /// Multisig keys that have not signed yet.
    pub missing: Vec<String>,
}

pub fn status(psbt: &Psbt) -> Result<Vec<SigStatus>> {
    let mut all = Vec::new();
    for i in 0..psbt.inputs.len() {
        let out = utxo(psbt, i)?;
        let op = psbt.unsigned_tx.input[i].previous_output;
        let inp = &psbt.inputs[i];
        let mut st = SigStatus {
            index: i,
            txid: op.txid.to_string(),
            vout: op.vout,
            kind: script_type(&out.script_pubkey),
            amount_sat: out.value.to_sat(),
            have: 0,
            need: 1,
            signed_by: vec![],
            missing: vec![],
        };
        if inp.final_script_sig.is_some() || inp.final_script_witness.is_some() {
            st.have = 1;
            st.kind += " (finalized)";
        } else {
            let kind = kind_of(psbt, i)?;
            st.kind = kind.name();
            st.need = kind.need();
            if kind == Kind::P2tr {
                st.have = valid_tap_sig(psbt, i, &out)?.is_some() as usize;
            } else if kind != Kind::P2shUnknown {
                let sigs = valid_sigs(psbt, i, &kind, &out)?;
                st.have = sigs.len();
                st.signed_by = sigs.iter().map(|(pk, _)| pk.to_string()).collect();
                if let Kind::Multi { ms, .. } = &kind {
                    st.missing = ms
                        .pubkeys
                        .iter()
                        .filter(|p| !sigs.iter().any(|(pk, _)| pk == *p))
                        .map(|p| p.to_string())
                        .collect();
                }
            }
        }
        all.push(st);
    }
    Ok(all)
}

fn push(b: Builder, data: &[u8]) -> Builder {
    b.push_slice(<&PushBytes>::try_from(data).expect("script element under 4 GB"))
}

/// Lay signatures out as the scriptSig and witness this kind of input wants.
fn assemble(kind: &Kind, sigs: &[Vec<u8>], pubkey: &[u8], redeem: &[u8]) -> (ScriptBuf, Witness) {
    let none = Witness::new;
    let sig0: &[u8] = sigs.first().map(|s| s.as_slice()).unwrap_or(&[]);
    match kind {
        Kind::P2pk(_) => (push(Builder::new(), sig0).into_script(), none()),
        Kind::P2pkh => (
            push(push(Builder::new(), sig0), pubkey).into_script(),
            none(),
        ),
        Kind::P2wpkh => (ScriptBuf::new(), Witness::from_slice(&[sig0, pubkey])),
        Kind::P2shP2wpkh | Kind::P2shUnknown => (
            push(Builder::new(), redeem).into_script(),
            Witness::from_slice(&[sig0, pubkey]),
        ),
        Kind::P2tr => (ScriptBuf::new(), Witness::from_slice(&[sig0])),
        Kind::Multi { ms, wrap } => {
            let script = ms.script();
            if *wrap == Wrap::P2sh {
                // OP_0 is the dummy element CHECKMULTISIG pops (and NULLDUMMY demands).
                let mut b = Builder::new().push_int(0);
                for s in sigs {
                    b = push(b, s);
                }
                return (push(b, script.as_bytes()).into_script(), none());
            }
            let mut w = Witness::new();
            w.push([]);
            for s in sigs {
                w.push(s);
            }
            w.push(script.as_bytes());
            let script_sig = match ms.redeem_script(*wrap) {
                Some(r) => push(Builder::new(), r.as_bytes()).into_script(),
                None => ScriptBuf::new(),
            };
            (script_sig, w)
        }
    }
}

/// Worst-case virtual size once fully signed (72-byte ECDSA signatures), so a
/// fee computed from it can never land below the requested rate. `keys` only
/// helps recognise legacy outputs that pay to an uncompressed key.
pub fn estimate_vsize(psbt: &Psbt, keys: &[SecretKey]) -> Result<usize> {
    let mut tx = psbt.unsigned_tx.clone();
    for i in 0..psbt.inputs.len() {
        let inp = &psbt.inputs[i];
        if inp.final_script_sig.is_some() || inp.final_script_witness.is_some() {
            tx.input[i].script_sig = inp.final_script_sig.clone().unwrap_or_default();
            tx.input[i].witness = inp.final_script_witness.clone().unwrap_or_default();
            continue;
        }
        let out = utxo(psbt, i)?;
        let kind = kind_of(psbt, i)?;
        let schnorr = inp.sighash_type.is_some_and(|t| t.to_u32() != 0) as usize + 64;
        let sig_len = if kind == Kind::P2tr { schnorr } else { 72 };
        let redeem = inp.redeem_script.as_deref();
        let uncompressed = inp.partial_sigs.keys().any(|p| !p.compressed)
            || keys
                .iter()
                .any(|sk| key_matches(&kind, &out, redeem, &both_pubkeys(sk)[1]));
        let pubkey = vec![0u8; if uncompressed { 65 } else { 33 }];
        let (script_sig, witness) = assemble(
            &kind,
            &vec![vec![0u8; sig_len]; kind.need()],
            &pubkey,
            &[0u8; 22],
        );
        tx.input[i].script_sig = script_sig;
        tx.input[i].witness = witness;
    }
    Ok(tx.vsize())
}

/// Turn a fully signed PSBT into a network-ready transaction.
pub fn finalize(psbt: &Psbt) -> Result<Transaction> {
    let mut tx = psbt.unsigned_tx.clone();
    for i in 0..psbt.inputs.len() {
        let inp = &psbt.inputs[i];
        if inp.final_script_sig.is_some() || inp.final_script_witness.is_some() {
            tx.input[i].script_sig = inp.final_script_sig.clone().unwrap_or_default();
            tx.input[i].witness = inp.final_script_witness.clone().unwrap_or_default();
            continue;
        }
        let out = utxo(psbt, i)?;
        let kind = kind_of(psbt, i)?;
        let (sigs, pubkey): (Vec<Vec<u8>>, Vec<u8>) = if kind == Kind::P2tr {
            (
                valid_tap_sig(psbt, i, &out)?
                    .iter()
                    .map(|s| s.to_vec())
                    .collect(),
                vec![],
            )
        } else if kind == Kind::P2shUnknown {
            (vec![], vec![])
        } else {
            let found = valid_sigs(psbt, i, &kind, &out)?;
            let pubkey = found
                .first()
                .map(|(pk, _)| pk.to_bytes())
                .unwrap_or_default();
            (
                found
                    .iter()
                    .take(kind.need())
                    .map(|(_, s)| s.to_vec())
                    .collect(),
                pubkey,
            )
        };
        if sigs.len() < kind.need() {
            bail!(
                "input {i} ({}) has {} of {} signatures",
                kind.name(),
                sigs.len(),
                kind.need()
            );
        }
        let redeem = inp
            .redeem_script
            .as_ref()
            .map(|r| r.to_bytes())
            .unwrap_or_default();
        let (script_sig, witness) = assemble(&kind, &sigs, &pubkey, &redeem);
        tx.input[i].script_sig = script_sig;
        tx.input[i].witness = witness;
    }
    Ok(tx)
}

#[derive(Debug, Clone, Serialize)]
pub struct OutputInfo {
    pub index: usize,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    pub script_pubkey: String,
    pub amount_sat: u64,
}

/// The result of `build`, `sign` and `combine`: either a finished, verified
/// transaction (`raw`) or a PSBT still waiting for signatures (`psbt`).
#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub network: String,
    pub complete: bool,
    /// Signed transaction hex; present only when complete and verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    /// Base64 PSBT to pass to the next signer; present only when incomplete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psbt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wtxid: Option<String>,
    /// Exact when complete, worst-case estimate otherwise.
    pub vsize: usize,
    pub total_in: u64,
    pub total_out: u64,
    pub fee: u64,
    pub fee_rate: f64,
    pub outputs: Vec<OutputInfo>,
    pub signatures: Vec<SigStatus>,
    /// Per-input signature verification of the finished transaction.
    pub verify: Vec<InputCheck>,
    /// "ok" once Bitcoin Core's script interpreter accepted every input.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consensus: Option<String>,
    pub notes: Vec<String>,
}

/// Summarise a PSBT; if every signature is present, finalise it and verify
/// the result. A transaction that fails verification is never returned.
pub fn outcome(psbt: &Psbt, net: Network, mut notes: Vec<String>) -> Result<Outcome> {
    let signatures = status(psbt)?;
    let prevouts = utxos(psbt)?;
    let complete = signatures.iter().all(|s| s.have >= s.need);
    let total_in: u64 = prevouts.iter().map(|o| o.value.to_sat()).sum();
    let total_out: u64 = psbt
        .unsigned_tx
        .output
        .iter()
        .map(|o| o.value.to_sat())
        .sum();
    if total_out > total_in {
        bail!("outputs ({total_out} sat) exceed inputs ({total_in} sat)");
    }
    let fee = total_in - total_out;
    let outputs = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .map(|(index, o)| OutputInfo {
            index,
            kind: script_type(&o.script_pubkey),
            address: script_address(&o.script_pubkey, net),
            script_pubkey: hx(o.script_pubkey.as_bytes()),
            amount_sat: o.value.to_sat(),
        })
        .collect();
    for (n, o) in psbt.unsigned_tx.output.iter().enumerate() {
        let v = o.value.to_sat();
        if !o.script_pubkey.is_op_return() && v > 0 && v < dust_threshold(&o.script_pubkey) {
            notes.push(format!(
                "WARNING output {n} is dust ({v} sat) and will not relay"
            ));
        }
    }

    let mut oc = Outcome {
        network: network_name(net).into(),
        complete,
        raw: None,
        psbt: None,
        txid: None,
        wtxid: None,
        vsize: 0,
        total_in,
        total_out,
        fee,
        fee_rate: 0.0,
        outputs,
        signatures,
        verify: vec![],
        consensus: None,
        notes,
    };
    if complete {
        let tx = finalize(psbt)?;
        oc.verify = verify_tx(&tx, &prevouts);
        if let Some(bad) = oc.verify.iter().find(|c| !c.ok) {
            bail!(
                "refusing to output the transaction: input {} ({}) failed verification: {}",
                bad.index,
                bad.kind,
                bad.note
            );
        }
        consensus_verify(&tx, &prevouts)
            .map_err(|e| err!("refusing to output the transaction: {e}"))?;
        oc.consensus = Some("ok".into());
        oc.vsize = tx.vsize();
        oc.txid = Some(tx.compute_txid().to_string());
        oc.wtxid = Some(tx.compute_wtxid().to_string());
        oc.raw = Some(bitcoin::consensus::encode::serialize_hex(&tx));
    } else {
        oc.vsize = estimate_vsize(psbt, &[])?;
        oc.psbt = Some(psbt.to_string());
        let waiting: Vec<String> = oc
            .signatures
            .iter()
            .filter(|s| s.have < s.need)
            .map(|s| format!("input {} has {} of {}", s.index, s.have, s.need))
            .collect();
        oc.notes
            .push(format!("NOT fully signed: {}", waiting.join("; ")));
    }
    oc.fee_rate = (fee as f64 / oc.vsize.max(1) as f64 * 100.0).round() / 100.0;
    Ok(oc)
}

/// Add signatures to a PSBT. A key that signs nothing is an error: it almost
/// always means the wrong key file was picked up.
pub fn sign_and_report(psbt: &mut Psbt, keys: &[SecretKey], net: Network) -> Result<Outcome> {
    if keys.is_empty() {
        bail!("no private key given");
    }
    let counts = sign_psbt(psbt, keys)?;
    if let Some(n) = counts.iter().position(|c| *c == 0) {
        bail!(
            "key #{} (pubkey {}) cannot sign any input of this transaction",
            n + 1,
            both_pubkeys(&keys[n])[0]
        );
    }
    outcome(psbt, net, vec![])
}

/// Merge PSBTs of the same transaction that were signed separately.
pub fn combine(mut psbts: Vec<Psbt>, net: Network) -> Result<Outcome> {
    if psbts.is_empty() {
        bail!("nothing to combine");
    }
    let mut base = psbts.remove(0);
    for other in psbts {
        base.combine(other)
            .map_err(|e| err!("cannot combine: {e}"))?;
    }
    outcome(&base, net, vec![])
}
