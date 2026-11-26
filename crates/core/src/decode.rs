//! Reading raw transactions and PSBTs back: decode and verify.

use std::str::FromStr;

use bitcoin::blockdata::script::Instruction;
use bitcoin::psbt::Psbt;
use bitcoin::{Network, Transaction, TxOut};
use serde::Serialize;
use serde_json::{json, Value};

use crate::script::{script_address, script_type};
use crate::sign::{check_shape, fee_of, finalize, output_info, status, utxos, OutputInfo};
use crate::spec::prevouts_from_spec;
use crate::verify::{consensus_verify, verify_tx, InputCheck};
use crate::{hx, sum_sats, unhx, Result};

pub enum Parsed {
    Tx(Transaction),
    Psbt(Box<Psbt>),
}

pub fn parse_psbt(text: &str) -> Result<Psbt> {
    let t: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if t.to_lowercase().starts_with("70736274ff") {
        Psbt::deserialize(&unhx(&t)?).map_err(|e| err!("bad PSBT: {e}"))
    } else {
        Psbt::from_str(&t).map_err(|e| err!("bad PSBT: {e}"))
    }
}

/// Accepts a raw transaction (hex) or a PSBT (base64 or hex).
pub fn parse_tx_or_psbt(text: &str) -> Result<Parsed> {
    let t: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if t.starts_with("cHNidP") || t.to_lowercase().starts_with("70736274ff") {
        return Ok(Parsed::Psbt(Box::new(parse_psbt(&t)?)));
    }
    let raw = unhx(&t).map_err(|_| err!("expected a raw transaction in hex or a PSBT"))?;
    let tx = bitcoin::consensus::deserialize(&raw).map_err(|e| err!("bad transaction: {e}"))?;
    Ok(Parsed::Tx(tx))
}

fn btc(sat: u64) -> String {
    format!("{}.{:08}", sat / 100_000_000, sat % 100_000_000)
}

pub fn decode_tx(tx: &Transaction, net: Network) -> Value {
    let inputs: Vec<Value> = tx
        .input
        .iter()
        .map(|i| {
            json!({
                "txid": i.previous_output.txid.to_string(),
                "vout": i.previous_output.vout,
                "script_sig": hx(i.script_sig.as_bytes()),
                "sequence": format!("0x{:08x}", i.sequence.0),
                "witness": i.witness.iter().map(hx).collect::<Vec<_>>(),
            })
        })
        .collect();
    let outputs: Vec<Value> = tx
        .output
        .iter()
        .map(|o| {
            let mut e = json!({
                "amount_sat": o.value.to_sat(),
                "amount_btc": btc(o.value.to_sat()),
                "type": script_type(&o.script_pubkey),
                "script_pubkey": hx(o.script_pubkey.as_bytes()),
            });
            if let Some(a) = script_address(&o.script_pubkey, net) {
                e["address"] = json!(a);
            }
            if o.script_pubkey.is_op_return() {
                if let Some(Ok(Instruction::PushBytes(b))) = o.script_pubkey.instructions().nth(1) {
                    e["data"] = json!(hx(b.as_bytes()));
                }
            }
            e
        })
        .collect();
    json!({
        "txid": tx.compute_txid().to_string(),
        "wtxid": tx.compute_wtxid().to_string(),
        "version": tx.version.0,
        "locktime": tx.lock_time.to_consensus_u32(),
        "size": tx.total_size(),
        "vsize": tx.vsize(),
        "weight": tx.weight().to_wu(),
        "segwit": tx.input.iter().any(|i| !i.witness.is_empty()),
        "inputs": inputs,
        "outputs": outputs,
        // saturating: `decode` refuses impossible sums, other callers must not panic
        "total_out": tx.output.iter().fold(0u64, |t, o| t.saturating_add(o.value.to_sat())),
    })
}

pub fn decode(text: &str, net: Network) -> Result<Value> {
    match parse_tx_or_psbt(text)? {
        Parsed::Tx(tx) => {
            // output amounts are attacker-controlled: refuse rather than overflow
            sum_sats(tx.output.iter().map(|o| o.value.to_sat()))?;
            Ok(decode_tx(&tx, net))
        }
        Parsed::Psbt(psbt) => {
            check_shape(&psbt.unsigned_tx)?;
            let signatures = status(&psbt)?;
            let prevouts = utxos(&psbt)?;
            let (total_in, _, fee) = fee_of(&psbt.unsigned_tx, &prevouts)?;
            let mut warnings: Vec<String> =
                signatures.iter().flat_map(|s| s.warnings.clone()).collect();
            let mut complete = signatures.iter().all(|s| s.have >= s.need);
            // Inputs that arrive already finalised are only *claimed* to be
            // signed: say "complete" only if the finished transaction verifies.
            if complete {
                let verifies = finalize(&psbt).is_ok_and(|tx| {
                    verify_tx(&tx, &prevouts).iter().all(|c| c.ok)
                        && consensus_verify(&tx, &prevouts).is_ok()
                });
                if !verifies {
                    complete = false;
                    warnings.push(
                        "this PSBT is marked as fully signed, but its signatures do NOT verify - \
                         do not rely on it"
                            .into(),
                    );
                }
            }
            Ok(json!({
                "psbt": true,
                "complete": complete,
                "total_in": total_in,
                "fee": fee,
                "warnings": warnings,
                "signatures": signatures,
                "unsigned_tx": decode_tx(&psbt.unsigned_tx, net),
            }))
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    /// True only for a fully signed transaction whose every signature
    /// verifies, both by our own check and by Bitcoin Core's interpreter.
    /// It says the signatures are good - not that the payment is the one you
    /// intended: read `outputs` and `fee` for that.
    pub valid: bool,
    /// False for a PSBT still waiting for signatures.
    pub complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
    pub inputs: Vec<InputCheck>,
    /// "ok", or why Bitcoin Core's script interpreter rejected it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consensus: Option<String>,
    /// What the transaction actually pays, so it can be compared with intent.
    pub outputs: Vec<OutputInfo>,
    pub total_in: u64,
    pub fee: u64,
    /// Valid-but-dangerous findings, e.g. a signature that does not commit
    /// to the outputs, or an input amount nothing proves.
    pub warnings: Vec<String>,
}

fn verify_final(
    tx: &Transaction,
    prevouts: &[TxOut],
    net: Network,
    mut warnings: Vec<String>,
) -> Result<VerifyReport> {
    check_shape(tx)?;
    let (total_in, _, fee) = fee_of(tx, prevouts)?;
    let inputs = verify_tx(tx, prevouts);
    let consensus = match consensus_verify(tx, prevouts) {
        Ok(()) => "ok".to_string(),
        Err(e) => e.0,
    };
    for c in inputs.iter().filter(|c| c.ok && !c.sighash_all) {
        warnings.push(format!(
            "input {}: signed with a sighash that does not commit to the whole transaction \
             ({}) - it can be altered and still be valid",
            c.index, c.note
        ));
    }
    Ok(VerifyReport {
        valid: inputs.iter().all(|c| c.ok) && consensus == "ok",
        complete: true,
        txid: Some(tx.compute_txid().to_string()),
        inputs,
        consensus: Some(consensus),
        outputs: output_info(tx, net),
        total_in,
        fee,
        warnings,
    })
}

/// Verify the signatures of a raw transaction (which needs the spec, to know
/// what the inputs spend) or of a PSBT (which carries that itself).
pub fn verify(text: &str, spec: Option<&str>, net: Network) -> Result<VerifyReport> {
    match parse_tx_or_psbt(text)? {
        Parsed::Tx(tx) => {
            let spec = spec.ok_or_else(|| {
                err!(
                    "verifying a raw transaction needs its spec: signatures commit to the \
                     amounts and scripts being spent, which the transaction itself does not contain"
                )
            })?;
            let (net, resolved) = prevouts_from_spec(spec)?;
            if resolved.len() != tx.input.len() {
                bail!(
                    "the spec has {} inputs, the transaction {}",
                    resolved.len(),
                    tx.input.len()
                );
            }
            let mut warnings = Vec::new();
            for (n, (r, i)) in resolved.iter().zip(&tx.input).enumerate() {
                if r.outpoint != i.previous_output {
                    bail!(
                        "input {n}: the spec spends {}, the transaction {}",
                        r.outpoint,
                        i.previous_output
                    );
                }
                if r.is_legacy() && r.prev_tx.is_none() {
                    warnings.push(format!(
                        "input {n}: the amount is taken from the spec on trust - legacy \
                         signatures do not cover it (add prev_tx to the spec to prove it)"
                    ));
                }
            }
            let prevouts: Vec<TxOut> = resolved.into_iter().map(|r| r.txout).collect();
            verify_final(&tx, &prevouts, net, warnings)
        }
        Parsed::Psbt(psbt) => {
            check_shape(&psbt.unsigned_tx)?;
            // `status` verifies every signature present and errors on a bad one.
            let st = status(&psbt)?;
            let warnings: Vec<String> = st.iter().flat_map(|s| s.warnings.clone()).collect();
            let prevouts = utxos(&psbt)?;
            if st.iter().all(|s| s.have >= s.need) {
                return verify_final(&finalize(&psbt)?, &prevouts, net, warnings);
            }
            let (total_in, _, fee) = fee_of(&psbt.unsigned_tx, &prevouts)?;
            let inputs = st
                .iter()
                .map(|s| InputCheck {
                    index: s.index,
                    kind: s.kind.clone(),
                    ok: s.have >= s.need,
                    note: format!("{} of {} signatures present, all valid", s.have, s.need),
                    sighash_all: true,
                })
                .collect();
            Ok(VerifyReport {
                valid: false,
                complete: false,
                txid: None,
                inputs,
                consensus: None,
                outputs: output_info(&psbt.unsigned_tx, net),
                total_in,
                fee,
                warnings,
            })
        }
    }
}
