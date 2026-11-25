//! The JSON transaction spec: parse it, build the transaction, sign what the
//! supplied keys can sign.

use bitcoin::absolute::LockTime;
use bitcoin::blockdata::opcodes::all::OP_RETURN;
use bitcoin::blockdata::script::{Builder, PushBytesBuf};
use bitcoin::psbt::{Psbt, PsbtSighashType};
use bitcoin::secp256k1::SecretKey;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use serde::Deserialize;
use serde_json::Value;

use crate::keys::{parse_key, parse_pubkey};
use crate::script::{classify_input, dust_threshold, parse_address, Multisig, Wrap};
use crate::sign::{estimate_vsize, outcome, sign_input, Outcome};
use crate::{parse_network, unhx, Result};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub network: Option<String>,
    pub version: Option<i32>,
    pub locktime: Option<u32>,
    /// Default key, tried on every input.
    pub key: Option<String>,
    /// More default keys (handy for multisig).
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub inputs: Vec<InputSpec>,
    #[serde(default)]
    pub outputs: Vec<OutputSpec>,
    pub change_address: Option<String>,
    /// sat/vB
    pub fee_rate: Option<f64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputSpec {
    pub txid: String,
    pub vout: u32,
    pub amount_sat: Option<u64>,
    pub address: Option<String>,
    pub script_pubkey: Option<String>,
    /// Full previous transaction hex; amount and script are then read from it.
    pub prev_tx: Option<String>,
    pub key: Option<String>,
    #[serde(default)]
    pub keys: Vec<String>,
    pub sequence: Option<u32>,
    pub sighash: Option<u8>,
    pub multisig: Option<MultisigSpec>,
    pub redeem_script: Option<String>,
    pub witness_script: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultisigSpec {
    pub threshold: usize,
    pub pubkeys: Vec<String>,
    /// BIP67 key ordering (`sortedmulti`). Default true.
    pub sorted: Option<bool>,
    /// p2wsh | p2sh-p2wsh | p2sh. Inferred from the address when omitted.
    #[serde(rename = "type")]
    pub kind: Option<String>,
}

impl MultisigSpec {
    pub fn build(&self) -> Result<Multisig> {
        let keys = self
            .pubkeys
            .iter()
            .map(|p| parse_pubkey(p))
            .collect::<Result<Vec<_>>>()?;
        Multisig::new(self.threshold, keys, self.sorted.unwrap_or(true))
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum AmountSpec {
    Sat(u64),
    Word(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSpec {
    pub address: Option<String>,
    pub script_pubkey: Option<String>,
    pub op_return: Option<String>,
    /// Treat `op_return` as hex instead of text.
    #[serde(default)]
    pub hex: bool,
    pub amount_sat: Option<AmountSpec>,
}

/// Keys starting with `_` are comments; any other unknown key is an error, so
/// a typo like "change_adress" cannot silently turn your change into fee.
fn strip_comments(v: &mut Value) {
    match v {
        Value::Object(m) => {
            m.retain(|k, _| !k.starts_with('_'));
            m.values_mut().for_each(strip_comments);
        }
        Value::Array(a) => a.iter_mut().for_each(strip_comments),
        _ => {}
    }
}

pub fn parse_spec(text: &str) -> Result<(Spec, Network)> {
    let mut v: Value =
        serde_json::from_str(text).map_err(|e| err!("spec is not valid JSON: {e}"))?;
    strip_comments(&mut v);
    let spec: Spec = serde_json::from_value(v).map_err(|e| err!("spec: {e}"))?;
    let net = parse_network(spec.network.as_deref().unwrap_or("mainnet"))?;
    Ok((spec, net))
}

/// An input with everything needed to sign or verify it.
pub struct ResolvedInput {
    pub outpoint: OutPoint,
    pub txout: TxOut,
    pub redeem_script: Option<ScriptBuf>,
    pub witness_script: Option<ScriptBuf>,
    pub prev_tx: Option<Transaction>,
}

fn resolve_input(n: usize, i: &InputSpec, net: Network) -> Result<ResolvedInput> {
    let txid: Txid = i
        .txid
        .trim()
        .parse()
        .map_err(|e| err!("input {n}: bad txid: {e}"))?;
    let script = |h: &Option<String>| -> Result<Option<ScriptBuf>> {
        h.as_ref().map(|h| unhx(h).map(ScriptBuf::from)).transpose()
    };
    let mut spk = match (&i.script_pubkey, &i.address) {
        (Some(h), _) => Some(ScriptBuf::from(unhx(h)?)),
        (None, Some(a)) => Some(parse_address(a, net).map_err(|e| err!("input {n}: {e}"))?),
        (None, None) => None,
    };
    let mut amount = i.amount_sat;
    let mut redeem_script = script(&i.redeem_script)?;
    let mut witness_script = script(&i.witness_script)?;

    let prev_tx = match &i.prev_tx {
        None => None,
        Some(h) => {
            let tx: Transaction = bitcoin::consensus::deserialize(&unhx(h)?)
                .map_err(|e| err!("input {n}: prev_tx: {e}"))?;
            if tx.compute_txid() != txid {
                bail!("input {n}: prev_tx is not transaction {txid}");
            }
            let out = tx
                .output
                .get(i.vout as usize)
                .ok_or_else(|| err!("input {n}: prev_tx has no output {}", i.vout))?;
            if spk.as_ref().is_some_and(|s| *s != out.script_pubkey) {
                bail!("input {n}: address/script_pubkey disagrees with prev_tx");
            }
            if amount.is_some_and(|a| a != out.value.to_sat()) {
                bail!(
                    "input {n}: amount_sat disagrees with prev_tx ({} sat)",
                    out.value.to_sat()
                );
            }
            spk = Some(out.script_pubkey.clone());
            amount = Some(out.value.to_sat());
            Some(tx)
        }
    };

    if let Some(m) = &i.multisig {
        let ms = m.build().map_err(|e| err!("input {n}: {e}"))?;
        let mismatch = || {
            err!(
                "input {n}: this multisig does not produce the address given - check the \
                 public keys, the threshold, \"sorted\" and \"type\""
            )
        };
        let wrap = match (&m.kind, &spk) {
            (Some(t), _) => Wrap::parse(t)?,
            (None, Some(s)) => ms.wrap_for(s).ok_or_else(mismatch)?,
            (None, None) => Wrap::P2wsh,
        };
        let want = ms.script_pubkey(wrap).map_err(|e| err!("input {n}: {e}"))?;
        if spk.as_ref().is_some_and(|s| *s != want) {
            return Err(mismatch());
        }
        spk = Some(want);
        redeem_script = ms.redeem_script(wrap);
        witness_script = ms.witness_script(wrap);
    }

    let script_pubkey =
        spk.ok_or_else(|| err!("input {n}: needs address, script_pubkey, multisig or prev_tx"))?;
    let amount = amount
        .ok_or_else(|| err!("input {n}: amount_sat is required (segwit signing commits to it)"))?;
    classify_input(
        &script_pubkey,
        redeem_script.as_deref(),
        witness_script.as_deref(),
    )
    .map_err(|e| err!("input {n}: {e}"))?;
    Ok(ResolvedInput {
        outpoint: OutPoint { txid, vout: i.vout },
        txout: TxOut {
            value: Amount::from_sat(amount),
            script_pubkey,
        },
        redeem_script,
        witness_script,
        prev_tx,
    })
}

/// The outputs a spec says its inputs spend - what `verify` checks a raw
/// transaction against.
pub fn prevouts_from_spec(text: &str) -> Result<(Network, Vec<ResolvedInput>)> {
    let (spec, net) = parse_spec(text)?;
    let inputs = spec
        .inputs
        .iter()
        .enumerate()
        .map(|(n, i)| resolve_input(n, i, net))
        .collect::<Result<Vec<_>>>()?;
    Ok((net, inputs))
}

fn make_psbt(tx: &Transaction, spec: &Spec, resolved: &[ResolvedInput]) -> Result<Psbt> {
    let mut psbt = Psbt::from_unsigned_tx(tx.clone())?;
    for ((inp, r), s) in psbt.inputs.iter_mut().zip(resolved).zip(&spec.inputs) {
        inp.witness_utxo = Some(r.txout.clone());
        inp.non_witness_utxo = r.prev_tx.clone();
        inp.redeem_script = r.redeem_script.clone();
        inp.witness_script = r.witness_script.clone();
        inp.sighash_type = s.sighash.map(|h| PsbtSighashType::from_u32(h as u32));
    }
    Ok(psbt)
}

/// Build the transaction a spec describes and sign it with whatever keys the
/// spec carries. Fully signed -> verified raw transaction; otherwise a PSBT.
pub fn build(text: &str, force: bool) -> Result<Outcome> {
    let (spec, net) = parse_spec(text)?;
    if spec.inputs.is_empty() {
        bail!("spec has no inputs");
    }
    let resolved = spec
        .inputs
        .iter()
        .enumerate()
        .map(|(n, i)| resolve_input(n, i, net))
        .collect::<Result<Vec<_>>>()?;

    // ---- keys ------------------------------------------------------------
    let pool: Vec<SecretKey> = spec
        .key
        .iter()
        .chain(&spec.keys)
        .map(|k| parse_key(k))
        .collect::<Result<_>>()?;
    let own: Vec<Vec<SecretKey>> = spec
        .inputs
        .iter()
        .map(|i| i.key.iter().chain(&i.keys).map(|k| parse_key(k)).collect())
        .collect::<Result<_>>()?;
    let all_keys: Vec<SecretKey> = pool.iter().chain(own.iter().flatten()).copied().collect();

    // ---- outputs ---------------------------------------------------------
    let mut outs: Vec<TxOut> = Vec::new();
    let mut sweep_index = None;
    for (n, o) in spec.outputs.iter().enumerate() {
        let sats = |a: &Option<AmountSpec>| -> Result<Option<u64>> {
            match a {
                Some(AmountSpec::Sat(v)) => Ok(Some(*v)),
                Some(AmountSpec::Word(w))
                    if matches!(w.to_lowercase().as_str(), "all" | "max" | "sweep") =>
                {
                    Ok(None)
                }
                Some(AmountSpec::Word(w)) => bail!("output {n}: bad amount_sat {w:?}"),
                None => bail!("output {n}: amount_sat is required"),
            }
        };
        if let Some(text) = &o.op_return {
            let data = if o.hex {
                unhx(text)?
            } else {
                text.clone().into_bytes()
            };
            if data.len() > 80 {
                bail!("output {n}: OP_RETURN payload over 80 bytes");
            }
            let value = if o.amount_sat.is_some() {
                sats(&o.amount_sat)?.unwrap_or(0)
            } else {
                0
            };
            let script = Builder::new()
                .push_opcode(OP_RETURN)
                .push_slice(PushBytesBuf::try_from(data).expect("80 bytes"))
                .into_script();
            outs.push(TxOut {
                value: Amount::from_sat(value),
                script_pubkey: script,
            });
            continue;
        }
        let script_pubkey = match (&o.script_pubkey, &o.address) {
            (Some(h), _) => ScriptBuf::from(unhx(h)?),
            (None, Some(a)) => parse_address(a, net).map_err(|e| err!("output {n}: {e}"))?,
            (None, None) => bail!("output {n}: needs address, script_pubkey or op_return"),
        };
        let value = match sats(&o.amount_sat)? {
            Some(v) => v,
            None => {
                if sweep_index.is_some() {
                    bail!("only one output may be 'all'");
                }
                sweep_index = Some(outs.len());
                0
            }
        };
        outs.push(TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        });
    }

    let total_in: u64 = resolved.iter().map(|r| r.txout.value.to_sat()).sum();
    let mut tx = Transaction {
        version: Version(spec.version.unwrap_or(2)),
        lock_time: LockTime::from_consensus(spec.locktime.unwrap_or(0)),
        input: resolved
            .iter()
            .zip(&spec.inputs)
            .map(|(r, s)| TxIn {
                previous_output: r.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence(s.sequence.unwrap_or(0xffff_fffd)), // RBF-enabled
                witness: Witness::new(),
            })
            .collect(),
        output: outs,
    };
    let mut notes = Vec::new();

    // ---- fee / change ----------------------------------------------------
    if let Some(rate) = spec.fee_rate {
        if !rate.is_finite() || rate < 0.0 {
            bail!("fee_rate must be a non-negative number of sat/vB");
        }
    }
    let fee_for = |tx: &Transaction, rate: f64| -> Result<u64> {
        let vsize = estimate_vsize(&make_psbt(tx, &spec, &resolved)?, &all_keys)?;
        Ok((vsize as f64 * rate).ceil() as u64)
    };
    let sum_out = |tx: &Transaction| tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>();

    if let Some(si) = sweep_index {
        let rate = spec
            .fee_rate
            .ok_or_else(|| err!("an 'all' output needs fee_rate (sat/vB)"))?;
        let fixed = sum_out(&tx);
        let fee = fee_for(&tx, rate)?;
        if total_in <= fixed + fee {
            bail!(
                "inputs ({total_in} sat) cannot cover the outputs ({fixed} sat) + fee ({fee} sat)"
            );
        }
        tx.output[si].value = Amount::from_sat(total_in - fixed - fee);
        notes.push(format!("output {si} swept the remaining balance"));
    } else if let Some(change) = &spec.change_address {
        let rate = spec
            .fee_rate
            .ok_or_else(|| err!("change_address needs fee_rate (sat/vB)"))?;
        let script_pubkey = parse_address(change, net).map_err(|e| err!("change_address: {e}"))?;
        let spent = sum_out(&tx);
        let dust = dust_threshold(&script_pubkey);
        tx.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey,
        });
        let fee = fee_for(&tx, rate)?;
        if total_in < spent + fee {
            bail!("inputs ({total_in} sat) cannot cover outputs ({spent} sat) + fee ({fee} sat)");
        }
        let change = total_in - spent - fee;
        if change < dust {
            tx.output.pop();
            notes.push(format!(
                "change of {change} sat was below the dust limit ({dust}) and went to fee"
            ));
        } else {
            let ci = tx.output.len() - 1;
            tx.output[ci].value = Amount::from_sat(change);
            notes.push(format!("change output {ci} added"));
        }
    } else if spec.fee_rate.is_some() {
        notes.push(
            "WARNING fee_rate was ignored: there is no change_address or 'all' output to adjust"
                .into(),
        );
    }

    // ---- sanity ----------------------------------------------------------
    let total_out = sum_out(&tx);
    if total_out > total_in {
        bail!("outputs ({total_out} sat) exceed inputs ({total_in} sat)");
    }
    let fee = total_in - total_out;
    if !force && fee > 100_000.max(total_in / 2) {
        bail!(
            "fee of {fee} sat looks like a mistake ({:.1}% of input). Use --force if you meant it.",
            100.0 * fee as f64 / total_in as f64
        );
    }

    // ---- sign ------------------------------------------------------------
    let mut psbt = make_psbt(&tx, &spec, &resolved)?;
    for (n, keys) in own.iter().enumerate() {
        for sk in keys {
            if !sign_input(&mut psbt, n, sk)? {
                bail!("input {n}: the key given for this input does not unlock it");
            }
        }
    }
    for (k, sk) in pool.iter().enumerate() {
        let mut used = false;
        for n in 0..psbt.inputs.len() {
            used |= sign_input(&mut psbt, n, sk)?;
        }
        if !used {
            bail!("spec key #{} does not unlock any input (wrong key?)", k + 1);
        }
    }
    outcome(&psbt, net, notes)
}
