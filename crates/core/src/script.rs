//! Script helpers: classification, addresses, dust, and k-of-n multisig.

use bitcoin::blockdata::opcodes::all::{OP_CHECKMULTISIG, OP_CHECKSIG};
use bitcoin::blockdata::script::{Builder, Instruction};
use bitcoin::{Address, Network, PublicKey, Script, ScriptBuf};

use crate::{hx, network_name, Result};

pub fn script_type(spk: &Script) -> String {
    let b = spk.as_bytes();
    if spk.is_p2pkh() {
        "p2pkh".into()
    } else if spk.is_p2sh() {
        "p2sh".into()
    } else if spk.is_p2wpkh() {
        "p2wpkh".into()
    } else if spk.is_p2wsh() {
        "p2wsh".into()
    } else if spk.is_p2tr() {
        "p2tr".into()
    } else if let Some(v) = spk.witness_version() {
        format!("witness_v{}", v.to_num())
    } else if p2pk_key(spk).is_some() {
        "p2pk".into()
    } else if b.first() == Some(&0x6a) {
        "op_return".into()
    } else {
        "nonstandard".into()
    }
}

/// The public key of a bare pay-to-pubkey output.
pub fn p2pk_key(spk: &Script) -> Option<PublicKey> {
    let b = spk.as_bytes();
    if matches!(b.len(), 35 | 67)
        && b[0] as usize == b.len() - 2
        && b[b.len() - 1] == OP_CHECKSIG.to_u8()
    {
        PublicKey::from_slice(&b[1..b.len() - 1]).ok()
    } else {
        None
    }
}

pub fn script_address(spk: &Script, net: Network) -> Option<String> {
    Address::from_script(spk, net).ok().map(|a| a.to_string())
}

/// Address -> scriptPubKey, refusing addresses from another network.
pub fn parse_address(addr: &str, net: Network) -> Result<ScriptBuf> {
    let a: Address<bitcoin::address::NetworkUnchecked> = addr
        .trim()
        .parse()
        .map_err(|e| err!("address {}: {e}", crate::keys::echo(addr)))?;
    if !a.is_valid_for_network(net) {
        bail!("address {addr} does not belong to {}", network_name(net));
    }
    Ok(a.assume_checked().script_pubkey())
}

const DUST_RELAY_FEE: u64 = 3; // sat/vB

/// Bitcoin Core's GetDustThreshold().
pub fn dust_threshold(spk: &Script) -> u64 {
    let n = spk.len() as u64;
    let varint = if n < 0xfd { 1 } else { 3 };
    let spend_cost = if spk.is_witness_program() { 67 } else { 148 };
    (8 + varint + n + spend_cost) * DUST_RELAY_FEE
}

// ------------------------------------------------------------- multisig ----

/// How a multisig script is wrapped into an output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wrap {
    /// Legacy P2SH (`3…`).
    P2sh,
    /// P2WSH nested in P2SH (`3…`).
    P2shP2wsh,
    /// Native segwit P2WSH (`bc1q…`, 62 characters).
    P2wsh,
}

impl Wrap {
    pub const ALL: [Wrap; 3] = [Wrap::P2wsh, Wrap::P2shP2wsh, Wrap::P2sh];

    pub fn parse(s: &str) -> Result<Wrap> {
        Ok(match s.to_ascii_lowercase().replace('_', "-").as_str() {
            "p2wsh" => Wrap::P2wsh,
            "p2sh-p2wsh" => Wrap::P2shP2wsh,
            "p2sh" => Wrap::P2sh,
            _ => bail!(
                "unknown multisig type {} (p2wsh, p2sh-p2wsh or p2sh)",
                crate::keys::echo(s)
            ),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Wrap::P2sh => "p2sh",
            Wrap::P2shP2wsh => "p2sh-p2wsh",
            Wrap::P2wsh => "p2wsh",
        }
    }
}

/// A bare `k <pk>… n OP_CHECKMULTISIG` script. `pubkeys` is in script order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Multisig {
    pub threshold: usize,
    pub pubkeys: Vec<PublicKey>,
}

impl Multisig {
    /// `sorted` applies BIP67 ordering (descriptor `sortedmulti`), so every
    /// cosigner derives the same address no matter how they list the keys.
    pub fn new(threshold: usize, mut pubkeys: Vec<PublicKey>, sorted: bool) -> Result<Self> {
        let n = pubkeys.len();
        if n == 0 || n > 20 {
            bail!("multisig needs between 1 and 20 public keys, got {n}");
        }
        if threshold == 0 || threshold > n {
            bail!("multisig threshold {threshold} is not possible with {n} keys");
        }
        if pubkeys.iter().any(|p| !p.compressed) {
            bail!("multisig public keys must be compressed (33 bytes)");
        }
        if sorted {
            pubkeys.sort_by_key(|p| p.inner.serialize());
        }
        for (i, p) in pubkeys.iter().enumerate() {
            if pubkeys[..i].contains(p) {
                bail!("multisig public key {p} is listed twice");
            }
        }
        Ok(Multisig { threshold, pubkeys })
    }

    pub fn is_sorted(&self) -> bool {
        self.pubkeys
            .windows(2)
            .all(|w| w[0].inner.serialize() <= w[1].inner.serialize())
    }

    pub fn script(&self) -> ScriptBuf {
        let mut b = Builder::new().push_int(self.threshold as i64);
        for p in &self.pubkeys {
            b = b.push_key(p);
        }
        b.push_int(self.pubkeys.len() as i64)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script()
    }

    /// Recognise a bare multisig script.
    pub fn parse(script: &Script) -> Option<Multisig> {
        fn small_int(i: &Instruction) -> Option<usize> {
            match i {
                Instruction::Op(op) if (0x51..=0x60).contains(&op.to_u8()) => {
                    Some((op.to_u8() - 0x50) as usize)
                }
                Instruction::PushBytes(b)
                    if b.len() == 1 && (17..=20).contains(&b.as_bytes()[0]) =>
                {
                    Some(b.as_bytes()[0] as usize)
                }
                _ => None,
            }
        }
        let ins: Vec<Instruction> = script
            .instructions()
            .collect::<std::result::Result<_, _>>()
            .ok()?;
        if ins.len() < 4 {
            return None;
        }
        let threshold = small_int(&ins[0])?;
        let n = small_int(&ins[ins.len() - 2])?;
        match ins[ins.len() - 1] {
            Instruction::Op(op) if op == OP_CHECKMULTISIG => {}
            _ => return None,
        }
        let mut pubkeys = Vec::new();
        for i in &ins[1..ins.len() - 2] {
            match i {
                Instruction::PushBytes(b) if b.len() == 33 => {
                    pubkeys.push(PublicKey::from_slice(b.as_bytes()).ok()?)
                }
                _ => return None,
            }
        }
        if pubkeys.len() != n || threshold == 0 || threshold > n {
            return None;
        }
        Some(Multisig { threshold, pubkeys })
    }

    pub fn script_pubkey(&self, wrap: Wrap) -> Result<ScriptBuf> {
        let script = self.script();
        Ok(match wrap {
            Wrap::P2wsh => ScriptBuf::new_p2wsh(&script.wscript_hash()),
            Wrap::P2shP2wsh => {
                ScriptBuf::new_p2sh(&ScriptBuf::new_p2wsh(&script.wscript_hash()).script_hash())
            }
            Wrap::P2sh => {
                if script.len() > 520 {
                    bail!(
                        "a {}-key multisig script is {} bytes, over the 520-byte P2SH limit; use p2wsh",
                        self.pubkeys.len(),
                        script.len()
                    );
                }
                ScriptBuf::new_p2sh(&script.script_hash())
            }
        })
    }

    /// The P2SH redeemScript, if this wrapping has one.
    pub fn redeem_script(&self, wrap: Wrap) -> Option<ScriptBuf> {
        match wrap {
            Wrap::P2sh => Some(self.script()),
            Wrap::P2shP2wsh => Some(ScriptBuf::new_p2wsh(&self.script().wscript_hash())),
            Wrap::P2wsh => None,
        }
    }

    /// The segwit witnessScript, if this wrapping has one.
    pub fn witness_script(&self, wrap: Wrap) -> Option<ScriptBuf> {
        match wrap {
            Wrap::P2sh => None,
            _ => Some(self.script()),
        }
    }

    /// Which wrapping of this script pays to `spk`, if any.
    pub fn wrap_for(&self, spk: &Script) -> Option<Wrap> {
        Wrap::ALL
            .into_iter()
            .find(|w| self.script_pubkey(*w).map(|s| s == *spk).unwrap_or(false))
    }

    /// An output descriptor (with checksum) that watch-only wallets can import.
    pub fn descriptor(&self, wrap: Wrap, sorted: bool) -> String {
        let keys: Vec<String> = self.pubkeys.iter().map(|p| p.to_string()).collect();
        let inner = format!(
            "{}({},{})",
            if sorted { "sortedmulti" } else { "multi" },
            self.threshold,
            keys.join(",")
        );
        let body = match wrap {
            Wrap::P2wsh => format!("wsh({inner})"),
            Wrap::P2shP2wsh => format!("sh(wsh({inner}))"),
            Wrap::P2sh => format!("sh({inner})"),
        };
        match descriptor_checksum(&body) {
            Some(c) => format!("{body}#{c}"),
            None => body,
        }
    }
}

/// Everything a cosigner needs to know about a new multisig: address, scripts
/// and an importable descriptor.
pub fn multisig_info(
    threshold: usize,
    pubkeys: &[String],
    kind: &str,
    sorted: bool,
    net: Network,
) -> Result<serde_json::Value> {
    use serde_json::json;
    let wrap = Wrap::parse(kind)?;
    let keys = pubkeys
        .iter()
        .map(|p| crate::keys::parse_compressed_pubkey(p))
        .collect::<Result<Vec<_>>>()?;
    let ms = Multisig::new(threshold, keys, sorted)?;
    let spk = ms.script_pubkey(wrap)?;
    let mut v = json!({
        "network": network_name(net),
        "type": format!("{} {}-of-{} multisig", wrap.name(), ms.threshold, ms.pubkeys.len()),
        "address": script_address(&spk, net),
        "script_pubkey": hx(spk.as_bytes()),
    });
    if let Some(r) = ms.redeem_script(wrap) {
        v["redeem_script"] = json!(hx(r.as_bytes()));
    }
    if let Some(w) = ms.witness_script(wrap) {
        v["witness_script"] = json!(hx(w.as_bytes()));
    }
    v["descriptor"] = json!(ms.descriptor(wrap, sorted));
    v["pubkeys"] = json!(ms.pubkeys.iter().map(|p| p.to_string()).collect::<Vec<_>>());
    Ok(v)
}

/// The 8-character checksum Bitcoin Core appends to output descriptors.
pub fn descriptor_checksum(desc: &str) -> Option<String> {
    const INPUT: &str = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~\
                         ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    const OUTPUT: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    fn polymod(c: u64, val: u64) -> u64 {
        let c0 = c >> 35;
        let mut c = ((c & 0x7_ffff_ffff) << 5) ^ val;
        for (bit, g) in [
            0xf5dee51989u64,
            0xa9fdca3312,
            0x1bab10e32d,
            0x3706b1677a,
            0x644d626ffd,
        ]
        .iter()
        .enumerate()
        {
            if c0 >> bit & 1 == 1 {
                c ^= g;
            }
        }
        c
    }
    let (mut c, mut cls, mut count) = (1u64, 0u64, 0);
    for ch in desc.chars() {
        let pos = INPUT.find(ch)? as u64;
        c = polymod(c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        count += 1;
        if count == 3 {
            c = polymod(c, cls);
            cls = 0;
            count = 0;
        }
    }
    if count > 0 {
        c = polymod(c, cls);
    }
    for _ in 0..8 {
        c = polymod(c, 0);
    }
    c ^= 1;
    Some(
        (0..8)
            .map(|j| OUTPUT[(c >> (5 * (7 - j)) & 31) as usize] as char)
            .collect(),
    )
}

// ------------------------------------------------------- input kinds ------

/// What it takes to spend an output, as far as this tool supports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    P2pk(PublicKey),
    P2pkh,
    P2wpkh,
    P2shP2wpkh,
    /// Taproot key-path spend.
    P2tr,
    Multi {
        ms: Multisig,
        wrap: Wrap,
    },
    /// A P2SH output whose redeemScript nobody has supplied yet.
    P2shUnknown,
}

impl Kind {
    pub fn name(&self) -> String {
        match self {
            Kind::P2pk(_) => "p2pk".into(),
            Kind::P2pkh => "p2pkh".into(),
            Kind::P2wpkh => "p2wpkh".into(),
            Kind::P2shP2wpkh => "p2sh-p2wpkh".into(),
            Kind::P2tr => "p2tr".into(),
            Kind::P2shUnknown => "p2sh".into(),
            Kind::Multi { ms, wrap } => {
                format!(
                    "{} {}-of-{} multisig",
                    wrap.name(),
                    ms.threshold,
                    ms.pubkeys.len()
                )
            }
        }
    }

    /// Pre-segwit spends: the signature does NOT commit to the amount being
    /// spent, so a wrong amount goes unnoticed and silently becomes fee.
    pub fn is_legacy(&self) -> bool {
        matches!(
            self,
            Kind::P2pk(_)
                | Kind::P2pkh
                | Kind::Multi {
                    wrap: Wrap::P2sh,
                    ..
                }
        )
    }

    /// Signatures required to spend.
    pub fn need(&self) -> usize {
        match self {
            Kind::Multi { ms, .. } => ms.threshold,
            _ => 1,
        }
    }
}

pub fn classify_input(
    spk: &Script,
    redeem: Option<&Script>,
    witness: Option<&Script>,
) -> Result<Kind> {
    let multi = |wrap: Wrap| -> Result<Kind> {
        let ws = witness.ok_or_else(|| err!("p2wsh input needs its witness_script"))?;
        let ms = Multisig::parse(ws)
            .ok_or_else(|| err!("witness script is not a k-of-n multisig (unsupported)"))?;
        Ok(Kind::Multi { ms, wrap })
    };
    if spk.is_p2pkh() {
        Ok(Kind::P2pkh)
    } else if spk.is_p2wpkh() {
        Ok(Kind::P2wpkh)
    } else if spk.is_p2tr() {
        Ok(Kind::P2tr)
    } else if let Some(pk) = p2pk_key(spk) {
        Ok(Kind::P2pk(pk))
    } else if spk.is_p2wsh() {
        let ws = witness.ok_or_else(|| err!("p2wsh input needs its witness_script"))?;
        if ScriptBuf::new_p2wsh(&ws.wscript_hash()) != *spk {
            bail!("witness_script does not hash to this p2wsh output");
        }
        multi(Wrap::P2wsh)
    } else if spk.is_p2sh() {
        let Some(redeem) = redeem else {
            return Ok(Kind::P2shUnknown);
        };
        if ScriptBuf::new_p2sh(&redeem.script_hash()) != *spk {
            bail!("redeem_script does not hash to this p2sh output");
        }
        if redeem.is_p2wpkh() {
            Ok(Kind::P2shP2wpkh)
        } else if redeem.is_p2wsh() {
            let ws = witness.ok_or_else(|| err!("p2sh-p2wsh input needs its witness_script"))?;
            if ScriptBuf::new_p2wsh(&ws.wscript_hash()) != *redeem {
                bail!("witness_script does not match the p2sh-p2wsh redeem_script");
            }
            multi(Wrap::P2shP2wsh)
        } else {
            let ms = Multisig::parse(redeem)
                .ok_or_else(|| err!("redeem script is not a k-of-n multisig (unsupported)"))?;
            Ok(Kind::Multi {
                ms,
                wrap: Wrap::P2sh,
            })
        }
    } else {
        bail!("unsupported script type {:?}", script_type(spk))
    }
}
