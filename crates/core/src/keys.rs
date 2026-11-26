//! Private keys, public keys and the addresses that belong to them.

use bitcoin::secp256k1::{
    rand::rngs::OsRng, PublicKey as SecpPublicKey, SecretKey, XOnlyPublicKey,
};
use bitcoin::{Address, CompressedPublicKey, Network, PrivateKey, PublicKey, ScriptBuf};
use serde::Serialize;
use serde_json::{json, Value};

use crate::script::{dust_threshold, script_type};
use crate::{hx, network_name, secp, unhx, Result};

/// Accepts WIF, 64-char hex, 0x-hex, or a decimal integer.
pub fn parse_key(text: &str) -> Result<SecretKey> {
    let t = text.trim();
    let from_bytes = |b: [u8; 32]| {
        SecretKey::from_slice(&b).map_err(|_| err!("private key out of range 1..n-1"))
    };
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        if h.is_empty() || h.len() > 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("could not read private key: bad 0x-hex");
        }
        let bytes = unhx(&format!("{h:0>64}"))?;
        return from_bytes(bytes.try_into().expect("32 bytes"));
    }
    let cleaned: String = t.chars().filter(|c| *c != ' ').collect();
    if cleaned.len() == 64 && cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return from_bytes(unhx(&cleaned)?.try_into().expect("32 bytes"));
    }
    if !cleaned.is_empty() && cleaned.chars().all(|c| c.is_ascii_digit()) {
        let mut out = [0u8; 32];
        for ch in cleaned.bytes() {
            let mut carry = (ch - b'0') as u32;
            for byte in out.iter_mut().rev() {
                let v = *byte as u32 * 10 + carry;
                *byte = v as u8;
                carry = v >> 8;
            }
            if carry != 0 {
                bail!("private key out of range 1..n-1");
            }
        }
        return from_bytes(out);
    }
    match PrivateKey::from_wif(t) {
        Ok(k) => Ok(k.inner),
        Err(e) => {
            bail!("could not read private key: expected WIF, 64-char hex, 0x-hex or decimal ({e})")
        }
    }
}

/// Text to quote back in an error message - unless it would be accepted as a
/// private key, which must never be repeated on screen or into a log.
pub fn echo(text: &str) -> String {
    if parse_key(text).is_ok() {
        "<hidden: this looks like a private key>".into()
    } else {
        format!("{text:?}")
    }
}

/// A fresh key straight from the operating system's entropy source.
pub fn generate_key() -> SecretKey {
    SecretKey::new(&mut OsRng)
}

pub fn parse_pubkey(hex: &str) -> Result<PublicKey> {
    let b = unhx(hex)?;
    match b.len() {
        32 => Ok(PublicKey::new(
            XOnlyPublicKey::from_slice(&b)
                .map_err(|_| err!("x-only pubkey: x is not on the curve"))?
                .public_key(bitcoin::secp256k1::Parity::Even),
        )),
        33 | 65 => PublicKey::from_slice(&b).map_err(|e| err!("pubkey: {e}")),
        n => bail!("pubkey: unrecognised length {n}"),
    }
}

/// A 33-byte compressed public key and nothing else. Multisig scripts need
/// the exact key: guessing the parity of an x-only key would build an
/// address nobody can sign for.
pub fn parse_compressed_pubkey(hex: &str) -> Result<PublicKey> {
    let b = unhx(hex)?;
    if b.len() != 33 {
        bail!(
            "public key must be compressed (33 bytes, starting 02 or 03), got {} bytes",
            b.len()
        );
    }
    PublicKey::from_slice(&b).map_err(|e| err!("pubkey: {e}"))
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Addresses {
    pub p2pkh: String,
    pub p2pkh_uncomp: String,
    pub p2sh_p2wpkh: String,
    pub p2wpkh: String,
    pub p2tr: String,
}

impl Addresses {
    pub fn list(&self) -> [(&'static str, &str); 5] {
        [
            ("p2pkh", &self.p2pkh),
            ("p2pkh_uncomp", &self.p2pkh_uncomp),
            ("p2sh_p2wpkh", &self.p2sh_p2wpkh),
            ("p2wpkh", &self.p2wpkh),
            ("p2tr", &self.p2tr),
        ]
    }
}

/// Every address a single public key controls.
pub fn addresses_for_pubkey(pk: &SecpPublicKey, net: Network) -> Addresses {
    let comp = CompressedPublicKey(*pk);
    Addresses {
        p2pkh: Address::p2pkh(PublicKey::new(*pk), net).to_string(),
        p2pkh_uncomp: Address::p2pkh(PublicKey::new_uncompressed(*pk), net).to_string(),
        p2sh_p2wpkh: Address::p2shwpkh(&comp, net).to_string(),
        p2wpkh: Address::p2wpkh(&comp, net).to_string(),
        p2tr: Address::p2tr(secp(), pk.x_only_public_key().0, None, net).to_string(),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyInfo {
    pub network: String,
    pub private_key_hex: String,
    pub wif_compressed: String,
    pub wif_uncompressed: String,
    pub public_key_compressed: String,
    pub public_key_uncompressed: String,
    pub public_key_x: String,
    pub public_key_y: String,
    pub hash160_compressed: String,
    pub addresses: Addresses,
    pub script_pubkeys: Addresses,
}

pub fn key_info(sk: &SecretKey, net: Network) -> Result<KeyInfo> {
    let pk = sk.public_key(secp());
    let unc = pk.serialize_uncompressed();
    let addresses = addresses_for_pubkey(&pk, net);
    let spk =
        |a: &str| -> Result<String> { Ok(hx(crate::script::parse_address(a, net)?.as_bytes())) };
    let script_pubkeys = Addresses {
        p2pkh: spk(&addresses.p2pkh)?,
        p2pkh_uncomp: spk(&addresses.p2pkh_uncomp)?,
        p2sh_p2wpkh: spk(&addresses.p2sh_p2wpkh)?,
        p2wpkh: spk(&addresses.p2wpkh)?,
        p2tr: spk(&addresses.p2tr)?,
    };
    Ok(KeyInfo {
        network: network_name(net).into(),
        private_key_hex: hx(&sk.secret_bytes()),
        wif_compressed: PrivateKey::new(*sk, net).to_wif(),
        wif_uncompressed: PrivateKey::new_uncompressed(*sk, net).to_wif(),
        public_key_compressed: hx(&pk.serialize()),
        public_key_uncompressed: hx(&unc),
        public_key_x: hx(&unc[1..33]),
        public_key_y: hx(&unc[33..]),
        hash160_compressed: PublicKey::new(pk).pubkey_hash().to_string(),
        addresses,
        script_pubkeys,
    })
}

/// Inspect an address (-> scriptPubKey, type, dust limit) or a public key
/// (-> every address it controls).
pub fn inspect(target: &str, net: Network) -> Result<Value> {
    let t = target.trim();
    let is_hex = t.chars().all(|c| c.is_ascii_hexdigit());
    if t.len() == 64 && is_hex {
        // 32 bytes can only be a taproot (x-only) key. It does not say which
        // of the two points with this x is meant, so legacy and segwit v0
        // addresses cannot be derived from it - and it may just as well be a
        // private key pasted into the wrong place.
        let x = XOnlyPublicKey::from_slice(&unhx(t)?)
            .map_err(|_| err!("x-only pubkey: x is not on the curve"))?;
        return Ok(json!({
            "x_only_public_key": hx(&x.serialize()),
            "p2tr": Address::p2tr(secp(), x, None, net).to_string(),
            "note": "Read as a 32-byte taproot (x-only) PUBLIC key, used as the internal key. \
                     Such a key has no legacy or segwit v0 address: give the 33-byte compressed \
                     key for those. If this is a PRIVATE key, do not fund this address - use \
                     `key` instead.",
        }));
    }
    if matches!(t.len(), 66 | 130) && is_hex {
        let pk = parse_pubkey(t)?;
        let a = addresses_for_pubkey(&pk.inner, net);
        return Ok(json!({
            "public_key_compressed": hx(&pk.inner.serialize()),
            "p2pkh": a.p2pkh,
            "p2sh_p2wpkh": a.p2sh_p2wpkh,
            "p2wpkh": a.p2wpkh,
            "p2tr": a.p2tr,
        }));
    }
    let unchecked: Address<bitcoin::address::NetworkUnchecked> =
        t.parse().map_err(|e| err!("address: {e}"))?;
    let detected = [Network::Bitcoin, Network::Testnet, Network::Regtest]
        .into_iter()
        .find(|n| unchecked.is_valid_for_network(*n))
        .ok_or_else(|| err!("address: unknown network"))?;
    let spk: ScriptBuf = unchecked.assume_checked().script_pubkey();
    Ok(json!({
        "address": t,
        "type": script_type(&spk),
        "network": network_name(detected),
        "script_pubkey": hx(spk.as_bytes()),
        "dust_threshold_sat": dust_threshold(&spk),
    }))
}
