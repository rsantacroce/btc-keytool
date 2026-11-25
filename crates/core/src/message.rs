//! Signing and verifying arbitrary text with a Bitcoin key ("signmessage",
//! BIP137 compact signatures).

use bitcoin::base64::prelude::{Engine, BASE64_STANDARD};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use bitcoin::secp256k1::{Message, SecretKey};
use bitcoin::sign_message::signed_msg_hash;
use bitcoin::Network;
use serde::Serialize;

use crate::keys::addresses_for_pubkey;
use crate::{secp, Result};

#[derive(Debug, Clone, Serialize)]
pub struct SignedMessage {
    pub address: String,
    pub message: String,
    pub signature: String,
    /// Always true: the signature is verified before it is returned.
    pub verified: bool,
}

fn digest(message: &str) -> Message {
    Message::from_digest(signed_msg_hash(message).to_byte_array())
}

/// Sign `message` for one of the key's addresses (default: compressed P2PKH,
/// the form every wallet can verify). Taproot addresses need BIP322, which
/// this tool does not implement.
pub fn sign_message(
    sk: &SecretKey,
    message: &str,
    address: Option<&str>,
    net: Network,
) -> Result<SignedMessage> {
    let addrs = addresses_for_pubkey(&sk.public_key(secp()), net);
    let address = address.map(str::trim).unwrap_or(&addrs.p2pkh).to_string();
    // BIP137 header byte: 27 + recovery id, plus an offset naming the address type.
    let base = match addrs
        .list()
        .iter()
        .find(|(_, a)| *a == address)
        .map(|(t, _)| *t)
    {
        Some("p2pkh_uncomp") => 27,
        Some("p2pkh") => 31,
        Some("p2sh_p2wpkh") => 35,
        Some("p2wpkh") => 39,
        Some(_) => bail!("taproot addresses cannot sign messages this way (needs BIP322)"),
        None => bail!("address {address} does not belong to this key"),
    };
    let (rec, compact) = secp()
        .sign_ecdsa_recoverable(&digest(message), sk)
        .serialize_compact();
    let mut bytes = vec![base + rec.to_i32() as u8];
    bytes.extend_from_slice(&compact);
    let signature = BASE64_STANDARD.encode(bytes);
    if !verify_message(&address, &signature, message)? {
        bail!("message signature failed self-verification");
    }
    Ok(SignedMessage {
        address,
        message: message.to_string(),
        signature,
        verified: true,
    })
}

/// Does `signature` prove that the owner of `address` signed `message`?
pub fn verify_message(address: &str, signature: &str, message: &str) -> Result<bool> {
    let bytes = BASE64_STANDARD
        .decode(signature.trim())
        .map_err(|e| err!("signature is not valid base64: {e}"))?;
    if bytes.len() != 65 || !(27..=42).contains(&bytes[0]) {
        bail!("not a Bitcoin message signature (expected 65 bytes with a 27..42 header)");
    }
    let rec = RecoveryId::from_i32(((bytes[0] - 27) & 3) as i32)?;
    let sig = RecoverableSignature::from_compact(&bytes[1..], rec)
        .map_err(|e| err!("bad signature: {e}"))?;
    let Ok(pk) = secp().recover_ecdsa(&digest(message), &sig) else {
        return Ok(false);
    };
    let address = address.trim();
    Ok([Network::Bitcoin, Network::Testnet, Network::Regtest]
        .into_iter()
        .any(|net| {
            let a = addresses_for_pubkey(&pk, net);
            [a.p2pkh, a.p2pkh_uncomp, a.p2sh_p2wpkh, a.p2wpkh]
                .iter()
                .any(|x| x == address)
        }))
}
