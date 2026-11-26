//! btc-keytool-core: offline Bitcoin keys, multisig, transaction signing and
//! verification.
//!
//! This crate contains no network code and depends on nothing that does. All
//! cryptography is delegated to `rust-bitcoin` / libsecp256k1, and every
//! finished transaction is additionally checked by Bitcoin Core's own script
//! interpreter (libbitcoinconsensus) before it is handed back.

use std::fmt;
use std::sync::OnceLock;

use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::Network;

pub use bitcoin;

/// A plain-text error. Everything here ends up in front of a human.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// `Error` deliberately does not implement `std::error::Error`, which is what
// makes this blanket conversion legal.
impl<E: std::error::Error> From<E> for Error {
    fn from(e: E) -> Self {
        Error(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

macro_rules! err {
    ($($t:tt)*) => { $crate::Error(format!($($t)*)) };
}
macro_rules! bail {
    ($($t:tt)*) => { return Err($crate::Error(format!($($t)*))) };
}

pub mod decode;
pub mod keys;
pub mod message;
pub mod script;
pub mod selftest;
pub mod sign;
pub mod spec;
pub mod verify;

pub fn secp() -> &'static Secp256k1<All> {
    static SECP: OnceLock<Secp256k1<All>> = OnceLock::new();
    SECP.get_or_init(Secp256k1::new)
}

pub const NETWORKS: [&str; 4] = ["mainnet", "testnet", "signet", "regtest"];

pub fn parse_network(s: &str) -> Result<Network> {
    Ok(match s {
        "mainnet" | "bitcoin" | "main" => Network::Bitcoin,
        "testnet" | "test" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        other => bail!(
            "unknown network {} (expected one of {})",
            keys::echo(other),
            NETWORKS.join(", ")
        ),
    })
}

pub fn network_name(n: Network) -> &'static str {
    match n {
        Network::Bitcoin => "mainnet",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
        _ => "testnet",
    }
}

pub fn hx(b: &[u8]) -> String {
    b.to_lower_hex_string()
}

pub fn unhx(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    Vec::<u8>::from_hex(&cleaned).map_err(|e| err!("bad hex: {e}"))
}

/// No amount can exceed the total supply.
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

/// Add up satoshi amounts, refusing anything impossible. Amounts in a PSBT
/// or a spec are attacker-controlled; a wrapped sum would misreport the fee.
pub fn sum_sats(values: impl IntoIterator<Item = u64>) -> Result<u64> {
    let mut total = 0u64;
    for v in values {
        if v > MAX_MONEY {
            bail!("amount of {v} sat is more than all the bitcoin that can exist");
        }
        total = total
            .checked_add(v)
            .filter(|t| *t <= MAX_MONEY)
            .ok_or_else(|| err!("amounts add up to more than all the bitcoin that can exist"))?;
    }
    Ok(total)
}
