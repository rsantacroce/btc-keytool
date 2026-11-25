//! Cross-checks against an independent implementation (rust-miniscript):
//! multisig addresses and descriptor checksums must agree with it.

use std::str::FromStr;

use btc_keytool_core::bitcoin::{Network, PublicKey};
use btc_keytool_core::keys::parse_pubkey;
use btc_keytool_core::script::{script_address, Multisig, Wrap};
use miniscript::Descriptor;

const KEYS: [&str; 4] = [
    "03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a",
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
];

#[test]
fn multisig_matches_miniscript() {
    let mut compared = 0;
    for n in 1..=KEYS.len() {
        for k in 1..=n {
            for sorted in [true, false] {
                for wrap in Wrap::ALL {
                    let keys = KEYS[..n].iter().map(|p| parse_pubkey(p).unwrap()).collect();
                    let ms = Multisig::new(k, keys, sorted).unwrap();
                    let ours = ms.descriptor(wrap, sorted);
                    // miniscript recomputes the checksum and rejects a wrong one
                    let theirs: Descriptor<PublicKey> = Descriptor::from_str(&ours)
                        .unwrap_or_else(|e| panic!("miniscript rejects {ours}: {e}"));
                    assert_eq!(theirs.to_string(), ours);
                    for net in [Network::Bitcoin, Network::Testnet, Network::Regtest] {
                        let addr = script_address(&ms.script_pubkey(wrap).unwrap(), net).unwrap();
                        assert_eq!(theirs.address(net).unwrap().to_string(), addr, "{ours}");
                    }
                    compared += 1;
                }
            }
        }
    }
    assert_eq!(compared, 60);
}

#[test]
fn p2sh_refuses_scripts_over_520_bytes() {
    // 16 compressed keys make a 547-byte script: fine for P2WSH, illegal in P2SH.
    let keys: Vec<PublicKey> = (1u8..=16)
        .map(|i| {
            let mut sk = [0u8; 32];
            sk[31] = i;
            let sk = btc_keytool_core::bitcoin::secp256k1::SecretKey::from_slice(&sk).unwrap();
            PublicKey::new(sk.public_key(btc_keytool_core::secp()))
        })
        .collect();
    let ms = Multisig::new(2, keys, true).unwrap();
    assert!(ms.script_pubkey(Wrap::P2sh).is_err());
    assert!(ms.script_pubkey(Wrap::P2wsh).is_ok());
    assert_eq!(Multisig::parse(&ms.script()), Some(ms));
}
