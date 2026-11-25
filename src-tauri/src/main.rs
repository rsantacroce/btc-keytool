//! BTC Keytool desktop app. A thin shell: every command forwards to
//! `btc-keytool-core`, the same library the CLI uses. No plugins are loaded
//! and the window is granted no Tauri APIs beyond these commands.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use btc_keytool_core::decode::{self, parse_psbt, VerifyReport};
use btc_keytool_core::keys::{self, KeyInfo};
use btc_keytool_core::message::{self, SignedMessage};
use btc_keytool_core::selftest::Check;
use btc_keytool_core::sign::{self, Outcome};
use btc_keytool_core::{parse_network, script, selftest, spec, Error};
use serde_json::Value;

type Reply<T> = Result<T, String>;

fn s(e: Error) -> String {
    e.0
}

/// One private key per line; blank lines are ignored.
fn parse_keys(text: &str) -> Reply<Vec<btc_keytool_core::bitcoin::secp256k1::SecretKey>> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| keys::parse_key(l).map_err(s))
        .collect()
}

#[tauri::command]
fn key_info(key: String, network: String) -> Reply<KeyInfo> {
    keys::key_info(
        &keys::parse_key(&key).map_err(s)?,
        parse_network(&network).map_err(s)?,
    )
    .map_err(s)
}

#[tauri::command]
fn new_key(network: String) -> Reply<KeyInfo> {
    keys::key_info(&keys::generate_key(), parse_network(&network).map_err(s)?).map_err(s)
}

#[tauri::command]
fn inspect(target: String, network: String) -> Reply<Value> {
    keys::inspect(&target, parse_network(&network).map_err(s)?).map_err(s)
}

#[tauri::command]
fn multisig(
    threshold: usize,
    pubkeys: Vec<String>,
    kind: String,
    sorted: bool,
    network: String,
) -> Reply<Value> {
    script::multisig_info(
        threshold,
        &pubkeys,
        &kind,
        sorted,
        parse_network(&network).map_err(s)?,
    )
    .map_err(s)
}

#[tauri::command]
fn build(spec: String, force: bool) -> Reply<Outcome> {
    spec::build(&spec, force).map_err(s)
}

#[tauri::command]
fn sign(psbt: String, keys: String, network: String) -> Reply<Outcome> {
    let mut p = parse_psbt(&psbt).map_err(s)?;
    sign::sign_and_report(
        &mut p,
        &parse_keys(&keys)?,
        parse_network(&network).map_err(s)?,
    )
    .map_err(s)
}

#[tauri::command]
fn combine(psbts: Vec<String>, network: String) -> Reply<Outcome> {
    let parsed = psbts
        .iter()
        .map(|p| parse_psbt(p).map_err(s))
        .collect::<Reply<Vec<_>>>()?;
    sign::combine(parsed, parse_network(&network).map_err(s)?).map_err(s)
}

#[tauri::command]
fn decode(data: String, network: String) -> Reply<Value> {
    decode::decode(&data, parse_network(&network).map_err(s)?).map_err(s)
}

#[tauri::command]
fn verify(data: String, spec: Option<String>) -> Reply<VerifyReport> {
    let spec = spec.filter(|t| !t.trim().is_empty());
    decode::verify(&data, spec.as_deref()).map_err(s)
}

#[tauri::command]
fn msg_sign(
    key: String,
    message: String,
    address: Option<String>,
    network: String,
) -> Reply<SignedMessage> {
    let address = address.filter(|a| !a.trim().is_empty());
    let sk = keys::parse_key(&key).map_err(s)?;
    message::sign_message(
        &sk,
        &message,
        address.as_deref(),
        parse_network(&network).map_err(s)?,
    )
    .map_err(s)
}

#[tauri::command]
fn msg_verify(address: String, signature: String, message: String) -> Reply<bool> {
    message::verify_message(&address, &signature, &message).map_err(s)
}

#[tauri::command]
fn run_selftest() -> Vec<Check> {
    selftest::run()
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            key_info,
            new_key,
            inspect,
            multisig,
            build,
            sign,
            combine,
            decode,
            verify,
            msg_sign,
            msg_verify,
            run_selftest
        ])
        .run(tauri::generate_context!())
        .expect("error while running BTC Keytool");
}
