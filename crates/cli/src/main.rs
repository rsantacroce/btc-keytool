//! btc-keytool - offline Bitcoin key, multisig and transaction tool.
//!
//! This binary contains no network code: it reads files and arguments, and
//! writes to the terminal and to files you name. Nothing is ever broadcast.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use btc_keytool_core::bitcoin::secp256k1::SecretKey;
use btc_keytool_core::bitcoin::Network;
use btc_keytool_core::decode::{decode, parse_psbt, verify};
use btc_keytool_core::keys::{generate_key, inspect, key_info, parse_key};
use btc_keytool_core::message::{sign_message, verify_message};
use btc_keytool_core::script::multisig_info;
use btc_keytool_core::sign::{combine, sign_and_report, Outcome};
use btc_keytool_core::{parse_network, selftest, spec, Error, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};

#[derive(Parser)]
#[command(
    name = "btc-keytool",
    version,
    about = "Offline Bitcoin key, multisig and transaction tool. Never touches the network."
)]
struct Cli {
    /// mainnet | testnet | signet | regtest
    #[arg(long, global = true, default_value = "mainnet")]
    network: String,
    /// Machine-readable output
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Derive the public key and every address from a private key
    Key {
        /// WIF, 64-char hex, 0x-hex or decimal
        privkey: Option<String>,
        /// Read the key from a file instead (keeps it out of shell history)
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Generate a new key from the operating system's entropy
    Newkey,
    /// Inspect an address or a public key
    Addr { target: String },
    /// Create a k-of-n multisig address from public keys
    Multisig {
        /// Signatures required (the k in k-of-n)
        #[arg(short = 'k', long)]
        threshold: usize,
        /// A cosigner's compressed public key (repeat for each cosigner)
        #[arg(short, long = "pubkey", required = true)]
        pubkeys: Vec<String>,
        /// p2wsh | p2sh-p2wsh | p2sh
        #[arg(long = "type", default_value = "p2wsh")]
        kind: String,
        /// Keep the keys in the order given instead of BIP67-sorting them
        #[arg(long)]
        unsorted: bool,
    },
    /// Build a transaction from a JSON spec and sign it with the spec's keys
    Build {
        spec: PathBuf,
        /// Also write the result (raw hex, or the PSBT if incomplete) here
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Allow an unusually large fee
        #[arg(long)]
        force: bool,
    },
    /// Add your signature to a partially signed transaction (PSBT)
    Sign {
        /// PSBT (base64 or hex), or a file containing one
        psbt: String,
        /// Private key (repeatable). Prefer --key-file.
        #[arg(long = "key")]
        keys: Vec<String>,
        /// File holding a private key (repeatable)
        #[arg(long = "key-file")]
        key_files: Vec<PathBuf>,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Merge PSBTs of one transaction that cosigners signed separately
    Combine {
        /// Two or more PSBTs (base64, hex, or files)
        #[arg(required = true, num_args = 2..)]
        psbts: Vec<String>,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Decode a raw transaction or a PSBT (string or file)
    Decode { data: String },
    /// Verify every signature of a signed transaction or a PSBT
    Verify {
        /// Raw transaction hex or PSBT (string or file)
        data: String,
        /// The spec it was built from (required for a raw transaction)
        spec: Option<PathBuf>,
    },
    /// Sign or verify a text message with a Bitcoin key
    Msg {
        #[command(subcommand)]
        cmd: MsgCmd,
    },
    /// Run the built-in test vectors
    Selftest {
        #[arg(short, long)]
        verbose: bool,
    },
}

#[derive(Subcommand)]
enum MsgCmd {
    /// Sign a message; the signature is verified before it is printed
    Sign {
        message: String,
        #[arg(long)]
        key: Option<String>,
        #[arg(long = "key-file")]
        key_file: Option<PathBuf>,
        /// Which of the key's addresses to sign for (default: P2PKH)
        #[arg(long)]
        address: Option<String>,
    },
    /// Verify a message signature
    Verify {
        address: String,
        signature: String,
        message: String,
    },
}

// ------------------------------------------------------------- output ----

const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";

fn c(s: &str, col: &str) -> String {
    if std::env::var_os("NO_COLOR").is_some() || !std::io::stdout().is_terminal() {
        s.to_string()
    } else {
        format!("{col}{s}\x1b[0m")
    }
}

fn head(title: &str, aside: &str) {
    println!(
        "\n{}{}",
        c(title, BOLD),
        if aside.is_empty() {
            String::new()
        } else {
            c(&format!("  ({aside})"), DIM)
        }
    );
}

fn row(label: &str, value: impl std::fmt::Display) {
    println!("  {:<18} {value}", format!("{label}:"));
}

fn mark(ok: bool) -> String {
    if ok {
        c("OK  ", GREEN)
    } else {
        c("FAIL", RED)
    }
}

fn print_json(v: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn btc(sat: u64) -> String {
    format!(
        "{sat} sat  ({}.{:08} BTC)",
        sat / 100_000_000,
        sat % 100_000_000
    )
}

// -------------------------------------------------------------- input ----

fn read_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| Error(format!("{}: {e}", path.display())))
}

/// An argument that is either the data itself or the name of a file holding it.
fn data_arg(s: &str) -> Result<String> {
    if s.len() < 4096 && Path::new(s).is_file() {
        read_file(Path::new(s))
    } else {
        Ok(s.to_string())
    }
}

fn load_keys(keys: &[String], files: &[PathBuf]) -> Result<Vec<SecretKey>> {
    let mut out = Vec::new();
    for k in keys {
        out.push(parse_key(k)?);
    }
    for f in files {
        out.push(parse_key(&read_file(f)?)?);
    }
    if out.is_empty() {
        return Err(Error(
            "give a private key with --key-file (or --key)".into(),
        ));
    }
    Ok(out)
}

// ----------------------------------------------------------- commands ----

fn show_key(sk: &SecretKey, net: Network, json: bool) -> Result<()> {
    let k = key_info(sk, net)?;
    if json {
        return print_json(&k);
    }
    println!(
        "\n{}{}",
        c("PRIVATE KEY", BOLD),
        c("  (keep this secret)", RED)
    );
    row("hex", &k.private_key_hex);
    row("WIF", &k.wif_compressed);
    row("WIF uncompr.", &k.wif_uncompressed);
    head("PUBLIC KEY", "");
    row("compressed", &k.public_key_compressed);
    row("uncompressed", &k.public_key_uncompressed);
    row("x-only (taproot)", &k.public_key_x);
    row("hash160", &k.hash160_compressed);
    head("ADDRESSES", &k.network);
    row("P2PKH legacy", &k.addresses.p2pkh);
    row("  uncompressed", &k.addresses.p2pkh_uncomp);
    row("P2SH-P2WPKH", &k.addresses.p2sh_p2wpkh);
    row("P2WPKH segwit", &k.addresses.p2wpkh);
    row("P2TR taproot", &k.addresses.p2tr);
    println!();
    Ok(())
}

fn show_outcome(oc: &Outcome, out: Option<&Path>, json: bool) -> Result<()> {
    let payload = oc
        .raw
        .as_ref()
        .or(oc.psbt.as_ref())
        .cloned()
        .unwrap_or_default();
    if let Some(path) = out {
        std::fs::write(path, format!("{payload}\n"))
            .map_err(|e| Error(format!("{}: {e}", path.display())))?;
    }
    if json {
        return print_json(oc);
    }
    if oc.complete {
        head("SIGNED TRANSACTION", "verified, not broadcast");
        row("txid", oc.txid.as_deref().unwrap_or(""));
        row("wtxid", oc.wtxid.as_deref().unwrap_or(""));
        row("vsize", format!("{} vB", oc.vsize));
    } else {
        println!(
            "\n{}{}",
            c("PARTIALLY SIGNED TRANSACTION", BOLD),
            c("  (PSBT - needs more signatures)", YELLOW)
        );
        row("vsize", format!("~{} vB once fully signed", oc.vsize));
    }
    row("total in", btc(oc.total_in));
    row("total out", btc(oc.total_out));
    row("fee", format!("{} sat  @ {} sat/vB", oc.fee, oc.fee_rate));
    head("OUTPUTS", "");
    for o in &oc.outputs {
        row(
            &format!("#{} {}", o.index, o.kind),
            format!(
                "{}  {} sat",
                o.address.as_deref().unwrap_or(&o.script_pubkey),
                o.amount_sat
            ),
        );
    }
    head("SIGNATURES", "");
    for s in &oc.signatures {
        let state = format!("{} of {}", s.have, s.need);
        row(
            &format!("input {}", s.index),
            format!(
                "{}  {}  {} sat",
                c(&state, if s.have >= s.need { GREEN } else { YELLOW }),
                s.kind,
                s.amount_sat
            ),
        );
        if !s.missing.is_empty() {
            for k in &s.signed_by {
                println!("      {} {k}", c("signed ", GREEN));
            }
            for k in &s.missing {
                println!("      {} {k}", c("not yet", DIM));
            }
        }
    }
    if oc.complete {
        head("SIGNATURE CHECK", "");
        for v in &oc.verify {
            println!(
                "  input {}  {}  {} - {}",
                v.index,
                mark(v.ok),
                v.kind,
                v.note
            );
        }
        println!(
            "  consensus {} Bitcoin Core script interpreter",
            mark(oc.consensus.as_deref() == Some("ok"))
        );
    }
    for n in &oc.notes {
        println!("{}", c(&format!("  note: {n}"), YELLOW));
    }
    head(if oc.complete { "RAW HEX" } else { "PSBT" }, "");
    println!("{payload}");
    if let Some(path) = out {
        println!("{}", c(&format!("\n  written to {}", path.display()), DIM));
    }
    let tail = if oc.complete {
        "\n  Nothing was broadcast. To publish it yourself, paste the hex into any\n  node or explorer's 'send raw transaction' form.\n"
    } else {
        "\n  This is NOT a transaction yet. Pass the PSBT to the next cosigner:\n      btc-keytool sign <psbt> --key-file <their key>\n"
    };
    println!("{}", c(tail, DIM));
    Ok(())
}

fn kv(v: &Value) {
    if let Some(m) = v.as_object() {
        for (k, val) in m {
            let text = val
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| val.to_string());
            println!("  {:<22} {text}", format!("{k}:"));
        }
    }
}

fn show_tx(d: &Value) {
    row("txid", d["txid"].as_str().unwrap_or(""));
    row("wtxid", d["wtxid"].as_str().unwrap_or(""));
    row("version", &d["version"]);
    row("locktime", &d["locktime"]);
    row("segwit", &d["segwit"]);
    row("size / vsize", format!("{} / {} vB", d["size"], d["vsize"]));
    head("INPUTS", "");
    for (n, i) in d["inputs"].as_array().into_iter().flatten().enumerate() {
        row(
            &format!("#{n}"),
            format!(
                "{}:{}  seq {}",
                i["txid"].as_str().unwrap_or(""),
                i["vout"],
                i["sequence"].as_str().unwrap_or("")
            ),
        );
        let short = |s: &str, n: usize| {
            if s.len() > n {
                format!("{}..", &s[..n])
            } else {
                s.to_string()
            }
        };
        let wit: Vec<String> = i["witness"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|w| short(w.as_str().unwrap_or(""), 24))
            .collect();
        if !wit.is_empty() {
            row("   witness", wit.join(" "));
        }
        let ss = i["script_sig"].as_str().unwrap_or("");
        if !ss.is_empty() {
            row("   scriptSig", short(ss, 72));
        }
    }
    head("OUTPUTS", "");
    for (n, o) in d["outputs"].as_array().into_iter().flatten().enumerate() {
        let to = o["address"]
            .as_str()
            .or(o["script_pubkey"].as_str())
            .unwrap_or("");
        row(
            &format!("#{n} {}", o["type"].as_str().unwrap_or("")),
            format!("{to}  {} sat", o["amount_sat"]),
        );
    }
    println!();
}

fn run(cli: Cli) -> Result<ExitCode> {
    let net = parse_network(&cli.network)?;
    let json = cli.json;
    match cli.cmd {
        Cmd::Key { privkey, file } => {
            let text = match (file, privkey) {
                (Some(f), _) => read_file(&f)?,
                (None, Some(k)) => k,
                (None, None) => {
                    return Err(Error(
                        "give a private key (WIF / hex / decimal) or --file".into(),
                    ))
                }
            };
            show_key(&parse_key(&text)?, net, json)?;
        }
        Cmd::Newkey => show_key(&generate_key(), net, json)?,
        Cmd::Addr { target } => {
            let v = inspect(&target, net)?;
            if json {
                print_json(&v)?
            } else {
                kv(&v)
            }
        }
        Cmd::Multisig {
            threshold,
            pubkeys,
            kind,
            unsorted,
        } => {
            let v = multisig_info(threshold, &pubkeys, &kind, !unsorted, net)?;
            if json {
                print_json(&v)?;
            } else {
                kv(&v);
                println!("{}", c("\n  Every cosigner should run this themselves and compare the address\n  before anyone sends funds to it.\n", DIM));
            }
        }
        Cmd::Build { spec, out, force } => {
            show_outcome(
                &spec::build(&read_file(&spec)?, force)?,
                out.as_deref(),
                json,
            )?;
        }
        Cmd::Sign {
            psbt,
            keys,
            key_files,
            out,
        } => {
            let mut p = parse_psbt(&data_arg(&psbt)?)?;
            let keys = load_keys(&keys, &key_files)?;
            show_outcome(&sign_and_report(&mut p, &keys, net)?, out.as_deref(), json)?;
        }
        Cmd::Combine { psbts, out } => {
            let parsed = psbts
                .iter()
                .map(|p| parse_psbt(&data_arg(p)?))
                .collect::<Result<Vec<_>>>()?;
            show_outcome(&combine(parsed, net)?, out.as_deref(), json)?;
        }
        Cmd::Decode { data } => {
            let d = decode(&data_arg(&data)?, net)?;
            if json {
                print_json(&d)?;
            } else if d["psbt"] == true {
                println!(
                    "\n{}{}",
                    c("PSBT", BOLD),
                    c(
                        if d["complete"] == true {
                            "  (fully signed)"
                        } else {
                            "  (needs more signatures)"
                        },
                        YELLOW
                    )
                );
                row("total in", btc(d["total_in"].as_u64().unwrap_or(0)));
                row("fee", format!("{} sat", d["fee"]));
                for s in d["signatures"].as_array().into_iter().flatten() {
                    row(
                        &format!("input {}", s["index"]),
                        format!(
                            "{} of {}  {}",
                            s["have"],
                            s["need"],
                            s["type"].as_str().unwrap_or("")
                        ),
                    );
                }
                head("UNSIGNED TRANSACTION", "");
                show_tx(&d["unsigned_tx"]);
            } else {
                head("TRANSACTION", "");
                show_tx(&d);
            }
        }
        Cmd::Verify { data, spec } => {
            let spec_text = spec.as_deref().map(read_file).transpose()?;
            let r = verify(&data_arg(&data)?, spec_text.as_deref())?;
            if json {
                print_json(&r)?;
            } else {
                println!();
                for v in &r.inputs {
                    let m = if !v.ok && !r.complete {
                        c("WAIT", YELLOW)
                    } else {
                        mark(v.ok)
                    };
                    println!("  input {}  {m}  {:<28} {}", v.index, v.kind, v.note);
                }
                if let Some(cons) = &r.consensus {
                    println!(
                        "  consensus {} Bitcoin Core script interpreter{}",
                        mark(cons == "ok"),
                        if cons == "ok" {
                            String::new()
                        } else {
                            format!(": {cons}")
                        }
                    );
                }
                let verdict = match (r.valid, r.complete) {
                    (true, _) => c("all signatures valid", GREEN),
                    (false, false) => c(
                        "INCOMPLETE - signatures present are valid, but more are needed",
                        YELLOW,
                    ),
                    (false, true) => c("INVALID", RED),
                };
                println!("\n  {verdict}\n");
            }
            if !r.valid {
                return Ok(ExitCode::FAILURE);
            }
        }
        Cmd::Msg {
            cmd:
                MsgCmd::Sign {
                    message,
                    key,
                    key_file,
                    address,
                },
        } => {
            let keys = load_keys(
                &key.into_iter().collect::<Vec<_>>(),
                &key_file.into_iter().collect::<Vec<_>>(),
            )?;
            let s = sign_message(&keys[0], &message, address.as_deref(), net)?;
            if json {
                print_json(&s)?;
            } else {
                row("address", &s.address);
                row("message", &s.message);
                row("signature", &s.signature);
                row("verified", mark(s.verified));
            }
        }
        Cmd::Msg {
            cmd:
                MsgCmd::Verify {
                    address,
                    signature,
                    message,
                },
        } => {
            let ok = verify_message(&address, &signature, &message)?;
            if json {
                print_json(&json!({ "valid": ok }))?;
            } else {
                println!(
                    "  {}",
                    if ok {
                        c("signature valid", GREEN)
                    } else {
                        c("INVALID", RED)
                    }
                );
            }
            if !ok {
                return Ok(ExitCode::FAILURE);
            }
        }
        Cmd::Selftest { verbose } => {
            let checks = selftest::run();
            let failed = checks.iter().filter(|x| !x.ok).count();
            if json {
                print_json(
                    &json!({ "checks": checks.len(), "failed": failed, "results": checks }),
                )?;
            } else {
                head("running test vectors", "");
                for x in &checks {
                    if !x.ok {
                        println!("  {} {}  {}", c("FAIL", RED), x.name, x.detail);
                    } else if verbose {
                        println!("  {} {}", c("ok  ", GREEN), x.name);
                    }
                }
                let verdict = if failed == 0 {
                    c("all passed", GREEN)
                } else {
                    c(&format!("{failed} FAILED"), RED)
                };
                println!("\n  {} checks, {verdict}\n", checks.len());
            }
            if failed > 0 {
                return Ok(ExitCode::FAILURE);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{}{e}", c("error: ", RED));
            ExitCode::FAILURE
        }
    }
}
