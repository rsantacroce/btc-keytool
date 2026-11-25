// BTC Keytool UI. All logic lives in Rust; this file only collects input,
// calls a command, and renders the reply. No data is fetched from anywhere.
"use strict";

const tauri = window.__TAURI__;
const $ = (id) => document.getElementById(id);
const net = () => $("network").value;
const lines = (text) => text.split("\n").map((l) => l.trim()).filter(Boolean);
const sats = (n) => `${n.toLocaleString("en-US")} sat  (${(n / 1e8).toFixed(8)} BTC)`;

function call(cmd, args) {
  if (!tauri) return Promise.reject("This page must be opened inside the BTC Keytool app.");
  return tauri.core.invoke(cmd, args);
}

// ---------------------------------------------------------------- DOM ----

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === "class") el.className = v;
    else if (k === "onclick") el.addEventListener("click", v);
    else el[k] = v;
  }
  for (const kid of kids.flat()) {
    if (kid != null && kid !== false) el.append(kid);
  }
  return el;
}

function copyButton(text, label = "Copy") {
  const b = h("button", { class: "small", type: "button" }, label);
  b.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const t = h("textarea", { value: text });
      document.body.append(t);
      t.select();
      document.execCommand("copy");
      t.remove();
    }
    b.textContent = "Copied";
    setTimeout(() => (b.textContent = label), 1200);
  });
  return b;
}

const tag = (kind, text) => h("span", { class: `tag ${kind}` }, text);
const banner = (kind, text, sub) => h("div", { class: `banner ${kind}` }, text, sub && h("small", {}, sub));

// rows: [label, value, {mono, secret, copy}]
function table(caption, rows) {
  const t = h("table", {}, caption && h("caption", {}, caption));
  for (const [label, value, opt = {}] of rows) {
    if (value == null || value === "") continue;
    const cls = [opt.mono !== false && typeof value === "string" ? "mono" : "", opt.secret ? "secret" : ""].join(" ").trim();
    const cell = h("td", { class: cls }, value);
    if (opt.copy) cell.append(" ", copyButton(String(value)));
    t.append(h("tr", {}, h("th", {}, label), cell));
  }
  return t;
}

function payload(label, text, ...extra) {
  return h("div", { class: "payload" },
    h("label", {}, label, h("textarea", { class: "mono", rows: Math.min(10, Math.ceil(text.length / 110) + 1), readOnly: true, value: text })),
    h("div", { class: "actions" }, copyButton(text, `Copy ${label.toLowerCase()}`), extra));
}

function show(id, ...nodes) {
  $(id).replaceChildren(...nodes.flat().filter(Boolean));
}

function fail(id, e) {
  show(id, banner("bad", "Error", String(e && e.message ? e.message : e)));
}

function openTab(name) {
  for (const b of document.querySelectorAll("#tabs button")) b.classList.toggle("on", b.dataset.tab === name);
  for (const s of document.querySelectorAll("main > section")) s.classList.toggle("on", s.id === name);
}

// ----------------------------------------------------------- renderers ----

function renderKey(k) {
  return [
    table("Private key - keep this secret", [
      ["hex", k.private_key_hex, { secret: true, copy: true }],
      ["WIF", k.wif_compressed, { secret: true, copy: true }],
      ["WIF uncompressed", k.wif_uncompressed, { secret: true, copy: true }],
    ]),
    table("Public key", [
      ["compressed", k.public_key_compressed, { copy: true }],
      ["uncompressed", k.public_key_uncompressed],
      ["x-only (taproot)", k.public_key_x],
      ["hash160", k.hash160_compressed],
    ]),
    table(`Addresses (${k.network})`, [
      ["P2PKH legacy", k.addresses.p2pkh, { copy: true }],
      ["P2PKH uncompressed", k.addresses.p2pkh_uncomp, { copy: true }],
      ["P2SH-P2WPKH", k.addresses.p2sh_p2wpkh, { copy: true }],
      ["P2WPKH segwit", k.addresses.p2wpkh, { copy: true }],
      ["P2TR taproot", k.addresses.p2tr, { copy: true }],
    ]),
  ];
}

function renderFlat(caption, obj) {
  return table(caption, Object.entries(obj).map(([k, v]) =>
    [k.replace(/_/g, " "), Array.isArray(v) ? v.join("\n") : String(v), { copy: typeof v === "string" && v.length > 20 }]));
}

function signatureRows(signatures) {
  return signatures.map((s) => {
    const done = s.have >= s.need;
    const cell = h("div", {}, tag(done ? "ok" : "warn", `${s.have} of ${s.need}`), ` ${s.type} · ${s.amount_sat.toLocaleString("en-US")} sat`);
    for (const k of s.missing.length ? s.signed_by : []) cell.append(h("div", { class: "mono" }, "signed   ", k));
    for (const k of s.missing) cell.append(h("div", { class: "mono dim" }, "not yet  ", k));
    return [`input ${s.index}`, cell];
  });
}

function checkRows(inputs, consensus, complete = true) {
  const rows = inputs.map((c) => [`input ${c.index}`,
    h("div", {}, c.ok ? tag("ok", "OK") : complete ? tag("bad", "FAIL") : tag("warn", "WAIT"), ` ${c.type} - ${c.note}`)]);
  if (consensus) {
    rows.push(["Bitcoin Core interpreter",
      h("div", {}, consensus === "ok" ? tag("ok", "OK") : tag("bad", "FAIL"), consensus === "ok" ? " every input accepted" : ` ${consensus}`)]);
  }
  return rows;
}

function renderOutcome(oc) {
  const need = oc.signatures.reduce((n, s) => n + Math.max(0, s.need - s.have), 0);
  const nodes = [
    oc.complete
      ? banner("ok", "Fully signed and verified - not broadcast",
          "Every signature was checked by this tool and by Bitcoin Core's script interpreter. Anyone holding this hex can broadcast it.")
      : banner("warn", `Not a transaction yet - ${need} more signature${need === 1 ? "" : "s"} needed`,
          "Pass the PSBT below to the next cosigner. Signatures already present have been verified."),
    table("Summary", [
      ["txid", oc.txid, { copy: true }],
      ["size", `${oc.complete ? "" : "~"}${oc.vsize} vB${oc.complete ? "" : " once fully signed"}`, { mono: false }],
      ["total in", sats(oc.total_in), { mono: false }],
      ["total out", sats(oc.total_out), { mono: false }],
      ["fee", `${oc.fee.toLocaleString("en-US")} sat  @ ${oc.fee_rate} sat/vB`, { mono: false }],
    ]),
    table("Outputs - where the money goes", oc.outputs.map((o) =>
      [`#${o.index} ${o.type}`, h("div", {}, h("span", { class: "mono" }, o.address || o.script_pubkey), `  ·  ${o.amount_sat.toLocaleString("en-US")} sat`)])),
    table("Signatures", signatureRows(oc.signatures)),
    oc.complete && table("Signature check", checkRows(oc.verify, oc.consensus)),
    oc.notes.map((n) => banner(/^(WARNING|NOT)/.test(n) ? "warn" : "ok", n)),
  ];
  if (oc.complete) {
    nodes.push(payload("Raw transaction hex", oc.raw));
  } else {
    nodes.push(payload("PSBT", oc.psbt, h("button", { class: "small", type: "button", onclick: () => {
      $("sign-psbt").value = oc.psbt;
      show("sign-out");
      openTab("sign");
    } }, "Open in Sign PSBT")));
  }
  return nodes;
}

function renderTx(d, caption = "Transaction") {
  return [
    table(caption, [
      ["txid", d.txid, { copy: true }], ["wtxid", d.wtxid],
      ["version / locktime", `${d.version} / ${d.locktime}`, { mono: false }],
      ["size", `${d.size} bytes, ${d.vsize} vB, ${d.weight} WU${d.segwit ? ", segwit" : ""}`, { mono: false }],
      ["total out", sats(d.total_out), { mono: false }],
    ]),
    table("Inputs", d.inputs.map((i, n) => [`#${n}`, h("div", { class: "mono" },
      `${i.txid}:${i.vout}  seq ${i.sequence}`,
      i.script_sig && h("div", { class: "dim" }, `scriptSig ${i.script_sig}`),
      i.witness.map((w) => h("div", { class: "dim" }, `witness ${w || "(empty)"}`)))])),
    table("Outputs", d.outputs.map((o, n) => [`#${n} ${o.type}`, h("div", {},
      h("span", { class: "mono" }, o.address || o.script_pubkey), `  ·  ${o.amount_sat.toLocaleString("en-US")} sat`,
      o.data != null && h("div", { class: "mono dim" }, `data ${o.data}`))])),
  ];
}

function renderDecoded(d) {
  if (!d.psbt) return renderTx(d);
  return [
    banner(d.complete ? "ok" : "warn", d.complete ? "PSBT - fully signed" : "PSBT - needs more signatures"),
    table("Summary", [["total in", sats(d.total_in), { mono: false }], ["fee", `${d.fee.toLocaleString("en-US")} sat`, { mono: false }]]),
    table("Signatures", signatureRows(d.signatures)),
    renderTx(d.unsigned_tx, "Unsigned transaction"),
  ];
}

function renderVerify(r) {
  const head = r.valid
    ? banner("ok", "All signatures valid", "Checked by this tool and by Bitcoin Core's script interpreter.")
    : r.complete
      ? banner("bad", "INVALID", "At least one signature does not verify. Do not rely on this transaction.")
      : banner("warn", "Incomplete", "The signatures present are valid, but more are needed before this is a transaction.");
  return [head, table("Signature check", [["txid", r.txid], ...checkRows(r.inputs, r.consensus, r.complete)])];
}

// ------------------------------------------------------------- examples ----

const EXAMPLES = {
  single: {
    _comment: "Send a fixed amount and return the change. The fee is computed from fee_rate.",
    network: "mainnet",
    key: "PUT-YOUR-WIF-OR-HEX-PRIVATE-KEY-HERE",
    inputs: [{ txid: "txid-of-the-utxo-you-are-spending", vout: 0, amount_sat: 250000, address: "bc1q-the-address-this-utxo-pays-to" }],
    outputs: [{ address: "bc1q-where-you-are-sending", amount_sat: 100000 }],
    change_address: "bc1q-your-own-change-address",
    fee_rate: 8,
  },
  sweep: {
    _comment: "Sweep UTXOs into one address. amount_sat 'all' takes whatever is left after the fee.",
    network: "mainnet",
    inputs: [
      { txid: "…", vout: 0, amount_sat: 40000, address: "1YourLegacyAddress", key: "WIF-for-this-input" },
      { txid: "…", vout: 1, amount_sat: 65000, address: "bc1p-your-taproot-address", key: "WIF-for-this-input" },
    ],
    outputs: [{ address: "bc1q-destination", amount_sat: "all" }],
    fee_rate: 5,
  },
  multisig: {
    _comment: "Spend from a 2-of-3 multisig. Put in the keys you hold (even none): if fewer than 2 are given you get a PSBT for the next cosigner.",
    network: "mainnet",
    keys: ["YOUR-PRIVATE-KEY"],
    inputs: [{
      txid: "…", vout: 0, amount_sat: 500000,
      address: "bc1q-the-multisig-address",
      multisig: { threshold: 2, pubkeys: ["02…cosigner-1", "03…cosigner-2", "02…cosigner-3"] },
    }],
    outputs: [{ address: "bc1q-where-you-are-sending", amount_sat: 120000 }],
    change_address: "bc1q-the-multisig-address",
    fee_rate: 10,
  },
};

// -------------------------------------------------------------- actions ----

const actions = {
  key: async () => show("key-out", renderKey(await call("key_info", { key: $("key-in").value, network: net() }))),
  newkey: async () => {
    const k = await call("new_key", { network: net() });
    $("key-in").value = k.wif_compressed;
    show("key-out", banner("warn", "New key generated", "It exists only on this screen. Write it down before closing the window."), renderKey(k));
  },
  addr: async () => show("addr-out", renderFlat("Result", await call("inspect", { target: $("addr-in").value, network: net() }))),
  multisig: async () => show("multisig-out", renderFlat("Multisig", await call("multisig", {
    threshold: Number($("ms-k").value), pubkeys: lines($("ms-keys").value), kind: $("ms-type").value,
    sorted: $("ms-sorted").checked, network: net(),
  }))),
  build: async () => show("build-out", renderOutcome(await call("build", { spec: $("build-in").value, force: $("build-force").checked }))),
  "sign-review": async () => show("sign-out", renderDecoded(await call("decode", { data: $("sign-psbt").value, network: net() }))),
  sign: async () => show("sign-out", renderOutcome(await call("sign", { psbt: $("sign-psbt").value, keys: $("sign-keys").value, network: net() }))),
  combine: async () => show("combine-out", renderOutcome(await call("combine", { psbts: lines($("combine-in").value), network: net() }))),
  verify: async () => show("verify-out", renderVerify(await call("verify", { data: $("verify-in").value, spec: $("verify-spec").value }))),
  decode: async () => show("decode-out", renderDecoded(await call("decode", { data: $("decode-in").value, network: net() }))),
  "msg-sign": async () => {
    const s = await call("msg_sign", { key: $("msg-key").value, message: $("msg-text").value, address: $("msg-addr").value, network: net() });
    $("msg-vaddr").value = s.address;
    $("msg-sig").value = s.signature;
    show("msg-out", banner("ok", "Signed and verified"), table("Signed message", [
      ["address", s.address, { copy: true }], ["signature", s.signature, { copy: true }]]));
  },
  "msg-verify": async () => {
    const ok = await call("msg_verify", { address: $("msg-vaddr").value, signature: $("msg-sig").value, message: $("msg-text").value });
    show("msg-out", ok
      ? banner("ok", "Signature valid", "The owner of this address signed exactly this message.")
      : banner("bad", "INVALID", "This signature does not match the address and message."));
  },
  selftest: async () => {
    const checks = await call("run_selftest");
    const failed = checks.filter((c) => !c.ok);
    show("selftest-out",
      failed.length ? banner("bad", `${failed.length} of ${checks.length} checks FAILED`, "Do not use this build to sign anything.")
                    : banner("ok", `${checks.length} checks, all passed`),
      table("Checks", checks.map((c) => [c.ok ? tag("ok", "ok") : tag("bad", "FAIL"), c.name + (c.detail ? ` - ${c.detail}` : ""), { mono: false }])));
  },
};

document.addEventListener("click", async (ev) => {
  const el = ev.target.closest("button");
  if (!el) return;
  if (el.dataset.tab) return openTab(el.dataset.tab);
  if (el.dataset.example) {
    $("build-in").value = JSON.stringify(EXAMPLES[el.dataset.example], null, 2);
    return;
  }
  const act = actions[el.dataset.act];
  if (!act) return;
  const out = `${el.closest("section").id}-out`;
  el.disabled = true;
  try {
    await act();
  } catch (e) {
    fail(out, e);
  } finally {
    el.disabled = false;
  }
});

document.addEventListener("change", (ev) => {
  const id = ev.target.dataset && ev.target.dataset.reveal;
  if (id) $(id).classList.toggle("reveal", ev.target.checked);
});

if (!tauri) {
  document.querySelector("header .pill").textContent = "preview only - open inside the app";
}
