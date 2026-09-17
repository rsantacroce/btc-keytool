#!/usr/bin/env python3
"""
btc-keytool - offline Bitcoin key & transaction tool.

Zero dependencies. Pure-Python secp256k1. Never touches the network:
socket access is disabled at import time (see _airgap below), so this
process cannot broadcast anything even if you asked it to.

  key      derive public key + every address type from a private key
  newkey   generate a new key from os.urandom
  addr     inspect an address or public key
  build    build and SIGN a transaction offline -> raw hex (not broadcast)
  decode   decode a raw transaction hex
  verify   verify the signatures in a signed transaction
  selftest run the built-in test vectors
"""

import sys, os, json, hashlib, hmac, binascii, argparse, struct

# ---------------------------------------------------------------- air gap ---

def _airgap():
    """Make network use impossible for the life of this process."""
    msg = "btc-keytool is offline-only: network access is disabled"
    try:
        import socket

        def _blocked(*a, **k):
            raise RuntimeError(msg)

        class _BlockedSocket(object):
            """A class, not a function, so libraries that subclass it still
            get a clear error at the moment they try to connect."""
            def __init__(self, *a, **k):
                raise RuntimeError(msg)

        socket.socket = _BlockedSocket
        for _n in ("create_connection", "socketpair", "getaddrinfo",
                   "gethostbyname", "create_server"):
            if hasattr(socket, _n):
                setattr(socket, _n, _blocked)
    except Exception:
        pass

_airgap()

# ---------------------------------------------------------------- hashing ---

def sha256(b):  return hashlib.sha256(b).digest()
def dsha256(b): return sha256(sha256(b))

def _ripemd160_py(msg):
    """Pure-Python RIPEMD-160 (OpenSSL 3 often drops it)."""
    RL = [
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
        7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
        3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
        1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
        4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    RR = [
        5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
        6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
        15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
        8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
        12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
    SL = [
        11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
        7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
        11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
        11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
        9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
    SR = [
        8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
        9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
        9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
        15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
        8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]
    KL = [0x00000000,0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xA953FD4E]
    KR = [0x50A28BE6,0x5C4DD124,0x6D703EF3,0x7A6D76E9,0x00000000]
    M = 0xffffffff
    def rol(x, n): return ((x << n) | (x >> (32 - n))) & M
    def f(j, x, y, z):
        if j < 16:  return x ^ y ^ z
        if j < 32:  return (x & y) | (~x & M & z)
        if j < 48:  return (x | (~y & M)) ^ z
        if j < 64:  return (x & z) | (y & (~z & M))
        return x ^ (y | (~z & M))

    ml = len(msg)
    msg = msg + b"\x80"
    msg += b"\x00" * ((56 - len(msg) % 64) % 64)
    msg += (ml * 8 & 0xffffffffffffffff).to_bytes(8, "little")

    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off:off + 64]))
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            t = (rol((al + f(j, bl, cl, dl) + X[RL[j]] + KL[j // 16]) & M, SL[j]) + el) & M
            al, bl, cl, dl, el = el, t, bl, rol(cl, 10), dl
            t = (rol((ar + f(79 - j, br, cr, dr) + X[RR[j]] + KR[j // 16]) & M, SR[j]) + er) & M
            ar, br, cr, dr, er = er, t, br, rol(cr, 10), dr
        h = [(h[1] + cl + dr) & M, (h[2] + dl + er) & M, (h[3] + el + ar) & M,
             (h[4] + al + br) & M, (h[0] + bl + cr) & M]
    return struct.pack("<5I", *h)

try:
    hashlib.new("ripemd160", b"").digest()
    def ripemd160(b): return hashlib.new("ripemd160", b).digest()
except Exception:
    ripemd160 = _ripemd160_py

def hash160(b): return ripemd160(sha256(b))

def tagged_hash(tag, msg):
    t = sha256(tag.encode())
    return sha256(t + t + msg)

def hx(b):  return binascii.hexlify(b).decode()
def unhx(s): return binascii.unhexlify(s.strip().replace(" ", ""))

# ---------------------------------------------------------------- base58 ----

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(b):
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out

def b58decode(s):
    n = 0
    for ch in s:
        i = _B58.find(ch)
        if i < 0:
            raise ValueError("bad base58 character %r" % ch)
        n = n * 58 + i
    pad = len(s) - len(s.lstrip("1"))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + body

def b58check_encode(b):
    return b58encode(b + dsha256(b)[:4])

def b58check_decode(s):
    raw = b58decode(s)
    if len(raw) < 5:
        raise ValueError("base58 payload too short")
    body, chk = raw[:-4], raw[-4:]
    if dsha256(body)[:4] != chk:
        raise ValueError("bad base58 checksum")
    return body

# ------------------------------------------------- bech32 / bech32m (BIP173/350)

_B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2bc830a3

def _b32_polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk

def _b32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def _b32_verify(hrp, data):
    c = _b32_polymod(_b32_hrp_expand(hrp) + data)
    if c == 1:      return "bech32"
    if c == BECH32M_CONST: return "bech32m"
    return None

def _b32_create_checksum(hrp, data, spec):
    const = BECH32M_CONST if spec == "bech32m" else 1
    polymod = _b32_polymod(_b32_hrp_expand(hrp) + data + [0] * 6) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data, spec):
    combined = data + _b32_create_checksum(hrp, data, spec)
    return hrp + "1" + "".join([_B32[d] for d in combined])

def bech32_decode(s):
    if any(ord(x) < 33 or ord(x) > 126 for x in s):
        raise ValueError("bech32: invalid character")
    if s.lower() != s and s.upper() != s:
        raise ValueError("bech32: mixed case")
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s) or len(s) > 90:
        raise ValueError("bech32: bad separator position")
    hrp, rest = s[:pos], s[pos + 1:]
    if not all(x in _B32 for x in rest):
        raise ValueError("bech32: invalid data character")
    data = [_B32.index(x) for x in rest]
    spec = _b32_verify(hrp, data)
    if spec is None:
        raise ValueError("bech32: bad checksum")
    return hrp, data[:-6], spec

def convertbits(data, frm, to, pad=True):
    acc = 0; bits = 0; ret = []
    maxv = (1 << to) - 1
    maxacc = (1 << (frm + to - 1)) - 1
    for v in data:
        if v < 0 or (v >> frm):
            raise ValueError("convertbits: value out of range")
        acc = ((acc << frm) | v) & maxacc
        bits += frm
        while bits >= to:
            bits -= to
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (to - bits)) & maxv)
    elif bits >= frm or ((acc << (to - bits)) & maxv):
        raise ValueError("convertbits: invalid padding")
    return ret

# ------------------------------------------------------------- secp256k1 ----
# Affine arithmetic on purpose: slower than Jacobian, far easier to audit.

P  = 2**256 - 2**32 - 977
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G  = (Gx, Gy)

def inv(a, m=P): return pow(a, -1, m)

def point_add(p, q):
    if p is None: return q
    if q is None: return p
    x1, y1 = p; x2, y2 = q
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1) * inv(2 * y1) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)

def point_mul(k, p=G):
    k %= N
    if k == 0 or p is None:
        return None
    r = None
    while k:
        if k & 1:
            r = point_add(r, p)
        p = point_add(p, p)
        k >>= 1
    return r

def point_on_curve(p):
    if p is None: return False
    x, y = p
    return (y * y - x * x * x - 7) % P == 0

def lift_x(x):
    """BIP340 lift_x: the point with even Y for this X, or None."""
    if x >= P: return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    return (x, y if y % 2 == 0 else P - y)

def ser_compressed(p):
    x, y = p
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")

def ser_uncompressed(p):
    x, y = p
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")

def ser_xonly(p):
    return p[0].to_bytes(32, "big")

def parse_pubkey(b):
    if len(b) == 33 and b[0] in (2, 3):
        pt = lift_x(int.from_bytes(b[1:], "big"))
        if pt is None:
            raise ValueError("pubkey: x is not on the curve")
        x, y = pt
        if y % 2 != b[0] % 2:
            y = P - y
        return (x, y)
    if len(b) == 65 and b[0] == 4:
        pt = (int.from_bytes(b[1:33], "big"), int.from_bytes(b[33:], "big"))
        if not point_on_curve(pt):
            raise ValueError("pubkey: point not on curve")
        return pt
    if len(b) == 32:
        pt = lift_x(int.from_bytes(b, "big"))
        if pt is None:
            raise ValueError("x-only pubkey: x is not on the curve")
        return pt
    raise ValueError("pubkey: unrecognised length %d" % len(b))

# ------------------------------------------------------- RFC6979 + ECDSA ----

def rfc6979_k(msg32, seckey_int, extra=b""):
    """Deterministic nonce, RFC6979 with HMAC-SHA256."""
    x = seckey_int.to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + msg32 + extra, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + msg32 + extra, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()

def ecdsa_sign(msg32, seckey_int):
    """Returns (r, s) with s canonically low (BIP62)."""
    z = int.from_bytes(msg32, "big")
    counter = 0
    while True:
        k = rfc6979_k(msg32, seckey_int, b"" if counter == 0 else counter.to_bytes(32, "big"))
        Rp = point_mul(k)
        r = Rp[0] % N
        if r:
            s = (inv(k, N) * (z + r * seckey_int)) % N
            if s:
                if s > N // 2:
                    s = N - s
                return r, s
        counter += 1

def ecdsa_verify(msg32, sig_rs, pubkey_pt):
    r, s = sig_rs
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = int.from_bytes(msg32, "big")
    w = inv(s, N)
    p = point_add(point_mul(z * w % N, G), point_mul(r * w % N, pubkey_pt))
    return p is not None and p[0] % N == r

def der_encode(r, s):
    def enc(v):
        b = v.to_bytes(32, "big").lstrip(b"\x00") or b"\x00"
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b
    body = enc(r) + enc(s)
    return b"\x30" + bytes([len(body)]) + body

def der_decode(b):
    if len(b) < 8 or b[0] != 0x30 or b[1] != len(b) - 2:
        raise ValueError("DER: bad envelope")
    if b[2] != 0x02:
        raise ValueError("DER: expected integer for r")
    rlen = b[3]
    r = int.from_bytes(b[4:4 + rlen], "big")
    off = 4 + rlen
    if b[off] != 0x02:
        raise ValueError("DER: expected integer for s")
    slen = b[off + 1]
    s = int.from_bytes(b[off + 2:off + 2 + slen], "big")
    return r, s

# ---------------------------------------------------- BIP340 Schnorr --------

def schnorr_sign(msg32, seckey_int, aux32=None):
    if not (1 <= seckey_int < N):
        raise ValueError("schnorr: private key out of range")
    if aux32 is None:
        aux32 = b"\x00" * 32
    Pp = point_mul(seckey_int)
    d = seckey_int if Pp[1] % 2 == 0 else N - seckey_int
    t = d ^ int.from_bytes(tagged_hash("BIP0340/aux", aux32), "big")
    rand = tagged_hash("BIP0340/nonce",
                       t.to_bytes(32, "big") + ser_xonly(Pp) + msg32)
    k0 = int.from_bytes(rand, "big") % N
    if k0 == 0:
        raise ValueError("schnorr: nonce is zero (retry with different aux)")
    Rp = point_mul(k0)
    k = k0 if Rp[1] % 2 == 0 else N - k0
    e = int.from_bytes(tagged_hash("BIP0340/challenge",
                                   ser_xonly(Rp) + ser_xonly(Pp) + msg32), "big") % N
    sig = ser_xonly(Rp) + ((k + e * d) % N).to_bytes(32, "big")
    if not schnorr_verify(msg32, sig, ser_xonly(Pp)):
        raise ValueError("schnorr: self-verification failed")
    return sig

def schnorr_verify(msg32, sig64, xonly_pub):
    if len(sig64) != 64 or len(xonly_pub) != 32:
        return False
    Pp = lift_x(int.from_bytes(xonly_pub, "big"))
    if Pp is None:
        return False
    r = int.from_bytes(sig64[:32], "big")
    s = int.from_bytes(sig64[32:], "big")
    if r >= P or s >= N:
        return False
    e = int.from_bytes(tagged_hash("BIP0340/challenge",
                                   sig64[:32] + xonly_pub + msg32), "big") % N
    Rp = point_add(point_mul(s, G), point_mul(N - e, Pp))
    return Rp is not None and Rp[1] % 2 == 0 and Rp[0] == r

def taproot_tweak_seckey(seckey_int, merkle_root=b""):
    """BIP341 key-path: tweak the internal key into the output key."""
    Pp = point_mul(seckey_int)
    d = seckey_int if Pp[1] % 2 == 0 else N - seckey_int
    t = int.from_bytes(tagged_hash("TapTweak", ser_xonly(Pp) + merkle_root), "big")
    if t >= N:
        raise ValueError("taproot: tweak out of range")
    return (d + t) % N

def taproot_tweak_pubkey(xonly_pub, merkle_root=b""):
    Pp = parse_pubkey(xonly_pub if len(xonly_pub) == 32 else xonly_pub)
    t = int.from_bytes(tagged_hash("TapTweak", ser_xonly(Pp) + merkle_root), "big")
    Q = point_add(Pp, point_mul(t))
    return ser_xonly(Q)

# --------------------------------------------------------------- networks ---

NETWORKS = {
    "mainnet": dict(p2pkh=0x00, p2sh=0x05, wif=0x80, hrp="bc"),
    "testnet": dict(p2pkh=0x6f, p2sh=0xc4, wif=0xef, hrp="tb"),
    "signet":  dict(p2pkh=0x6f, p2sh=0xc4, wif=0xef, hrp="tb"),
    "regtest": dict(p2pkh=0x6f, p2sh=0xc4, wif=0xef, hrp="bcrt"),
}

# ------------------------------------------------------------------ keys ----

class Key(object):
    def __init__(self, secret, compressed=True, network="mainnet"):
        if not (1 <= secret < N):
            raise ValueError("private key out of range 1..n-1")
        self.secret = secret
        self.compressed = compressed
        self.network = network
        self.point = point_mul(secret)

    # -- constructors ------------------------------------------------------
    @classmethod
    def parse(cls, text, network="mainnet"):
        """Accepts WIF, 64-char hex, 0x-hex, or a decimal integer."""
        t = text.strip()
        if t.lower().startswith("0x"):
            return cls(int(t, 16), True, network)
        cleaned = t.replace(" ", "")
        if len(cleaned) == 64 and all(c in "0123456789abcdefABCDEF" for c in cleaned):
            return cls(int(cleaned, 16), True, network)
        if cleaned.isdigit():
            return cls(int(cleaned), True, network)
        try:
            return cls.from_wif(t)
        except ValueError as e:
            raise ValueError("could not read private key: expected WIF, 64-char hex, "
                             "0x-hex or decimal (%s)" % e)

    @classmethod
    def from_wif(cls, wif):
        body = b58check_decode(wif)
        prefix, rest = body[0], body[1:]
        net = None
        for name, cfg in NETWORKS.items():
            if cfg["wif"] == prefix:
                net = "mainnet" if prefix == 0x80 else "testnet"
                break
        if net is None:
            raise ValueError("WIF: unknown version byte 0x%02x" % prefix)
        if len(rest) == 33 and rest[32] == 0x01:
            return cls(int.from_bytes(rest[:32], "big"), True, net)
        if len(rest) == 32:
            return cls(int.from_bytes(rest, "big"), False, net)
        raise ValueError("WIF: bad payload length")

    @classmethod
    def generate(cls, network="mainnet"):
        while True:
            s = int.from_bytes(os.urandom(32), "big")
            if 1 <= s < N:
                return cls(s, True, network)

    # -- serialisation -----------------------------------------------------
    @property
    def hex(self): return "%064x" % self.secret

    def wif(self, compressed=None, network=None):
        net = network or self.network
        comp = self.compressed if compressed is None else compressed
        body = bytes([NETWORKS[net]["wif"]]) + self.secret.to_bytes(32, "big")
        if comp:
            body += b"\x01"
        return b58check_encode(body)

    def pubkey(self, compressed=None):
        comp = self.compressed if compressed is None else compressed
        return ser_compressed(self.point) if comp else ser_uncompressed(self.point)

    def xonly(self): return ser_xonly(self.point)

# -------------------------------------------------------------- scripts -----

OP_DUP, OP_HASH160, OP_EQUAL, OP_EQUALVERIFY, OP_CHECKSIG = 0x76, 0xa9, 0x87, 0x88, 0xac

def push(data):
    n = len(data)
    if n < 0x4c:   return bytes([n]) + data
    if n <= 0xff:  return b"\x4c" + bytes([n]) + data
    if n <= 0xffff: return b"\x4d" + n.to_bytes(2, "little") + data
    return b"\x4e" + n.to_bytes(4, "little") + data

def p2pkh_script(h160):   return bytes([OP_DUP, OP_HASH160]) + push(h160) + bytes([OP_EQUALVERIFY, OP_CHECKSIG])
def p2sh_script(h160):    return bytes([OP_HASH160]) + push(h160) + bytes([OP_EQUAL])
def p2wpkh_script(h160):  return b"\x00" + push(h160)
def p2wsh_script(sha):    return b"\x00" + push(sha)
def p2tr_script(xonly):   return b"\x51" + push(xonly)

def witness_v0_redeem(h160):
    """redeemScript for P2SH-wrapped P2WPKH."""
    return p2wpkh_script(h160)

# ------------------------------------------------------------- addresses ----

def addresses_for_key(key, network=None):
    net = network or key.network
    cfg = NETWORKS[net]
    pk_c = key.pubkey(True)
    pk_u = key.pubkey(False)
    h160_c = hash160(pk_c)
    h160_u = hash160(pk_u)
    redeem = witness_v0_redeem(h160_c)
    tweaked = ser_xonly(point_mul(taproot_tweak_seckey(key.secret)))
    return {
        "p2pkh":        b58check_encode(bytes([cfg["p2pkh"]]) + h160_c),
        "p2pkh_uncomp": b58check_encode(bytes([cfg["p2pkh"]]) + h160_u),
        "p2sh_p2wpkh":  b58check_encode(bytes([cfg["p2sh"]]) + hash160(redeem)),
        "p2wpkh":       bech32_encode(cfg["hrp"], [0] + convertbits(h160_c, 8, 5), "bech32"),
        "p2tr":         bech32_encode(cfg["hrp"], [1] + convertbits(tweaked, 8, 5), "bech32m"),
    }

def address_to_script(addr, network=None):
    """Address -> (scriptPubKey, type, detected-network)."""
    a = addr.strip()
    # bech32 / bech32m
    if "1" in a and a.lower()[:4] in ("bc1q", "bc1p", "tb1q", "tb1p", "bcr", "bc1", "tb1"):
        try:
            hrp, data, spec = bech32_decode(a)
        except ValueError:
            hrp = None
        if hrp is not None:
            net = next((n for n, c in NETWORKS.items() if c["hrp"] == hrp), None)
            if net is None:
                raise ValueError("address: unknown bech32 prefix %r" % hrp)
            ver = data[0]
            prog = bytes(convertbits(data[1:], 5, 8, False))
            if ver == 0:
                if spec != "bech32":
                    raise ValueError("address: v0 must use bech32, not bech32m")
                if len(prog) == 20:
                    return p2wpkh_script(prog), "p2wpkh", net
                if len(prog) == 32:
                    return p2wsh_script(prog), "p2wsh", net
                raise ValueError("address: bad v0 program length")
            if spec != "bech32m":
                raise ValueError("address: v1+ must use bech32m")
            if ver == 1 and len(prog) == 32:
                return p2tr_script(prog), "p2tr", net
            if not (2 <= len(prog) <= 40) or ver > 16:
                raise ValueError("address: bad witness program")
            return bytes([0x50 + ver]) + push(prog), "witness_v%d" % ver, net
    # base58
    body = b58check_decode(a)
    if len(body) != 21:
        raise ValueError("address: bad base58 length")
    ver, h = body[0], body[1:]
    for name, cfg in NETWORKS.items():
        if ver == cfg["p2pkh"]:
            return p2pkh_script(h), "p2pkh", name
        if ver == cfg["p2sh"]:
            return p2sh_script(h), "p2sh", name
    raise ValueError("address: unknown version byte 0x%02x" % ver)

def script_to_address(spk, network="mainnet"):
    """scriptPubKey -> (address or None, type)."""
    cfg = NETWORKS[network]
    if len(spk) == 25 and spk[0] == OP_DUP and spk[1] == OP_HASH160 and spk[2] == 20 \
            and spk[23] == OP_EQUALVERIFY and spk[24] == OP_CHECKSIG:
        return b58check_encode(bytes([cfg["p2pkh"]]) + spk[3:23]), "p2pkh"
    if len(spk) == 23 and spk[0] == OP_HASH160 and spk[1] == 20 and spk[22] == OP_EQUAL:
        return b58check_encode(bytes([cfg["p2sh"]]) + spk[2:22]), "p2sh"
    if len(spk) == 22 and spk[0] == 0x00 and spk[1] == 20:
        return bech32_encode(cfg["hrp"], [0] + convertbits(spk[2:], 8, 5), "bech32"), "p2wpkh"
    if len(spk) == 34 and spk[0] == 0x00 and spk[1] == 32:
        return bech32_encode(cfg["hrp"], [0] + convertbits(spk[2:], 8, 5), "bech32"), "p2wsh"
    if len(spk) == 34 and spk[0] == 0x51 and spk[1] == 32:
        return bech32_encode(cfg["hrp"], [1] + convertbits(spk[2:], 8, 5), "bech32m"), "p2tr"
    if len(spk) in (35, 67) and spk[-1] == OP_CHECKSIG and spk[0] == len(spk) - 2:
        return None, "p2pk"
    if spk[:1] == b"\x6a":
        return None, "op_return"
    return None, "nonstandard"

def classify_script(spk):
    return script_to_address(spk)[1]

# ------------------------------------------------------- tx serialisation ---

SIGHASH_ALL          = 0x01
SIGHASH_NONE         = 0x02
SIGHASH_SINGLE       = 0x03
SIGHASH_ANYONECANPAY = 0x80
SIGHASH_DEFAULT      = 0x00   # taproot only

def varint(n):
    if n < 0xfd:        return bytes([n])
    if n <= 0xffff:     return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xffffffff: return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")

def varbytes(b): return varint(len(b)) + b

class Reader(object):
    def __init__(self, b): self.b, self.i = b, 0
    def take(self, n):
        if self.i + n > len(self.b):
            raise ValueError("tx: truncated")
        out = self.b[self.i:self.i + n]; self.i += n
        return out
    def u8(self):  return self.take(1)[0]
    def u16(self): return int.from_bytes(self.take(2), "little")
    def u32(self): return int.from_bytes(self.take(4), "little")
    def u64(self): return int.from_bytes(self.take(8), "little")
    def varint(self):
        p = self.u8()
        if p < 0xfd: return p
        if p == 0xfd: return self.u16()
        if p == 0xfe: return self.u32()
        return self.u64()
    def varbytes(self): return self.take(self.varint())
    def eof(self): return self.i >= len(self.b)

class TxIn(object):
    def __init__(self, txid, vout, script_sig=b"", sequence=0xfffffffd, witness=None):
        self.txid = txid            # display order (big-endian hex string)
        self.vout = vout
        self.script_sig = script_sig
        self.sequence = sequence
        self.witness = witness or []

    def outpoint(self):
        return unhx(self.txid)[::-1] + self.vout.to_bytes(4, "little")

    def ser(self, with_script=True):
        s = self.script_sig if with_script else b""
        return self.outpoint() + varbytes(s) + self.sequence.to_bytes(4, "little")

class TxOut(object):
    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey
    def ser(self):
        return self.amount.to_bytes(8, "little") + varbytes(self.script_pubkey)

class Tx(object):
    def __init__(self, version=2, vin=None, vout=None, locktime=0):
        self.version = version
        self.vin = vin or []
        self.vout = vout or []
        self.locktime = locktime

    def has_witness(self):
        return any(i.witness for i in self.vin)

    def ser(self, witness=None):
        w = self.has_witness() if witness is None else witness
        out = self.version.to_bytes(4, "little")
        if w:
            out += b"\x00\x01"
        out += varint(len(self.vin)) + b"".join(i.ser() for i in self.vin)
        out += varint(len(self.vout)) + b"".join(o.ser() for o in self.vout)
        if w:
            for i in self.vin:
                out += varint(len(i.witness)) + b"".join(varbytes(x) for x in i.witness)
        out += self.locktime.to_bytes(4, "little")
        return out

    def txid(self):  return hx(dsha256(self.ser(witness=False))[::-1])
    def wtxid(self): return hx(dsha256(self.ser())[::-1])

    def vsize(self):
        base = len(self.ser(witness=False))
        total = len(self.ser())
        return (base * 3 + total + 3) // 4

    def weight(self):
        return len(self.ser(witness=False)) * 3 + len(self.ser())

    @classmethod
    def parse(cls, raw):
        r = Reader(raw)
        tx = cls()
        tx.version = r.u32()
        marker_pos = r.i
        segwit = False
        n_in = r.varint()
        if n_in == 0:
            flag = r.u8()
            if flag != 1:
                raise ValueError("tx: bad segwit flag")
            segwit = True
            n_in = r.varint()
        for _ in range(n_in):
            op = r.take(32)[::-1]
            vout = r.u32()
            ss = r.varbytes()
            seq = r.u32()
            tx.vin.append(TxIn(hx(op), vout, ss, seq))
        for _ in range(r.varint()):
            amt = r.u64()
            tx.vout.append(TxOut(amt, r.varbytes()))
        if segwit:
            for i in tx.vin:
                i.witness = [r.varbytes() for _ in range(r.varint())]
        tx.locktime = r.u32()
        if not r.eof():
            raise ValueError("tx: %d trailing bytes" % (len(raw) - r.i))
        return tx

# ---------------------------------------------------------------- sighash ---

def legacy_sighash(tx, index, script_code, hashtype):
    """Pre-segwit signature hash (BIP143 predecessor)."""
    ins = []
    for n, i in enumerate(tx.vin):
        if hashtype & SIGHASH_ANYONECANPAY and n != index:
            continue
        script = script_code if n == index else b""
        seq = i.sequence
        if n != index and (hashtype & 0x1f) in (SIGHASH_NONE, SIGHASH_SINGLE):
            seq = 0
        ins.append(i.outpoint() + varbytes(script) + seq.to_bytes(4, "little"))

    base = hashtype & 0x1f
    if base == SIGHASH_NONE:
        outs = []
    elif base == SIGHASH_SINGLE:
        if index >= len(tx.vout):
            return b"\x00" * 31 + b"\x01"     # the famous SIGHASH_SINGLE bug
        outs = [(b"\xff" * 8 + b"\x00") for _ in range(index)]
        outs.append(tx.vout[index].ser())
    else:
        outs = [o.ser() for o in tx.vout]

    ser = (tx.version.to_bytes(4, "little")
           + varint(len(ins)) + b"".join(ins)
           + varint(len(outs)) + b"".join(outs)
           + tx.locktime.to_bytes(4, "little")
           + hashtype.to_bytes(4, "little"))
    return dsha256(ser)

def bip143_sighash(tx, index, script_code, amount, hashtype):
    """Segwit v0 signature hash."""
    zero = b"\x00" * 32
    anyone = hashtype & SIGHASH_ANYONECANPAY
    base = hashtype & 0x1f

    hash_prevouts = zero if anyone else dsha256(b"".join(i.outpoint() for i in tx.vin))
    if anyone or base in (SIGHASH_NONE, SIGHASH_SINGLE):
        hash_sequence = zero
    else:
        hash_sequence = dsha256(b"".join(i.sequence.to_bytes(4, "little") for i in tx.vin))
    if base not in (SIGHASH_NONE, SIGHASH_SINGLE):
        hash_outputs = dsha256(b"".join(o.ser() for o in tx.vout))
    elif base == SIGHASH_SINGLE and index < len(tx.vout):
        hash_outputs = dsha256(tx.vout[index].ser())
    else:
        hash_outputs = zero

    i = tx.vin[index]
    pre = (tx.version.to_bytes(4, "little")
           + hash_prevouts + hash_sequence
           + i.outpoint()
           + varbytes(script_code)
           + amount.to_bytes(8, "little")
           + i.sequence.to_bytes(4, "little")
           + hash_outputs
           + tx.locktime.to_bytes(4, "little")
           + hashtype.to_bytes(4, "little"))
    return dsha256(pre)

def bip341_sighash(tx, index, prevouts, hashtype=SIGHASH_DEFAULT, annex=None):
    """Taproot key-path signature hash. prevouts = list of TxOut for every input."""
    if len(prevouts) != len(tx.vin):
        raise ValueError("taproot: need the prevout of every input, got %d of %d"
                         % (len(prevouts), len(tx.vin)))
    anyone = hashtype & SIGHASH_ANYONECANPAY
    base = hashtype & 0x03

    ss = bytes([0, hashtype])                      # epoch + hash_type
    ss += tx.version.to_bytes(4, "little")
    ss += tx.locktime.to_bytes(4, "little")
    if not anyone:
        ss += sha256(b"".join(i.outpoint() for i in tx.vin))
        ss += sha256(b"".join(p.amount.to_bytes(8, "little") for p in prevouts))
        ss += sha256(b"".join(varbytes(p.script_pubkey) for p in prevouts))
        ss += sha256(b"".join(i.sequence.to_bytes(4, "little") for i in tx.vin))
    if base == SIGHASH_DEFAULT or base == SIGHASH_ALL:
        ss += sha256(b"".join(o.ser() for o in tx.vout))

    spend_type = 0 * 2 + (1 if annex is not None else 0)   # ext_flag 0 = key path
    ss += bytes([spend_type])
    if anyone:
        ss += tx.vin[index].outpoint()
        ss += prevouts[index].amount.to_bytes(8, "little")
        ss += varbytes(prevouts[index].script_pubkey)
        ss += tx.vin[index].sequence.to_bytes(4, "little")
    else:
        ss += index.to_bytes(4, "little")
    if annex is not None:
        ss += sha256(varbytes(annex))
    if base == SIGHASH_SINGLE:
        ss += sha256(tx.vout[index].ser())
    return tagged_hash("TapSighash", ss)

# ---------------------------------------------------------------- signing ---

class Prevout(object):
    """A UTXO being spent, plus the key that unlocks it."""
    def __init__(self, txid, vout, amount, script_pubkey, key=None,
                 sequence=0xfffffffd, sighash=None):
        self.txid = txid
        self.vout = vout
        self.amount = amount
        self.script_pubkey = script_pubkey
        self.key = key
        self.sequence = sequence
        self.type = classify_script(script_pubkey)
        self.sighash = sighash

    def txout(self): return TxOut(self.amount, self.script_pubkey)

def _check_key_matches(prev, key):
    """Refuse to sign with a key that cannot possibly unlock this output."""
    spk, t = prev.script_pubkey, prev.type
    if t == "p2pkh":
        want = spk[3:23]
        for comp in (True, False):
            if hash160(key.pubkey(comp)) == want:
                return comp
        raise ValueError("input %s:%d is p2pkh for a different key" % (prev.txid, prev.vout))
    if t == "p2wpkh":
        if hash160(key.pubkey(True)) != spk[2:]:
            raise ValueError("input %s:%d is p2wpkh for a different key" % (prev.txid, prev.vout))
        return True
    if t == "p2sh":
        redeem = witness_v0_redeem(hash160(key.pubkey(True)))
        if hash160(redeem) != spk[2:22]:
            raise ValueError("input %s:%d is p2sh but not the p2sh-p2wpkh of this key "
                             "(other p2sh scripts are not supported)" % (prev.txid, prev.vout))
        return True
    if t == "p2tr":
        if ser_xonly(point_mul(taproot_tweak_seckey(key.secret))) != spk[2:]:
            raise ValueError("input %s:%d is p2tr for a different key (or a script-path "
                             "output, which is not supported)" % (prev.txid, prev.vout))
        return True
    if t == "p2pk":
        want = spk[1:-1]
        for comp in (True, False):
            if key.pubkey(comp) == want:
                return comp
        raise ValueError("input %s:%d is p2pk for a different key" % (prev.txid, prev.vout))
    raise ValueError("input %s:%d has unsupported script type %r" % (prev.txid, prev.vout, t))

def sign_input(tx, index, prevouts, key, aux_rand=None):
    """Sign one input in place. prevouts: list of Prevout for the whole tx."""
    prev = prevouts[index]
    comp = _check_key_matches(prev, key)
    t = prev.type
    txin = tx.vin[index]

    if t == "p2tr":
        ht = SIGHASH_DEFAULT if prev.sighash is None else prev.sighash
        h = bip341_sighash(tx, index, [p.txout() for p in prevouts], ht)
        sig = schnorr_sign(h, taproot_tweak_seckey(key.secret), aux_rand)
        if ht != SIGHASH_DEFAULT:
            sig += bytes([ht])
        txin.witness = [sig]
        txin.script_sig = b""
        return

    ht = SIGHASH_ALL if prev.sighash is None else prev.sighash
    pub = key.pubkey(comp)

    if t == "p2wpkh":
        script_code = p2pkh_script(hash160(pub))
        h = bip143_sighash(tx, index, script_code, prev.amount, ht)
        sig = der_encode(*ecdsa_sign(h, key.secret)) + bytes([ht])
        txin.witness = [sig, pub]
        txin.script_sig = b""
    elif t == "p2sh":                       # p2sh-wrapped p2wpkh
        redeem = witness_v0_redeem(hash160(pub))
        script_code = p2pkh_script(hash160(pub))
        h = bip143_sighash(tx, index, script_code, prev.amount, ht)
        sig = der_encode(*ecdsa_sign(h, key.secret)) + bytes([ht])
        txin.witness = [sig, pub]
        txin.script_sig = push(redeem)
    elif t == "p2pkh":
        h = legacy_sighash(tx, index, prev.script_pubkey, ht)
        sig = der_encode(*ecdsa_sign(h, key.secret)) + bytes([ht])
        txin.witness = []
        txin.script_sig = push(sig) + push(pub)
    elif t == "p2pk":
        h = legacy_sighash(tx, index, prev.script_pubkey, ht)
        sig = der_encode(*ecdsa_sign(h, key.secret)) + bytes([ht])
        txin.witness = []
        txin.script_sig = push(sig)
    else:
        raise ValueError("cannot sign script type %r" % t)

def sign_tx(tx, prevouts, aux_rand=None):
    for n, p in enumerate(prevouts):
        if p.key is None:
            raise ValueError("input %d (%s:%d) has no private key" % (n, p.txid, p.vout))
        sign_input(tx, n, prevouts, p.key, aux_rand)
    return tx

def verify_tx(tx, prevouts):
    """Check every input's signature. Returns list of (index, type, ok, note)."""
    results = []
    for n, prev in enumerate(prevouts):
        t = prev.type
        txin = tx.vin[n]
        try:
            if t == "p2tr":
                if len(txin.witness) != 1:
                    raise ValueError("expected a 1-element key-path witness")
                sig = txin.witness[0]
                ht = SIGHASH_DEFAULT
                if len(sig) == 65:
                    ht, sig = sig[64], sig[:64]
                h = bip341_sighash(tx, n, [p.txout() for p in prevouts], ht)
                ok = schnorr_verify(h, sig, prev.script_pubkey[2:])
                results.append((n, t, ok, "schnorr key-path, sighash 0x%02x" % ht))
                continue

            if t in ("p2wpkh", "p2sh"):
                sig, pub = txin.witness[0], txin.witness[1]
                ht = sig[-1]
                h = bip143_sighash(tx, n, p2pkh_script(hash160(pub)), prev.amount, ht)
            elif t in ("p2pkh", "p2pk"):
                r = Reader(txin.script_sig)
                sig = r.varbytes()
                pub = r.varbytes() if t == "p2pkh" else prev.script_pubkey[1:-1]
                ht = sig[-1]
                h = legacy_sighash(tx, n, prev.script_pubkey, ht)
            else:
                results.append((n, t, False, "unsupported script type"))
                continue
            rs = der_decode(sig[:-1])
            ok = ecdsa_verify(h, rs, parse_pubkey(pub))
            low_s = rs[1] <= N // 2
            note = "ecdsa, sighash 0x%02x%s" % (ht, "" if low_s else ", HIGH-S (non-standard)")
            results.append((n, t, ok and low_s, note))
        except Exception as e:
            results.append((n, t, False, "error: %s" % e))
    return results

# ------------------------------------------------------- fees & building ----

DUST_RELAY_FEE = 3   # sat/vB

def dust_threshold(spk):
    """Bitcoin Core GetDustThreshold()."""
    out_size = 8 + len(varbytes(spk))
    spend_cost = 67 if spk[:1] in (b"\x00", b"\x51") else 148   # witness vs legacy input
    return (out_size + spend_cost) * DUST_RELAY_FEE

def _sign_estimate(tx, prevouts):
    """Sign a scratch copy to learn the real vsize."""
    scratch = Tx.parse(tx.ser(witness=False))
    sign_tx(scratch, prevouts)
    return scratch.vsize()

def build_from_spec(spec, force=False):
    """Build and sign a transaction from a JSON spec. Returns (tx, info)."""
    net = spec.get("network", "mainnet")
    if net not in NETWORKS:
        raise ValueError("unknown network %r" % net)
    default_key = spec.get("key")

    # ---- inputs ----------------------------------------------------------
    prevouts = []
    for n, i in enumerate(spec.get("inputs", [])):
        if "script_pubkey" in i:
            spk = unhx(i["script_pubkey"])
        elif "address" in i:
            spk, _, anet = address_to_script(i["address"], net)
            if anet != net and not (anet, net) in (("testnet", "signet"), ("signet", "testnet")):
                raise ValueError("input %d: address is %s but network is %s" % (n, anet, net))
        else:
            raise ValueError("input %d: needs script_pubkey or address" % n)
        amt = i.get("amount_sat")
        if amt is None:
            raise ValueError("input %d: amount_sat is required (segwit signing commits to it)" % n)
        kt = i.get("key", default_key)
        key = Key.parse(kt, net) if kt else None
        prevouts.append(Prevout(i["txid"], int(i["vout"]), int(amt), spk, key,
                                int(i.get("sequence", 0xfffffffd)),
                                i.get("sighash")))
    if not prevouts:
        raise ValueError("spec has no inputs")

    # ---- outputs ---------------------------------------------------------
    outs, sweep_index = [], None
    for n, o in enumerate(spec.get("outputs", [])):
        if "op_return" in o:
            data = o["op_return"]
            data = unhx(data) if o.get("hex") else data.encode()
            if len(data) > 80:
                raise ValueError("output %d: OP_RETURN payload over 80 bytes" % n)
            outs.append(TxOut(int(o.get("amount_sat", 0)), b"\x6a" + push(data)))
            continue
        if "script_pubkey" in o:
            spk = unhx(o["script_pubkey"])
        elif "address" in o:
            spk, _, anet = address_to_script(o["address"], net)
            if anet != net and not (anet, net) in (("testnet", "signet"), ("signet", "testnet")):
                raise ValueError("output %d: address is %s but network is %s" % (n, anet, net))
        else:
            raise ValueError("output %d: needs address, script_pubkey or op_return" % n)
        amt = o.get("amount_sat")
        if isinstance(amt, str) and amt.lower() in ("all", "max", "sweep"):
            if sweep_index is not None:
                raise ValueError("only one output may be 'all'")
            sweep_index = len(outs)
            amt = 0
        outs.append(TxOut(int(amt), spk))

    total_in = sum(p.amount for p in prevouts)
    tx = Tx(int(spec.get("version", 2)),
            [TxIn(p.txid, p.vout, b"", p.sequence) for p in prevouts],
            outs, int(spec.get("locktime", 0)))

    fee_rate = spec.get("fee_rate")
    change_addr = spec.get("change_address")
    notes = []

    # ---- fee / change ----------------------------------------------------
    if sweep_index is not None:
        if fee_rate is None:
            raise ValueError("an 'all' output needs fee_rate (sat/vB)")
        fixed = sum(o.amount for n, o in enumerate(tx.vout) if n != sweep_index)
        tx.vout[sweep_index].amount = max(0, total_in - fixed)   # placeholder to size the tx
        vsize_est = 0
        for _ in range(4):
            # never shrink the estimate: DER signatures vary by a byte between
            # passes, and undershooting would put us below the requested rate
            vsize_est = max(vsize_est, _sign_estimate(tx, prevouts))
            fee = int(round(vsize_est * float(fee_rate)))
            new = total_in - fixed - fee
            if new <= 0:
                raise ValueError("inputs (%d sat) cannot cover the fee (%d sat)" % (total_in, fee))
            if new == tx.vout[sweep_index].amount:
                break
            tx.vout[sweep_index].amount = new
        notes.append("output %d swept the remaining balance" % sweep_index)
    elif change_addr is not None:
        if fee_rate is None:
            raise ValueError("change_address needs fee_rate (sat/vB)")
        cspk, _, cnet = address_to_script(change_addr, net)
        spent = sum(o.amount for o in tx.vout)
        tx.vout.append(TxOut(max(0, total_in - spent), cspk))   # placeholder to size the tx
        ci = len(tx.vout) - 1
        vsize_est = 0
        for _ in range(4):
            vsize_est = max(vsize_est, _sign_estimate(tx, prevouts))
            fee = int(round(vsize_est * float(fee_rate)))
            new = total_in - spent - fee
            if new < 0:
                raise ValueError("inputs (%d sat) cannot cover outputs (%d sat) + fee (%d sat)"
                                 % (total_in, spent, fee))
            if new == tx.vout[ci].amount:
                break
            tx.vout[ci].amount = new
        dust = dust_threshold(cspk)
        if tx.vout[ci].amount < dust:
            notes.append("change of %d sat was below the dust limit (%d) and went to fee"
                         % (tx.vout[ci].amount, dust))
            tx.vout.pop()
        else:
            notes.append("change output %d added" % ci)

    # ---- sanity ----------------------------------------------------------
    total_out = sum(o.amount for o in tx.vout)
    fee = total_in - total_out
    if fee < 0:
        raise ValueError("outputs (%d sat) exceed inputs (%d sat)" % (total_out, total_in))
    for n, o in enumerate(tx.vout):
        if o.script_pubkey[:1] != b"\x6a" and 0 < o.amount < dust_threshold(o.script_pubkey):
            notes.append("WARNING output %d is dust (%d sat) and will not relay" % (n, o.amount))
    if not force and total_in and fee > max(100000, total_in * 0.5):
        raise ValueError("fee of %d sat looks like a mistake (%.1f%% of input). "
                         "Re-run with --force if you meant it." % (fee, 100.0 * fee / total_in))

    sign_tx(tx, prevouts)
    vsize = tx.vsize()
    info = dict(network=net, txid=tx.txid(), wtxid=tx.wtxid(),
                vsize=vsize, weight=tx.weight(), size=len(tx.ser()),
                total_in=total_in, total_out=total_out, fee=fee,
                fee_rate=round(fee / float(vsize), 2) if vsize else 0,
                notes=notes,
                verify=[dict(index=n, type=t, ok=ok, note=note)
                        for n, t, ok, note in verify_tx(tx, prevouts)])
    return tx, info

def decode_tx(raw, network="mainnet"):
    tx = Tx.parse(raw)
    d = dict(txid=tx.txid(), wtxid=tx.wtxid(), version=tx.version, locktime=tx.locktime,
             size=len(raw), vsize=tx.vsize(), weight=tx.weight(),
             segwit=tx.has_witness(), inputs=[], outputs=[])
    for i in tx.vin:
        d["inputs"].append(dict(txid=i.txid, vout=i.vout,
                                script_sig=hx(i.script_sig),
                                sequence="0x%08x" % i.sequence,
                                witness=[hx(w) for w in i.witness]))
    total = 0
    for o in tx.vout:
        addr, t = script_to_address(o.script_pubkey, network)
        total += o.amount
        e = dict(amount_sat=o.amount, amount_btc="%.8f" % (o.amount / 1e8),
                 type=t, script_pubkey=hx(o.script_pubkey))
        if addr:
            e["address"] = addr
        if t == "op_return":
            try:
                e["data"] = hx(Reader(o.script_pubkey[1:]).varbytes())
            except Exception:
                pass
        d["outputs"].append(e)
    d["total_out"] = total
    return tx, d

# ------------------------------------------------------------------- CLI ----

BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
GREEN, RED, YELL = "\033[32m", "\033[31m", "\033[33m"

def _c(s, col):
    return s if os.environ.get("NO_COLOR") or not sys.stdout.isatty() else col + s + RESET

def _row(label, value):
    print("  %-16s %s" % (label + ":", value))

def cmd_key(args):
    text = args.privkey
    if args.file:
        with open(args.file) as f:
            text = f.read().strip()
    if text is None:
        raise SystemExit("give a private key (WIF / hex / decimal) or --file")
    key = Key.parse(text, args.network)
    net = args.network
    addrs = addresses_for_key(key, net)
    pk_c, pk_u = key.pubkey(True), key.pubkey(False)
    out = dict(network=net, private_key_hex=key.hex,
               wif_compressed=key.wif(True, net), wif_uncompressed=key.wif(False, net),
               public_key_compressed=hx(pk_c), public_key_uncompressed=hx(pk_u),
               public_key_x=hx(key.xonly()), public_key_y="%064x" % key.point[1],
               hash160_compressed=hx(hash160(pk_c)),
               addresses=addrs,
               script_pubkeys={k: hx(address_to_script(v, net)[0]) for k, v in addrs.items()})
    if args.json:
        print(json.dumps(out, indent=2))
        return
    print(_c("\nPRIVATE KEY", BOLD) + _c("  (keep this secret)", RED))
    _row("hex", key.hex)
    _row("WIF", key.wif(True, net))
    _row("WIF uncompr.", key.wif(False, net))
    print(_c("\nPUBLIC KEY", BOLD))
    _row("compressed", hx(pk_c))
    _row("uncompressed", hx(pk_u))
    _row("x-only (taproot)", hx(key.xonly()))
    _row("hash160", hx(hash160(pk_c)))
    print(_c("\nADDRESSES", BOLD) + _c("  (%s)" % net, DIM))
    _row("P2PKH legacy", addrs["p2pkh"])
    _row("  uncompressed", addrs["p2pkh_uncomp"])
    _row("P2SH-P2WPKH", addrs["p2sh_p2wpkh"])
    _row("P2WPKH segwit", addrs["p2wpkh"])
    _row("P2TR taproot", addrs["p2tr"])
    print()

def cmd_newkey(args):
    key = Key.generate(args.network)
    args.privkey, args.file = key.hex, None
    cmd_key(args)

def cmd_addr(args):
    t = args.target.strip()
    if all(c in "0123456789abcdefABCDEF" for c in t) and len(t) in (64, 66, 130):
        pt = parse_pubkey(unhx(t))
        cfg = NETWORKS[args.network]
        h_c = hash160(ser_compressed(pt))
        tweaked = taproot_tweak_pubkey(ser_xonly(pt))
        res = dict(public_key_compressed=hx(ser_compressed(pt)),
                   p2pkh=b58check_encode(bytes([cfg["p2pkh"]]) + h_c),
                   p2sh_p2wpkh=b58check_encode(bytes([cfg["p2sh"]]) + hash160(witness_v0_redeem(h_c))),
                   p2wpkh=bech32_encode(cfg["hrp"], [0] + convertbits(h_c, 8, 5), "bech32"),
                   p2tr=bech32_encode(cfg["hrp"], [1] + convertbits(tweaked, 8, 5), "bech32m"))
    else:
        spk, typ, net = address_to_script(t, args.network)
        res = dict(address=t, type=typ, network=net, script_pubkey=hx(spk),
                   dust_threshold_sat=dust_threshold(spk))
    print(json.dumps(res, indent=2) if args.json else
          "\n".join("  %-22s %s" % (k + ":", v) for k, v in res.items()))

def cmd_build(args):
    with open(args.spec) as f:
        spec = json.load(f)
    tx, info = build_from_spec(spec, args.force)
    raw = hx(tx.ser())
    if args.out:
        with open(args.out, "w") as f:
            f.write(raw + "\n")
    if args.json:
        info["raw"] = raw
        print(json.dumps(info, indent=2))
        return
    print(_c("\nSIGNED TRANSACTION", BOLD) + _c("  (not broadcast)", DIM))
    _row("txid", info["txid"])
    _row("wtxid", info["wtxid"])
    _row("size / vsize", "%d / %d vB  (%d WU)" % (info["size"], info["vsize"], info["weight"]))
    _row("total in", "%d sat  (%.8f BTC)" % (info["total_in"], info["total_in"] / 1e8))
    _row("total out", "%d sat  (%.8f BTC)" % (info["total_out"], info["total_out"] / 1e8))
    _row("fee", "%d sat  @ %s sat/vB" % (info["fee"], info["fee_rate"]))
    print(_c("\nOUTPUTS", BOLD))
    for n, o in enumerate(tx.vout):
        addr, t = script_to_address(o.script_pubkey, info["network"])
        _row("#%d %s" % (n, t), "%s  %d sat" % (addr or hx(o.script_pubkey), o.amount))
    print(_c("\nSIGNATURE CHECK", BOLD))
    for v in info["verify"]:
        mark = _c("OK  ", GREEN) if v["ok"] else _c("FAIL", RED)
        _row("input %d %s" % (v["index"], mark), "%s - %s" % (v["type"], v["note"]))
    for n in info["notes"]:
        print(_c("  note: " + n, YELL))
    print(_c("\nRAW HEX", BOLD))
    print(raw)
    if args.out:
        print(_c("\n  written to %s" % args.out, DIM))
    print(_c("\n  Nothing was broadcast. To publish it yourself, paste the hex into any\n"
             "  node or explorer's 'send raw transaction' form.\n", DIM))

def cmd_decode(args):
    t = args.raw
    if os.path.exists(t):
        with open(t) as f:
            t = f.read().strip()
    tx, d = decode_tx(unhx(t), args.network)
    if args.json:
        print(json.dumps(d, indent=2))
        return
    print(_c("\nTRANSACTION", BOLD))
    _row("txid", d["txid"])
    _row("wtxid", d["wtxid"])
    _row("version", d["version"])
    _row("locktime", d["locktime"])
    _row("segwit", d["segwit"])
    _row("size / vsize", "%d / %d vB" % (d["size"], d["vsize"]))
    print(_c("\nINPUTS", BOLD))
    for n, i in enumerate(d["inputs"]):
        _row("#%d" % n, "%s:%d  seq %s" % (i["txid"], i["vout"], i["sequence"]))
        if i["witness"]:
            _row("   witness", " ".join(w[:24] + ".." if len(w) > 24 else w for w in i["witness"]))
        if i["script_sig"]:
            _row("   scriptSig", i["script_sig"][:72] + ("..." if len(i["script_sig"]) > 72 else ""))
    print(_c("\nOUTPUTS", BOLD))
    for n, o in enumerate(d["outputs"]):
        _row("#%d %s" % (n, o["type"]), "%s  %s sat" % (o.get("address", o["script_pubkey"][:32]), o["amount_sat"]))
    print()

def cmd_verify(args):
    with open(args.spec) as f:
        spec = json.load(f)
    t = args.raw
    if os.path.exists(t):
        with open(t) as f:
            t = f.read().strip()
    tx = Tx.parse(unhx(t))
    net = spec.get("network", "mainnet")
    prevouts = []
    for i in spec["inputs"]:
        spk = unhx(i["script_pubkey"]) if "script_pubkey" in i else address_to_script(i["address"], net)[0]
        prevouts.append(Prevout(i["txid"], int(i["vout"]), int(i["amount_sat"]), spk))
    allok = True
    print()
    for n, typ, ok, note in verify_tx(tx, prevouts):
        allok &= ok
        print("  input %d  %s  %-8s %s" % (n, _c("OK  ", GREEN) if ok else _c("FAIL", RED), typ, note))
    print("\n  %s\n" % (_c("all signatures valid", GREEN) if allok else _c("INVALID", RED)))
    if not allok:
        raise SystemExit(1)

# -------------------------------------------------------------- selftest ----

def cmd_selftest(args):
    fails, count = [], [0]

    def check(name, got, want):
        count[0] += 1
        if got != want:
            fails.append("%s\n     got:  %s\n     want: %s" % (name, got, want))
            print("  %s %s" % (_c("FAIL", RED), name))
        elif args.verbose:
            print("  %s %s" % (_c("ok  ", GREEN), name))

    def ok(name, cond):
        check(name, bool(cond), True)

    print(_c("\nrunning test vectors", BOLD))

    # --- hashes -----------------------------------------------------------
    check("ripemd160('')", hx(_ripemd160_py(b"")), "9c1185a5c5e9fc54612808977ee8f548b2258d31")
    check("ripemd160('abc')", hx(_ripemd160_py(b"abc")), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
    check("ripemd160('message digest')", hx(_ripemd160_py(b"message digest")),
          "5d0689ef49d2fae572b881b123a85ffa21595f36")
    check("ripemd160 a-z", hx(_ripemd160_py(b"abcdefghijklmnopqrstuvwxyz")),
          "f71c27109c692c1b56bbdceb5b9d2865b3708dbc")
    check("ripemd160 backend agrees", hx(ripemd160(b"btc-keytool")), hx(_ripemd160_py(b"btc-keytool")))
    check("tagged_hash TapTweak", len(tagged_hash("TapTweak", b"")), 32)

    # --- base58 / bech32 --------------------------------------------------
    check("base58check roundtrip", b58check_decode(b58check_encode(b"\x00" + b"\x11" * 20)),
          b"\x00" + b"\x11" * 20)
    check("bech32 BIP173 vector",
          bech32_encode("bc", [0] + convertbits(unhx("751e76e8199196d454941c45d1b3a323f1433bd6"), 8, 5), "bech32"),
          "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    check("bech32 testnet P2WSH",
          bech32_encode("tb", [0] + convertbits(unhx("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"), 8, 5), "bech32"),
          "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
    check("bech32m BIP350 v1 40-byte program",
          bech32_encode("bc", [1] + convertbits(unhx("751e76e8199196d454941c45d1b3a323f1433bd6"
                                                     "751e76e8199196d454941c45d1b3a323f1433bd6"), 8, 5), "bech32m"),
          "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y")
    try:
        bech32_decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5")
        ok("bech32 rejects bad checksum", False)
    except ValueError:
        ok("bech32 rejects bad checksum", True)
    try:
        address_to_script("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh")   # v1 with bech32
        ok("rejects v1 encoded as bech32", False)
    except ValueError:
        ok("rejects v1 encoded as bech32", True)

    # --- keys and addresses ----------------------------------------------
    k1 = Key.parse("0000000000000000000000000000000000000000000000000000000000000001")
    a1 = addresses_for_key(k1)
    check("privkey 1 -> compressed pubkey", hx(k1.pubkey(True)),
          "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    check("privkey 1 -> P2PKH", a1["p2pkh"], "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
    check("privkey 1 -> P2PKH uncompressed", a1["p2pkh_uncomp"], "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm")
    check("privkey 1 -> P2WPKH", a1["p2wpkh"], "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    check("privkey 1 -> WIF", k1.wif(True), "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")
    check("privkey 1 -> WIF uncompressed", k1.wif(False), "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf")
    check("WIF roundtrip", Key.from_wif(k1.wif(True)).secret, 1)
    check("WIF sets compressed flag", Key.from_wif(k1.wif(False)).compressed, False)
    check("testnet WIF prefix", Key.from_wif(k1.wif(True, "testnet")).secret, 1)
    check("address_to_script(P2PKH)", hx(address_to_script(a1["p2pkh"])[0]),
          "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac")
    check("script_to_address roundtrip P2TR",
          script_to_address(address_to_script(a1["p2tr"])[0])[0], a1["p2tr"])
    check("script_to_address roundtrip P2SH",
          script_to_address(address_to_script(a1["p2sh_p2wpkh"])[0])[0], a1["p2sh_p2wpkh"])

    # --- curve ------------------------------------------------------------
    ok("G is on the curve", point_on_curve(G))
    check("n*G is infinity", point_mul(N % N, G), None)
    check("(n-1)*G == -G", point_mul(N - 1)[1], P - Gy)
    check("2G == G+G", point_mul(2), point_add(G, G))
    check("lift_x(Gx) has even y", lift_x(Gx)[1] % 2, 0)
    check("parse(ser(pub)) roundtrip", parse_pubkey(ser_uncompressed(point_mul(12345))), point_mul(12345))
    check("parse compressed roundtrip", parse_pubkey(ser_compressed(point_mul(12345))), point_mul(12345))

    # --- ECDSA ------------------------------------------------------------
    msg = sha256(b"btc-keytool selftest")
    sig = ecdsa_sign(msg, 0xC0FFEE)
    ok("ecdsa verifies", ecdsa_verify(msg, sig, point_mul(0xC0FFEE)))
    ok("ecdsa low-s", sig[1] <= N // 2)
    ok("ecdsa rejects wrong msg", not ecdsa_verify(sha256(b"other"), sig, point_mul(0xC0FFEE)))
    ok("ecdsa rejects wrong key", not ecdsa_verify(msg, sig, point_mul(0xC0FFEF)))
    check("rfc6979 is deterministic", ecdsa_sign(msg, 0xC0FFEE), sig)
    check("DER roundtrip", der_decode(der_encode(*sig)), sig)
    ok("DER is minimally encoded", der_encode(*sig)[1] == len(der_encode(*sig)) - 2)

    # --- Schnorr / BIP340 -------------------------------------------------
    s = schnorr_sign(msg, 0xBEEF, b"\x00" * 32)
    ok("schnorr verifies", schnorr_verify(msg, s, ser_xonly(point_mul(0xBEEF))))
    check("schnorr is deterministic with fixed aux", schnorr_sign(msg, 0xBEEF, b"\x00" * 32), s)
    ok("schnorr rejects tampered sig", not schnorr_verify(msg, s[:63] + bytes([s[63] ^ 1]),
                                                          ser_xonly(point_mul(0xBEEF))))
    ok("schnorr rejects wrong msg", not schnorr_verify(sha256(b"other"), s, ser_xonly(point_mul(0xBEEF))))
    check("schnorr sig is 64 bytes", len(s), 64)
    check("taproot tweak of key 1 -> BIP86-style addr", a1["p2tr"],
          "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9")
    check("tweak pubkey == tweak seckey",
          taproot_tweak_pubkey(k1.xonly()), ser_xonly(point_mul(taproot_tweak_seckey(k1.secret))))

    # --- BIP143 sighash (official vector) ---------------------------------
    rev = lambda h: hx(unhx(h)[::-1])
    t143 = Tx(1, [TxIn(rev("fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"), 0, b"", 0xffffffee),
                  TxIn(rev("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a"), 1, b"", 0xffffffff)],
                 [TxOut(112340000, unhx("76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac")),
                  TxOut(223450000, unhx("76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac"))], 0x11)
    check("BIP143 P2WPKH sighash",
          hx(bip143_sighash(t143, 1, unhx("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"), 600000000, 1)),
          "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670")
    kb = Key.parse("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")
    check("BIP143 vector pubkey", hx(kb.pubkey(True)),
          "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357")
    check("BIP143 vector signature",
          hx(der_encode(*ecdsa_sign(bip143_sighash(t143, 1, unhx("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"), 600000000, 1), kb.secret))),
          "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a"
          "0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee")

    # --- real transaction parsing -----------------------------------------
    genesis = ("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d"
               "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f"
               "6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2"
               "052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649"
               "f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000")
    gtx = Tx.parse(unhx(genesis))
    check("genesis coinbase txid", gtx.txid(),
          "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
    check("genesis reserialises", hx(gtx.ser()), genesis)
    check("genesis output type", classify_script(gtx.vout[0].script_pubkey), "p2pk")
    check("genesis output value", gtx.vout[0].amount, 5000000000)

    # --- full build + sign + verify, every supported input type ------------
    k = Key.parse("0000000000000000000000000000000000000000000000000000000000000abc")
    ad = addresses_for_key(k)
    for typ, addr in (("p2pkh", ad["p2pkh"]), ("p2sh-p2wpkh", ad["p2sh_p2wpkh"]),
                      ("p2wpkh", ad["p2wpkh"]), ("p2tr", ad["p2tr"])):
        spec = dict(network="mainnet", key=k.hex,
                    inputs=[dict(txid="a" * 64, vout=0, amount_sat=100000, address=addr)],
                    outputs=[dict(address=ad["p2wpkh"], amount_sat="all")],
                    fee_rate=5)
        tx, info = build_from_spec(spec)
        ok("sign+verify %s" % typ, all(v["ok"] for v in info["verify"]))
        ok("reparse %s" % typ, hx(Tx.parse(tx.ser()).ser()) == hx(tx.ser()))
        ok("fee rate honoured %s" % typ, abs(info["fee_rate"] - 5) < 0.6)

    # mixed-input transaction, taproot commits to every prevout
    spec = dict(network="mainnet", key=k.hex,
                inputs=[dict(txid="b" * 64, vout=0, amount_sat=50000, address=ad["p2tr"]),
                        dict(txid="c" * 64, vout=1, amount_sat=60000, address=ad["p2wpkh"]),
                        dict(txid="d" * 64, vout=2, amount_sat=70000, address=ad["p2pkh"])],
                outputs=[dict(address=ad["p2tr"], amount_sat=100000),
                         dict(op_return="btc-keytool")],
                change_address=ad["p2wpkh"], fee_rate=12)
    tx, info = build_from_spec(spec)
    ok("mixed-input tx verifies", all(v["ok"] for v in info["verify"]))
    ok("mixed-input change added", any("change" in n for n in info["notes"]))
    ok("mixed-input fee rate", abs(info["fee_rate"] - 12) < 1.0)
    ok("op_return output present", any(o["type"] == "op_return" for o in decode_tx(tx.ser())[1]["outputs"]))

    # fee targeting must never land below the requested rate
    for rate in (1, 7, 57, 300, 1000):
        for mode in ("change", "sweep"):
            sp = dict(network="mainnet", key=k.hex, fee_rate=rate,
                      inputs=[dict(txid="a" * 64, vout=0, amount_sat=900000, address=ad["p2wpkh"]),
                              dict(txid="b" * 64, vout=1, amount_sat=800000, address=ad["p2tr"]),
                              dict(txid="c" * 64, vout=2, amount_sat=700000, address=ad["p2pkh"])],
                      outputs=[dict(address=ad["p2tr"],
                                    amount_sat="all" if mode == "sweep" else 500000)])
            if mode == "change":
                sp["change_address"] = ad["p2wpkh"]
            _t, _i = build_from_spec(sp, force=True)
            ok("fee rate %d %s never undershoots" % (rate, mode), _i["fee_rate"] >= rate)
            ok("fee rate %d %s stays close" % (rate, mode), _i["fee_rate"] <= rate * 1.05)

    # dust thresholds match Bitcoin Core
    for name, addr, want in (("p2pkh", ad["p2pkh"], 546), ("p2sh", ad["p2sh_p2wpkh"], 540),
                             ("p2wpkh", ad["p2wpkh"], 294), ("p2tr", ad["p2tr"], 330)):
        check("dust threshold %s" % name, dust_threshold(address_to_script(addr)[0]), want)

    # tampering must be detected
    prevouts = [Prevout("b" * 64, 0, 50000, address_to_script(ad["p2tr"])[0]),
                Prevout("c" * 64, 1, 60000, address_to_script(ad["p2wpkh"])[0]),
                Prevout("d" * 64, 2, 70000, address_to_script(ad["p2pkh"])[0])]
    tx.vout[0].amount += 1
    ok("edited amount invalidates every signature",
       not any(r[2] for r in verify_tx(tx, prevouts)))

    # refuses to sign with the wrong key
    try:
        build_from_spec(dict(network="mainnet", key=Key.parse("2").hex,
                             inputs=[dict(txid="e" * 64, vout=0, amount_sat=5000, address=ad["p2wpkh"])],
                             outputs=[dict(address=ad["p2wpkh"], amount_sat="all")], fee_rate=1))
        ok("refuses a key that does not match the input", False)
    except ValueError:
        ok("refuses a key that does not match the input", True)

    # refuses to overspend / absurd fee
    for bad, name in (
        (dict(inputs=[dict(txid="f" * 64, vout=0, amount_sat=1000, address=ad["p2wpkh"])],
              outputs=[dict(address=ad["p2wpkh"], amount_sat=2000)]), "refuses to overspend"),
        (dict(inputs=[dict(txid="f" * 64, vout=0, amount_sat=10000000, address=ad["p2wpkh"])],
              outputs=[dict(address=ad["p2wpkh"], amount_sat=1000)]), "refuses an absurd fee"),
    ):
        bad.update(network="mainnet", key=k.hex)
        try:
            build_from_spec(bad)
            ok(name, False)
        except ValueError:
            ok(name, True)

    # --- cross-check against independent libraries, when present -----------
    try:
        import ecdsa as _e
        sk = _e.SigningKey.from_secret_exponent(0xC0FFEE, curve=_e.SECP256k1)
        ok("pubkey matches python-ecdsa",
           sk.get_verifying_key().to_string() == ser_uncompressed(point_mul(0xC0FFEE))[1:])
        ok("our ECDSA sig verifies under python-ecdsa",
           sk.get_verifying_key().verify_digest(
               sig[0].to_bytes(32, "big") + sig[1].to_bytes(32, "big"), msg))
    except ImportError:
        print(_c("  (python-ecdsa not installed, cross-check skipped)", DIM))
    try:
        import coincurve as _cc
        pk = _cc.PrivateKey((0xC0FFEE).to_bytes(32, "big"))
        ok("pubkey matches libsecp256k1", pk.public_key.format(True) == ser_compressed(point_mul(0xC0FFEE)))
        ok("our ECDSA sig verifies under libsecp256k1",
           pk.public_key.verify(der_encode(*sig), msg, hasher=None))
        try:
            ok("our Schnorr sig verifies under libsecp256k1",
               _cc.PublicKeyXOnly(ser_xonly(point_mul(0xBEEF))).verify(s, msg))
        except AttributeError:
            pass
    except ImportError:
        print(_c("  (coincurve not installed, cross-check skipped)", DIM))

    print("\n  %d checks, %s\n" % (count[0], _c("all passed", GREEN) if not fails
                                   else _c("%d FAILED" % len(fails), RED)))
    for f in fails:
        print("   - " + f)
    if fails:
        raise SystemExit(1)

# ------------------------------------------------------------------ main ----

def main(argv=None):
    p = argparse.ArgumentParser(prog="btc-keytool",
        description="Offline Bitcoin key and transaction tool. Never touches the network.")
    p.add_argument("--network", default="mainnet", choices=sorted(NETWORKS), help="default: mainnet")
    p.add_argument("--json", action="store_true", help="machine-readable output")

    # The same two flags again on every subcommand, so they work on either side
    # of it. SUPPRESS keeps an unused subcommand flag from clobbering the global.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--network", choices=sorted(NETWORKS), default=argparse.SUPPRESS,
                        help=argparse.SUPPRESS)
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                        help=argparse.SUPPRESS)

    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("key", help="derive pubkey + addresses from a private key", parents=[common])
    s.add_argument("privkey", nargs="?", help="WIF, 64-char hex, 0x-hex or decimal")
    s.add_argument("--file", help="read the key from a file instead")
    s.set_defaults(func=cmd_key)

    s = sub.add_parser("newkey", help="generate a new key with os.urandom", parents=[common])
    s.set_defaults(func=cmd_newkey)

    s = sub.add_parser("addr", help="inspect an address or a public key", parents=[common])
    s.add_argument("target")
    s.set_defaults(func=cmd_addr)

    s = sub.add_parser("build", help="build and sign a transaction from a JSON spec", parents=[common])
    s.add_argument("spec")
    s.add_argument("-o", "--out", help="also write the raw hex here")
    s.add_argument("--force", action="store_true", help="allow an unusually large fee")
    s.set_defaults(func=cmd_build)

    s = sub.add_parser("decode", help="decode a raw transaction (hex string or file)",
                       parents=[common])
    s.add_argument("raw")
    s.set_defaults(func=cmd_decode)

    s = sub.add_parser("verify", help="verify signatures in a signed tx against its spec", parents=[common])
    s.add_argument("raw")
    s.add_argument("spec")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("selftest", help="run the built-in test vectors", parents=[common])
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(func=cmd_selftest)

    args = p.parse_args(argv)
    if not getattr(args, "func", None):
        p.print_help()
        return 1
    try:
        args.func(args)
    except (ValueError, IOError, KeyError) as e:
        print(_c("error: ", RED) + str(e), file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
