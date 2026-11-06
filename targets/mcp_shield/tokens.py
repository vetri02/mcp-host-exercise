"""Minimal signed tokens for per-server credentials. Standard library only.

A token is ``base64url(json claims) . base64url(hmac-sha256)``. The claims
are ``sub``, ``aud``, ``scope`` (list), ``iat`` and ``exp`` (unix seconds).
This stands in for a real JWT; the shape is what matters for the target.
"""
import base64
import hashlib
import hmac
import json
import time

SIGNING_KEY = b"host-signing-key-for-the-target-only"
MAX_TTL = 300


def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def mint(sub, aud, scopes, ttl=MAX_TTL, key=SIGNING_KEY, now=None):
    now = int(time.time()) if now is None else now
    claims = {"sub": sub, "aud": aud, "scope": sorted(scopes), "iat": now, "exp": now + int(ttl)}
    body = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(key, body, hashlib.sha256).digest()
    return _b64(body) + "." + _b64(sig)


def decode(token, key=SIGNING_KEY):
    """Return the claims if the signature verifies, else raise ValueError."""
    try:
        body_s, sig_s = token.split(".")
        body, sig = _unb64(body_s), _unb64(sig_s)
    except Exception:
        raise ValueError("malformed token")
    if not hmac.compare_digest(hmac.new(key, body, hashlib.sha256).digest(), sig):
        raise ValueError("bad signature")
    return json.loads(body.decode("utf-8"))
