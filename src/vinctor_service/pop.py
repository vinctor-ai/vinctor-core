"""HMAC proof-of-possession (PoP) for subject tokens (ADR 0007 C3).

Stdlib only. The canonical form is length-prefixed (not delimiter-joined) so the
binding is injection-proof regardless of field content or validation order. The
replay cache is a per-process instance, injected by the owning service; a bad or
stale proof never consumes a cache slot (record only AFTER mac + freshness pass).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import UTC, datetime


def pop_canonical(action: str, resource: str, ts: int, nonce: str, token_id: str) -> bytes:
    """Length-prefixed canonical bytes for the proof binding.

    Each field is encoded as a 4-byte big-endian length followed by its UTF-8
    bytes. This locks the field boundaries: no field content (including newlines
    or delimiters) can shift the parse, so a proof for one (action, resource)
    can never validate for a different split.
    """
    parts = [action, resource, str(ts), nonce, token_id]
    out = bytearray()
    for p in parts:
        b = p.encode("utf-8")
        out += len(b).to_bytes(4, "big") + b
    return bytes(out)


def pop_mac(pop_secret: str, canonical: bytes) -> str:
    digest = hmac.new(pop_secret.encode("utf-8"), canonical, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class PopReplayCache:
    """Per-process anti-replay for PoP nonces. Single-node only (see spec Risks)."""

    def __init__(self, max_entries: int = 10000, max_per_token: int = 256) -> None:
        self._seen: dict[tuple[str, str], int] = {}
        self._max = max_entries
        # Per-token-id cap mirrors SQLiteReplayStore: one token's nonce flood is
        # bounded to its own footprint and evicts only its own oldest within-window
        # nonce, so it can never saturate the global cap against other tokens.
        self._max_per_token = max_per_token

    def check_and_record(
        self, *, token_id: str, nonce: str, ts: int, now_unix: int, skew: int
    ) -> bool:
        cutoff = now_unix - skew
        if self._seen:
            for k in [k for k, t in self._seen.items() if t < cutoff]:
                del self._seen[k]
        key = (token_id, nonce)
        if key in self._seen:
            return False  # replay
        token_keys = [k for k in self._seen if k[0] == token_id]
        if len(token_keys) >= self._max_per_token:
            # This token is at its own cap: evict its OWN oldest within-window
            # nonce (min ts; insertion order as the FIFO tie-break) — net-zero on
            # the global count, never touching another token's row.
            # token_keys is already in insertion order; min is stable, so an
            # equal-ts tie resolves to the earliest-inserted (FIFO) key.
            oldest = min(token_keys, key=lambda k: self._seen[k])
            del self._seen[oldest]
        elif len(self._seen) >= self._max:
            return False  # full of fresh entries -> fail closed
        self._seen[key] = ts
        return True


def verify_pop(
    *,
    proof: str | None,
    pop_secret: str,
    token_id: str,
    action: str,
    resource: str,
    now: datetime,
    skew: int,
    replay_cache: PopReplayCache,
) -> bool:
    if proof is None or proof.strip() == "":
        return False
    parts = proof.split(".")
    if len(parts) != 3:
        return False
    ts_raw, nonce, mac = parts
    try:
        ts = int(ts_raw)
    except ValueError:
        return False
    if not nonce or not mac:
        return False
    # The mac is base64url (ASCII). A non-ASCII mac would make hmac.compare_digest
    # raise TypeError; reject it cleanly so every bad proof returns the same
    # generic failure (no exception, no probing oracle) instead of crashing.
    if not mac.isascii():
        return False
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    now_unix = int(now.timestamp())
    if abs(now_unix - ts) > skew:
        return False
    expected = pop_mac(pop_secret, pop_canonical(action, resource, ts, nonce, token_id))
    if not hmac.compare_digest(expected, mac):
        return False
    # record ONLY after mac + freshness pass
    return replay_cache.check_and_record(
        token_id=token_id, nonce=nonce, ts=ts, now_unix=now_unix, skew=skew
    )
