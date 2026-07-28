"""HMAC proof-of-possession (PoP) for subject tokens (ADR 0007 C3).

No third-party deps. The canonical form is length-prefixed (not delimiter-joined) so the
binding is injection-proof regardless of field content or validation order. The
replay cache is a per-process instance, injected by the owning service; a bad or
stale proof never consumes a cache slot (record only AFTER mac + freshness pass).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import threading
from datetime import UTC, datetime

from vinctor_service.service_config import load_pop_replay_caps


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

    def __init__(
        self, max_entries: int | None = None, max_per_token: int | None = None
    ) -> None:
        # Caps left unset resolve from the environment (PKA-24), so a legit
        # high-throughput token can be accommodated by raising the fail-closed
        # caps at deploy time without a code change.
        if max_entries is None or max_per_token is None:
            env_entries, env_per_token = load_pop_replay_caps()
            max_entries = env_entries if max_entries is None else max_entries
            max_per_token = env_per_token if max_per_token is None else max_per_token
        self._seen: dict[tuple[str, str], int] = {}
        self._max = max_entries
        # Per-token-id cap mirrors SQLiteReplayStore: one token's nonce flood is
        # bounded to its own footprint (fresh proofs beyond the cap are rejected),
        # so it can never saturate the global cap against other tokens.
        self._max_per_token = max_per_token
        self._lock = threading.Lock()

    def check_and_record(
        self, *, token_id: str, nonce: str, ts: int, now_unix: int, skew: int
    ) -> bool:
        with self._lock:
            cutoff = now_unix - skew
            if self._seen:
                for k in [k for k, t in self._seen.items() if t < cutoff]:
                    del self._seen[k]
            key = (token_id, nonce)
            if key in self._seen:
                return False  # replay
            # Expired entries were purged above, so every entry counted here is
            # still inside the freshness window. NEVER evict a live nonce to make
            # room (ADR 0007): a dropped fresh nonce would let its captured proof
            # replay within the window. When a cap is full of fresh entries, fail
            # closed (reject the new proof); operators can raise the cap.
            if sum(1 for k in self._seen if k[0] == token_id) >= self._max_per_token:
                return False  # per-token cap full of fresh entries -> fail closed
            if len(self._seen) >= self._max:
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
