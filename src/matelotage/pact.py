"""The pact: who is trusted, in what order, and who has been revoked."""

from __future__ import annotations

import time

from . import index, schema


def describe(with_network: bool = True) -> dict:
    keys = index.get_trusted_pubkeys()
    revoked = sorted(index.revoked_keys()) if with_network else []
    return {
        "cold_root": keys[0] if keys else None,
        "allowlist": [
            {
                "index": position,
                "pubkey": key,
                "npub": schema.hex_to_bech32(key) if len(key) == 64 else key,
                "role": "cold root" if position == 0 else "community" if position > 1 else "publisher",
            }
            for position, key in enumerate(keys)
        ],
        "revoked": revoked,
        "relays": index.get_relays(),
        "timeout": index.get_timeout(),
        "breaker_open": index.breaker_open(),
        "checked": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def format_text(info: dict) -> str:
    lines = [f"matelotage pact ({info['checked']})"]
    if not info["allowlist"]:
        lines.append("  no trusted keys configured — the fallback is disabled")
    for entry in info["allowlist"]:
        mark = " (revoked)" if entry["pubkey"] in info["revoked"] else ""
        lines.append(f"  {entry['index']}: {entry['role']:11} {entry['npub']}{mark}")
    lines.append(f"  relays ({len(info['relays'])}): " + (", ".join(info["relays"]) or "none"))
    lines.append(f"  timeout: {info['timeout']}s" + ("  [breaker open]" if info["breaker_open"] else ""))
    return "\n".join(lines)
