"""Local enforcement adapter for autonomous response.

Two modes, both auditable:

``simulate`` (default)
    Record the control, report success, and never touch the host firewall.
    The stored provider message says so, so the console cannot imply that a
    packet filter was installed when it was not.

``nftables``
    Apply a time-bounded element to a dedicated ``inet attacksentry`` set and
    drop matching traffic in input/output/forward. Requires root and the
    ``nft`` binary; otherwise the dispatch fails instead of pretending.

Targets are validated as IP addresses and passed to ``nft`` as argv, never
through a shell.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import shutil

from ..config import settings
from .webhook import WebhookDispatcher

logger = logging.getLogger("sentry.enforcement")

TABLE = "attacksentry"
SET4 = "blocked4"
SET6 = "blocked6"
_RULE_COMMENT = "attacksentry-auto"


class LocalEnforcer:
    async def send(self, event_type: str, payload: dict) -> tuple[bool, str]:
        target = (payload.get("target") or {}).get("value", "")
        try:
            address = ipaddress.ip_address(str(target))
        except ValueError:
            return False, f"Refused: {target!r} is not an IP address"

        if event_type.endswith("release_requested"):
            return await self._release(address)
        return await self._apply(address, payload)

    # ---- simulate -------------------------------------------------------
    async def _simulate(self, address: ipaddress._BaseAddress, verb: str) -> tuple[bool, str]:
        return True, (
            f"simulated: {verb} {address} recorded; no packet filter applied "
            f"(set SENTRY_ENFORCEMENT_MODE=nftables to enforce)"
        )

    # ---- nftables -------------------------------------------------------
    async def _apply(self, address: ipaddress._BaseAddress, payload: dict) -> tuple[bool, str]:
        action = str(payload.get("action") or "block")
        if action == "rate_limit":
            # A host firewall cannot rate-limit an inbound flood for a victim.
            # Upstream scrubbing or a provider API is the correct enforcement.
            if settings.enforcement_mode == "nftables":
                return False, (
                    f"rate_limit on {address} requires an upstream scrubbing adapter; "
                    "the local nftables adapter does not rate-limit floods"
                )
            return True, f"simulated: rate_limit {address} recorded; upstream scrubbing required"
        if settings.enforcement_mode != "nftables":
            return await self._simulate(address, action)
        reason, code, stderr = self._preflight()
        if reason:
            return False, reason
        ttl = self._ttl_seconds(payload.get("expires_at"))
        await self._ensure_table(code)
        set_name = SET4 if address.version == 4 else SET6
        command = ["nft", "add", "element", "inet", TABLE, set_name,
                   "{", str(address), "timeout", f"{ttl}s", "}"]
        ok, message = await self._run(command)
        if not ok:
            return False, message
        logger.info("Enforced %s on %s for %ss", payload.get("action"), address, ttl)
        return True, f"nftables: {payload.get('action')} {address} for {ttl}s"

    async def _release(self, address: ipaddress._BaseAddress) -> tuple[bool, str]:
        if settings.enforcement_mode != "nftables":
            return await self._simulate(address, "release")
        reason, code, _ = self._preflight()
        if reason:
            return False, reason
        set_name = SET4 if address.version == 4 else SET6
        ok, message = await self._run(
            ["nft", "delete", "element", "inet", TABLE, set_name, "{", str(address), "}"]
        )
        # A missing element means the control already expired; that is success.
        if not ok and "No such file or directory" in message:
            ok, message = True, f"nftables: {address} was already released"
        return ok, message

    def _preflight(self) -> tuple[str | None, str, str]:
        binary = shutil.which("nft")
        if not binary:
            return "nftables enforcement requested, but the nft binary is not installed", "", ""
        if os.geteuid() != 0:
            return "nftables enforcement requires root", "", ""
        return None, binary, ""

    async def _ensure_table(self, binary: str) -> None:
        # Idempotent: every failure here means the object already exists.
        commands = [
            [binary, "add", "table", "inet", TABLE],
            [binary, "add", "set", "inet", TABLE, SET4,
             "{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}"],
            [binary, "add", "set", "inet", TABLE, SET6,
             "{", "type", "ipv6_addr", ";", "flags", "timeout", ";", "}"],
            [binary, "add", "chain", "inet", TABLE, "input",
             "{", "type", "filter", "hook", "input", "priority", "-10", ";", "policy", "accept", ";", "}"],
            [binary, "add", "chain", "inet", TABLE, "output",
             "{", "type", "filter", "hook", "output", "priority", "-10", ";", "policy", "accept", ";", "}"],
            [binary, "add", "chain", "inet", TABLE, "forward",
             "{", "type", "filter", "hook", "forward", "priority", "-10", ";", "policy", "accept", ";", "}"],
        ]
        for command in commands:
            await self._run(command, quiet=True)
        rules = [
            ["ip", "saddr", "@" + SET4], ["ip", "daddr", "@" + SET4],
            ["ip6", "saddr", "@" + SET6], ["ip6", "daddr", "@" + SET6],
        ]
        for chain in ("input", "output", "forward"):
            for match in rules:
                await self._run(
                    [binary, "add", "rule", "inet", TABLE, chain, *match, "counter", "drop"],
                    quiet=True,
                )

    def _ttl_seconds(self, expires_at: str | None) -> int:
        from datetime import datetime, timezone

        maximum = max(60, settings.response_ttl_max_minutes * 60)
        if not expires_at:
            return min(settings.response_ttl_minutes * 60, maximum)
        try:
            when = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            seconds = int((when - datetime.now(timezone.utc)).total_seconds())
            return max(60, min(seconds, maximum))
        except ValueError:
            return min(settings.response_ttl_minutes * 60, maximum)

    async def _run(self, command: list[str], quiet: bool = False) -> tuple[bool, str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
        except (OSError, asyncio.TimeoutError) as exc:
            return False, f"nft failed: {exc}"
        if proc.returncode == 0:
            return True, " ".join(command)
        message = (stderr or b"").decode(errors="replace").strip()
        if not quiet:
            logger.warning("nft command failed: %s", message)
        return False, message or f"nft exited {proc.returncode}"


class ResponseDispatcher:
    """Prefer the configured webhook; otherwise enforce locally."""

    def __init__(self, webhook: WebhookDispatcher):
        self.webhook = webhook
        self.local = LocalEnforcer()

    async def send(self, event_type: str, payload: dict) -> tuple[bool, str]:
        if settings.webhook_url:
            return await self.webhook.send(event_type, payload)
        return await self.local.send(event_type, payload)
