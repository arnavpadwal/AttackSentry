"""Entity registry: IP -> group / identity context resolution."""
from __future__ import annotations

import ipaddress
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("sentry.registry")


class EntityRegistry:
    def __init__(self, config_path: Optional[Path] = None):
        self.groups: Dict[str, str] = {}   # CIDR -> group name
        self.iam_map: Dict[str, str] = {}  # IP -> username
        if config_path and Path(config_path).exists():
            self.load_config(Path(config_path))

    def load_config(self, path: Path) -> None:
        try:
            config = json.loads(path.read_text())
            self.groups = config.get("groups", {})
            self.iam_map = config.get("iam_map", {})
            logger.info("Loaded registry config from %s", path)
        except Exception as exc:
            logger.error("Failed to load registry config: %s", exc)

    def resolve_group(self, ip_str: str) -> str:
        try:
            ip = ipaddress.ip_address(ip_str)
            for cidr, group in self.groups.items():
                if ip in ipaddress.ip_network(cidr):
                    return group
        except ValueError:
            pass
        parts = ip_str.split(".")
        if len(parts) == 4:
            return f"Subnet_{parts[0]}.{parts[1]}.{parts[2]}.0_24"
        return "Default_Group"

    def resolve_identity(self, ip_str: str) -> str:
        return self.iam_map.get(ip_str, "Unknown")

    def get_context(self, ip_str: str, provided_group: Optional[str] = None,
                    provided_identity: Optional[str] = None,
                    provided_identity_type: Optional[str] = None) -> Dict[str, Any]:
        group = provided_group or self.resolve_group(ip_str)
        return {
            "group": group,
            "identity": provided_identity or self.resolve_identity(ip_str),
            "identity_type": provided_identity_type or "Unknown",
        }
