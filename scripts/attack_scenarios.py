#!/usr/bin/env python3
"""AttackSentry live detection matrix.

Trains an environment-specific baseline for a simulated corporate network, then
streams every attack family the platform can attribute plus three zero-day
behaviours it has not been trained to name.

Usage:
    python scripts/attack_scenarios.py --fresh-baseline
    python scripts/attack_scenarios.py --skip-baseline --scenario all --count 20
    python scripts/attack_scenarios.py --scenario zero-day --count 30
    python scripts/attack_scenarios.py --list-scenarios
"""
from __future__ import annotations

import argparse
import json
import os
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

BASE = os.environ.get("ATTACKSENTRY_URL", "http://127.0.0.1:8000").rstrip("/")
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ENV_PATH = (
    os.path.join(_ROOT, "deploy", "docker-compose", ".env")
    if BASE.endswith(":8080")
    else os.path.join(_ROOT, "Sentry", ".env")
)


def _env_value(key: str, default: str = "") -> str:
    try:
        with open(_ENV_PATH, encoding="utf-8") as env_file:
            for line in env_file:
                if line.startswith(f"{key}="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return default


ADMIN_USER = _env_value("SENTRY_BOOTSTRAP_ADMIN_USERNAME", "admin")
ADMIN_PASS = _env_value("SENTRY_BOOTSTRAP_ADMIN_PASSWORD")

random.seed(42)


# --------------------------------------------------------------------------- #
# HTTP client
# --------------------------------------------------------------------------- #
class SentryClient:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.token = ""
        self.sensor_id: str | None = None
        self.key_id: str | None = None
        self.secret: str | None = None

    def api(self, method: str, path: str, body=None, headers=None):
        request_headers = dict(headers or {})
        request_headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{self.base}{path}", data=data, headers=request_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=180) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as error:
            print(f"  ERR {error.code} {path}: {error.read().decode()[:240]}")
            return None
        except urllib.error.URLError as error:
            print(f"  ERR cannot reach {self.base}: {error.reason}")
            return None

    def login(self) -> None:
        if not ADMIN_PASS:
            raise SystemExit(f"SENTRY_BOOTSTRAP_ADMIN_PASSWORD is missing in {_ENV_PATH}")
        response = self.api("POST", "/api/auth/login", {"username": ADMIN_USER, "password": ADMIN_PASS})
        if not response:
            raise SystemExit("AttackSentry is not reachable or login failed. Start the platform, then retry.")
        self.token = response["access_token"]

    def authed(self, method: str, path: str, body=None):
        return self.api(method, path, body, {"Authorization": f"Bearer {self.token}"})

    def ensure_sensor(self) -> None:
        print("[*] Preparing simulation sensor...")
        sensors = self.authed("GET", "/api/sensors") or []
        sensor = next((item for item in sensors if item.get("name") == "simulation-matrix"), None)
        if not sensor:
            sensor = self.authed("POST", "/api/sensors", {
                "name": "simulation-matrix",
                "ip_address": "10.20.40.250",
                "sensor_type": "rest",
            })
        if not sensor:
            raise SystemExit("Could not register the simulation sensor.")
        self.sensor_id = sensor["id"]
        key = self.authed("POST", f"/api/sensors/{self.sensor_id}/api-key")
        self.key_id, self.secret = key["key_id"], key["secret"]
        print(f"    sensor {self.sensor_id} · key {self.key_id}")

    def ingest(self, flow: dict) -> dict | None:
        headers = {"X-Sentry-Key-ID": self.key_id, "X-Sentry-Secret": self.secret}
        return self.api("POST", "/api/ingest/flow", flow, headers)

    def ingest_batch(self, flows: list[dict]) -> dict | None:
        headers = {"X-Sentry-Key-ID": self.key_id, "X-Sentry-Secret": self.secret}
        return self.api("POST", "/api/ingest/flow", flows, headers)

    def snapshot(self) -> dict[str, tuple[int, str]]:
        rows = self.authed("GET", "/api/incidents") or []
        return {row["id"]: (int(row.get("count", 0)), row.get("last_seen", "")) for row in rows}

    def changed_incidents(self, before: dict[str, tuple[int, str]]) -> list[dict]:
        rows = self.authed("GET", "/api/incidents") or []
        return [row for row in rows if row["id"] not in before or before[row["id"]] != (int(row.get("count", 0)), row.get("last_seen", ""))]

    def incident_evidence(self, incident_id: str) -> list[dict]:
        return self.authed("GET", f"/api/incidents/{incident_id}/alerts") or []

    def wait_for_processing(self, start_flows: int, submitted: int, timeout: float = 90.0) -> None:
        deadline = time.time() + max(15.0, min(timeout, submitted * 0.30))
        while time.time() < deadline:
            status = self.authed("GET", "/api/sentry/status") or {}
            if int(status.get("flows_processed", 0)) >= start_flows + submitted:
                time.sleep(1.5)
                return
            time.sleep(1.0)


# --------------------------------------------------------------------------- #
# Corporate baseline
# --------------------------------------------------------------------------- #
CORP_HOSTS = {
    "Finance": [f"10.20.10.{index}" for index in range(11, 16)],
    "Engineering": [f"10.20.20.{index}" for index in range(11, 16)],
    "Sales": [f"10.20.30.{index}" for index in range(11, 16)],
    "DataCenter": [f"10.20.40.{index}" for index in range(10, 15)],
    "IoT": [f"10.20.50.{index}" for index in range(11, 16)],
}
SERVICES = {
    "dns": ("10.20.40.10", 53, 17),
    "http": ("10.20.40.20", 80, 6),
    "https": ("10.20.40.21", 443, 6),
    "smb": ("10.20.40.30", 445, 6),
    "smtp": ("10.20.40.40", 587, 6),
    "mqtt": ("10.20.50.10", 1883, 6),
}
EXTERNAL_WEB = ["142.250.80.46", "151.101.1.69", "104.244.42.1", "93.184.216.34"]


def flow(**overrides) -> dict:
    """Generate a flow with every canonical field the sensor emits."""
    base = {
        "Src_IP": "10.20.20.11",
        "Dst_IP": "10.20.40.21",
        "Src_Port": random.randint(40000, 60000),
        "Dst_Port": 443,
        "Protocol": 6,
        "Flow_Duration": round(random.uniform(0.2, 4.0), 4),
        "Total_Fwd_Packets": random.randint(4, 40),
        "Total_Bwd_Packets": random.randint(4, 35),
        "Total_Fwd_Bytes": random.randint(500, 30000),
        "Total_Bwd_Bytes": random.randint(500, 30000),
        "Fwd_Pkt_Len_Min": round(random.uniform(40, 120), 1),
        "Fwd_Pkt_Len_Max": round(random.uniform(500, 1500), 1),
        "Fwd_Pkt_Len_Mean": round(random.uniform(180, 900), 1),
        "Fwd_Pkt_Len_Std": round(random.uniform(10, 250), 1),
        "Bwd_Pkt_Len_Min": round(random.uniform(40, 120), 1),
        "Bwd_Pkt_Len_Max": round(random.uniform(300, 1500), 1),
        "Bwd_Pkt_Len_Mean": round(random.uniform(160, 900), 1),
        "Bwd_Pkt_Len_Std": round(random.uniform(10, 200), 1),
        "Flow_IAT_Mean": round(random.uniform(0.01, 0.4), 6),
        "Flow_IAT_Std": round(random.uniform(0.005, 0.2), 6),
        "Flow_IAT_Max": round(random.uniform(0.1, 2.0), 6),
        "Flow_IAT_Min": round(random.uniform(0.0001, 0.05), 6),
        "Flow_Bytes_Sec": round(random.uniform(1000, 30000), 1),
        "Flow_Packets_Sec": round(random.uniform(5, 60), 1),
        "FIN_Flag_Count": random.randint(0, 1),
        "SYN_Flag_Count": 1,
        "RST_Flag_Count": 0,
        "PSH_Flag_Count": random.randint(0, 6),
        "ACK_Flag_Count": random.randint(2, 18),
        "URG_Flag_Count": 0,
        "Subnet_Group": None,
        "Source_Subnet": None,
        "identity_type": "employee",
    }
    base.update(overrides)
    return base


def corp_benign(index: int) -> dict:
    """Representative workday traffic: web, DNS, SMB, mail, and IoT."""
    group = random.choices(
        ["Finance", "Engineering", "Sales", "DataCenter", "IoT"],
        weights=[24, 30, 20, 16, 10],
    )[0]
    src = random.choice(CORP_HOSTS[group])
    subnet = ".".join(src.split(".")[:3]) + ".0/24"
    kind = random.choices(
        ["external_web", "internal_web", "dns", "smb", "mail", "mqtt"],
        weights=[30, 24, 20, 9, 8, 9],
    )[0]

    if kind == "external_web":
        return flow(
            Src_IP=src, Dst_IP=random.choice(EXTERNAL_WEB), Dst_Port=random.choice([443, 443, 443, 80]),
            Flow_Duration=round(random.uniform(0.3, 6), 4),
            Total_Fwd_Packets=random.randint(5, 35), Total_Bwd_Packets=random.randint(5, 40),
            Total_Fwd_Bytes=random.randint(500, 25000), Total_Bwd_Bytes=random.randint(1000, 45000),
            Flow_IAT_Mean=round(random.uniform(0.02, 0.4), 6),
            Flow_Bytes_Sec=round(random.uniform(1500, 40000), 1),
            Subnet_Group=group, Source_Subnet=subnet,
        )
    if kind == "internal_web":
        dest, port, proto = SERVICES[random.choice(["http", "https"])]
        return flow(
            Src_IP=src, Dst_IP=dest, Dst_Port=port, Protocol=proto,
            Flow_Duration=round(random.uniform(0.1, 3), 4),
            Total_Fwd_Packets=random.randint(3, 25), Total_Bwd_Packets=random.randint(3, 30),
            Total_Fwd_Bytes=random.randint(300, 12000), Total_Bwd_Bytes=random.randint(600, 30000),
            Flow_IAT_Mean=round(random.uniform(0.01, 0.3), 6),
            Flow_Bytes_Sec=round(random.uniform(800, 25000), 1),
            Subnet_Group=group, Source_Subnet=subnet,
        )
    if kind == "dns":
        dest, port, proto = SERVICES["dns"]
        return flow(
            Src_IP=src, Dst_IP=dest, Dst_Port=port, Protocol=proto,
            Flow_Duration=round(random.uniform(0.001, 0.05), 6),
            Total_Fwd_Packets=random.randint(1, 2), Total_Bwd_Packets=random.randint(1, 2),
            Total_Fwd_Bytes=random.randint(50, 180), Total_Bwd_Bytes=random.randint(80, 400),
            Fwd_Pkt_Len_Mean=round(random.uniform(50, 120), 1), Fwd_Pkt_Len_Max=180,
            Bwd_Pkt_Len_Mean=round(random.uniform(80, 300), 1), Bwd_Pkt_Len_Max=512,
            Flow_IAT_Mean=round(random.uniform(0.0005, 0.01), 6),
            Flow_Bytes_Sec=round(random.uniform(2000, 30000), 1),
            SYN_Flag_Count=0, ACK_Flag_Count=0, PSH_Flag_Count=0, FIN_Flag_Count=0,
            Subnet_Group=group, Source_Subnet=subnet,
        )
    if kind == "smb":
        dest, port, proto = SERVICES["smb"]
        return flow(
            Src_IP=src, Dst_IP=dest, Dst_Port=port, Protocol=proto,
            Flow_Duration=round(random.uniform(0.5, 12), 4),
            Total_Fwd_Packets=random.randint(15, 80), Total_Bwd_Packets=random.randint(10, 60),
            Total_Fwd_Bytes=random.randint(3000, 120000), Total_Bwd_Bytes=random.randint(2000, 90000),
            Flow_IAT_Mean=round(random.uniform(0.01, 0.2), 6),
            Flow_Bytes_Sec=round(random.uniform(2000, 30000), 1),
            PSH_Flag_Count=random.randint(2, 12), FIN_Flag_Count=1,
            Subnet_Group=group, Source_Subnet=subnet,
        )
    if kind == "mail":
        dest, port, proto = SERVICES["smtp"]
        return flow(
            Src_IP=src, Dst_IP=dest, Dst_Port=port, Protocol=proto,
            Flow_Duration=round(random.uniform(0.3, 5), 4),
            Total_Fwd_Packets=random.randint(8, 40), Total_Bwd_Packets=random.randint(6, 30),
            Total_Fwd_Bytes=random.randint(1000, 20000), Total_Bwd_Bytes=random.randint(800, 12000),
            Flow_IAT_Mean=round(random.uniform(0.02, 0.3), 6),
            Flow_Bytes_Sec=round(random.uniform(1000, 15000), 1),
            Subnet_Group=group, Source_Subnet=subnet,
        )
    dest, port, proto = SERVICES["mqtt"]
    return flow(
        Src_IP=src, Dst_IP=dest, Dst_Port=port, Protocol=proto,
        Flow_Duration=round(random.uniform(0.05, 2), 4),
        Total_Fwd_Packets=random.randint(1, 6), Total_Bwd_Packets=random.randint(1, 5),
        Total_Fwd_Bytes=random.randint(40, 900), Total_Bwd_Bytes=random.randint(40, 600),
        Flow_IAT_Mean=round(random.uniform(0.005, 0.4), 6),
        Flow_Bytes_Sec=round(random.uniform(200, 5000), 1),
        SYN_Flag_Count=0, ACK_Flag_Count=1, PSH_Flag_Count=0, FIN_Flag_Count=0,
        Subnet_Group=group, Source_Subnet=subnet,
    )


# --------------------------------------------------------------------------- #
# Attack generators
# --------------------------------------------------------------------------- #
def _reflection(index: int, port: int) -> dict:
    return flow(
        Src_IP=f"10.20.60.{index % 200 + 1}", Dst_IP="10.20.40.21", Dst_Port=port, Protocol=17,
        Flow_Duration=round(random.uniform(15, 60), 2),
        Total_Fwd_Packets=random.randint(20000, 60000), Total_Bwd_Packets=0,
        Total_Fwd_Bytes=random.randint(1_000_000, 3_000_000), Total_Bwd_Bytes=0,
        Fwd_Pkt_Len_Min=60, Fwd_Pkt_Len_Max=1472, Fwd_Pkt_Len_Mean=1400, Fwd_Pkt_Len_Std=20,
        Bwd_Pkt_Len_Min=0, Bwd_Pkt_Len_Max=0, Bwd_Pkt_Len_Mean=0, Bwd_Pkt_Len_Std=0,
        Flow_IAT_Mean=0.00005, Flow_IAT_Std=0.00002, Flow_IAT_Max=0.001, Flow_IAT_Min=0,
        Flow_Bytes_Sec=round(random.uniform(80000, 200000), 1),
        Flow_Packets_Sec=round(random.uniform(1000, 3000), 1),
        SYN_Flag_Count=0, ACK_Flag_Count=0, PSH_Flag_Count=0, FIN_Flag_Count=0,
    )


def ddos_dns(index: int) -> dict:
    return _reflection(index, 53)


def ddos_ntp(index: int) -> dict:
    return _reflection(index, 123)


def ddos_ssdp(index: int) -> dict:
    return _reflection(index, 1900)


def ddos_ldap(index: int) -> dict:
    return _reflection(index, 389)


def ddos_snmp(index: int) -> dict:
    return _reflection(index, 161)


def ddos_udp(index: int) -> dict:
    return _reflection(index, 4444)


def ddos_tcp(index: int) -> dict:
    return flow(
        Src_IP=f"10.20.60.{index % 200 + 1}", Dst_IP="10.20.40.21", Dst_Port=443, Protocol=6,
        Flow_Duration=round(random.uniform(10, 40), 2),
        Total_Fwd_Packets=random.randint(15000, 50000), Total_Bwd_Packets=random.randint(0, 5),
        Total_Fwd_Bytes=random.randint(800_000, 2_500_000), Total_Bwd_Bytes=random.randint(0, 500),
        Fwd_Pkt_Len_Mean=1200, Fwd_Pkt_Len_Max=1500, Bwd_Pkt_Len_Mean=40, Bwd_Pkt_Len_Max=80,
        Flow_IAT_Mean=0.00008, Flow_IAT_Std=0.00003, Flow_IAT_Max=0.002, Flow_IAT_Min=0,
        Flow_Bytes_Sec=round(random.uniform(60000, 150000), 1),
        Flow_Packets_Sec=round(random.uniform(800, 2500), 1),
        SYN_Flag_Count=random.randint(500, 2000), ACK_Flag_Count=0, PSH_Flag_Count=0, FIN_Flag_Count=0,
    )


def http_flood(index: int) -> dict:
    return flow(
        Src_IP=f"10.20.60.{index % 200 + 1}", Dst_IP="10.20.40.20", Dst_Port=80, Protocol=6,
        Flow_Duration=round(random.uniform(2, 10), 2),
        Total_Fwd_Packets=random.randint(100, 800), Total_Bwd_Packets=random.randint(10, 80),
        Total_Fwd_Bytes=random.randint(20_000, 150_000), Total_Bwd_Bytes=random.randint(2_000, 20_000),
        Fwd_Pkt_Len_Mean=900, Fwd_Pkt_Len_Std=180, Bwd_Pkt_Len_Mean=300, Bwd_Pkt_Len_Std=120,
        Flow_IAT_Mean=round(random.uniform(0.001, 0.01), 6),
        Flow_Bytes_Sec=round(random.uniform(20_000, 90_000), 1),
        Flow_Packets_Sec=round(random.uniform(100, 600), 1),
        SYN_Flag_Count=random.randint(10, 60), ACK_Flag_Count=random.randint(20, 100), PSH_Flag_Count=random.randint(5, 30),
    )


def syn_port_scan(index: int) -> dict:
    return flow(
        Src_IP="10.20.60.77", Dst_IP=f"10.20.{index % 10}.{index % 254 + 1}", Dst_Port=random.randint(1, 1024),
        Protocol=6, Flow_Duration=round(random.uniform(0.001, 0.01), 6),
        Total_Fwd_Packets=1, Total_Bwd_Packets=0, Total_Fwd_Bytes=random.randint(40, 60), Total_Bwd_Bytes=0,
        Fwd_Pkt_Len_Min=40, Fwd_Pkt_Len_Max=60, Fwd_Pkt_Len_Mean=54, Fwd_Pkt_Len_Std=2,
        Bwd_Pkt_Len_Min=0, Bwd_Pkt_Len_Max=0, Bwd_Pkt_Len_Mean=0, Bwd_Pkt_Len_Std=0,
        Flow_IAT_Mean=0.0001, Flow_IAT_Std=0.00005, Flow_IAT_Max=0.001, Flow_IAT_Min=0.00001,
        Flow_Bytes_Sec=5000, Flow_Packets_Sec=1000,
        SYN_Flag_Count=1, ACK_Flag_Count=0, PSH_Flag_Count=0, FIN_Flag_Count=0,
    )


def _bruteforce(index: int, port: int) -> dict:
    return flow(
        Src_IP=f"10.20.60.{index % 40 + 100}", Dst_IP="10.20.40.20", Dst_Port=port, Protocol=6,
        Flow_Duration=round(random.uniform(0.5, 2), 4),
        Total_Fwd_Packets=random.randint(20, 80), Total_Bwd_Packets=random.randint(5, 30),
        Total_Fwd_Bytes=random.randint(3000, 20000), Total_Bwd_Bytes=random.randint(200, 5000),
        Fwd_Pkt_Len_Mean=300, Fwd_Pkt_Len_Std=200, Bwd_Pkt_Len_Mean=100, Bwd_Pkt_Len_Std=50,
        Flow_IAT_Mean=0.03, Flow_IAT_Std=0.02, Flow_IAT_Max=0.5, Flow_IAT_Min=0.001,
        Flow_Bytes_Sec=round(random.uniform(5000, 15000), 1),
        Flow_Packets_Sec=round(random.uniform(30, 100), 1),
        SYN_Flag_Count=random.randint(5, 20), RST_Flag_Count=random.randint(3, 15), ACK_Flag_Count=random.randint(0, 5),
    )


def ssh_bruteforce(index: int) -> dict:
    return _bruteforce(index, 22)


def ftp_bruteforce(index: int) -> dict:
    return _bruteforce(index, 21)


def rdp_bruteforce(index: int) -> dict:
    return _bruteforce(index, 3389)


def web_sqli(index: int) -> dict:
    return flow(
        Src_IP=f"10.20.60.{index % 50 + 150}", Dst_IP="10.20.40.20", Dst_Port=80, Protocol=6,
        Flow_Duration=round(random.uniform(20, 90), 2),
        Total_Fwd_Packets=random.randint(500, 3000), Total_Bwd_Packets=random.randint(200, 1500),
        Total_Fwd_Bytes=random.randint(1_000_000, 10_000_000), Total_Bwd_Bytes=random.randint(500_000, 5_000_000),
        Fwd_Pkt_Len_Mean=900, Fwd_Pkt_Len_Std=300, Bwd_Pkt_Len_Mean=700, Bwd_Pkt_Len_Std=250,
        Flow_IAT_Mean=round(random.uniform(0.01, 0.03), 5), Flow_IAT_Std=0.01, Flow_IAT_Max=0.5, Flow_IAT_Min=0.001,
        Flow_Bytes_Sec=round(random.uniform(80_000, 250_000), 1),
        Flow_Packets_Sec=round(random.uniform(30, 120), 1),
        URG_Flag_Count=random.randint(2, 8), PSH_Flag_Count=random.randint(50, 150),
        SYN_Flag_Count=1, ACK_Flag_Count=random.randint(100, 600),
    )


def slowloris(index: int) -> dict:
    return flow(
        Src_IP=f"10.20.60.{index % 40 + 200}", Dst_IP="10.20.40.20", Dst_Port=80, Protocol=6,
        Flow_Duration=round(random.uniform(30, 120), 2),
        Total_Fwd_Packets=random.randint(3, 12), Total_Bwd_Packets=random.randint(0, 2),
        Total_Fwd_Bytes=random.randint(100, 800), Total_Bwd_Bytes=0,
        Fwd_Pkt_Len_Mean=80, Fwd_Pkt_Len_Std=20, Bwd_Pkt_Len_Mean=0, Bwd_Pkt_Len_Std=0,
        Flow_IAT_Mean=round(random.uniform(5, 20), 3), Flow_IAT_Std=round(random.uniform(1, 5), 3),
        Flow_IAT_Max=round(random.uniform(20, 40), 3), Flow_IAT_Min=1,
        Flow_Bytes_Sec=round(random.uniform(5, 40), 1), Flow_Packets_Sec=round(random.uniform(0.1, 1), 2),
        SYN_Flag_Count=1, ACK_Flag_Count=random.randint(0, 2), PSH_Flag_Count=0, FIN_Flag_Count=0,
    )


def c2_beacon(index: int) -> dict:
    return flow(
        Src_IP=f"10.20.20.{index % 20 + 11}", Dst_IP="185.220.100.252", Dst_Port=443, Protocol=6,
        Flow_Duration=round(random.uniform(0.1, 0.5), 4),
        Total_Fwd_Packets=random.randint(2, 5), Total_Bwd_Packets=random.randint(2, 4),
        Total_Fwd_Bytes=random.randint(100, 500), Total_Bwd_Bytes=random.randint(200, 1000),
        Fwd_Pkt_Len_Mean=120, Fwd_Pkt_Len_Std=30, Bwd_Pkt_Len_Mean=200, Bwd_Pkt_Len_Std=80,
        Flow_IAT_Mean=round(random.uniform(25, 40), 2), Flow_IAT_Std=round(random.uniform(1, 5), 2),
        Flow_IAT_Max=round(random.uniform(30, 50), 2), Flow_IAT_Min=round(random.uniform(10, 20), 2),
        Flow_Bytes_Sec=round(random.uniform(500, 3000), 1), Flow_Packets_Sec=round(random.uniform(5, 20), 1),
        FIN_Flag_Count=1, SYN_Flag_Count=0, ACK_Flag_Count=2, PSH_Flag_Count=1,
    )


def irc_botnet(index: int) -> dict:
    return flow(
        Src_IP=f"10.20.50.{index % 10 + 11}", Dst_IP="198.51.100.44", Dst_Port=6667, Protocol=6,
        Flow_Duration=round(random.uniform(20, 90), 2),
        Total_Fwd_Packets=random.randint(4, 18), Total_Bwd_Packets=random.randint(3, 12),
        Total_Fwd_Bytes=random.randint(200, 1500), Total_Bwd_Bytes=random.randint(300, 2500),
        Fwd_Pkt_Len_Mean=120, Fwd_Pkt_Len_Std=40, Bwd_Pkt_Len_Mean=160, Bwd_Pkt_Len_Std=60,
        Flow_IAT_Mean=round(random.uniform(4, 20), 2), Flow_IAT_Std=round(random.uniform(1, 6), 2),
        Flow_IAT_Max=round(random.uniform(20, 60), 2), Flow_IAT_Min=1,
        Flow_Bytes_Sec=round(random.uniform(20, 400), 1), Flow_Packets_Sec=round(random.uniform(0.2, 2), 2),
        FIN_Flag_Count=1, SYN_Flag_Count=0, ACK_Flag_Count=2,
    )


def data_exfiltration(index: int) -> dict:
    return flow(
        Src_IP=f"10.20.10.{index % 10 + 11}", Dst_IP=f"203.0.113.{index % 200 + 1}", Dst_Port=443, Protocol=6,
        Flow_Duration=round(random.uniform(30, 120), 2),
        Total_Fwd_Packets=random.randint(500, 5000), Total_Bwd_Packets=random.randint(2, 10),
        Total_Fwd_Bytes=random.randint(500_000, 5_000_000), Total_Bwd_Bytes=random.randint(100, 1000),
        Fwd_Pkt_Len_Min=1200, Fwd_Pkt_Len_Max=1500, Fwd_Pkt_Len_Mean=1450, Fwd_Pkt_Len_Std=20,
        Bwd_Pkt_Len_Min=60, Bwd_Pkt_Len_Max=100, Bwd_Pkt_Len_Mean=80, Bwd_Pkt_Len_Std=10,
        Flow_IAT_Mean=round(random.uniform(0.005, 0.02), 6), Flow_IAT_Std=round(random.uniform(0.001, 0.005), 6),
        Flow_IAT_Max=round(random.uniform(0.02, 0.1), 6), Flow_IAT_Min=round(random.uniform(0.001, 0.005), 6),
        Flow_Bytes_Sec=round(random.uniform(40_000, 100_000), 1), Flow_Packets_Sec=round(random.uniform(20, 100), 1),
        SYN_Flag_Count=0, ACK_Flag_Count=5, PSH_Flag_Count=10,
    )


def service_exploit(index: int) -> dict:
    return flow(
        Src_IP=f"10.20.60.{index % 40 + 30}", Dst_IP="10.20.40.20", Dst_Port=80, Protocol=6,
        Flow_Duration=round(random.uniform(20, 90), 2),
        Total_Fwd_Packets=random.randint(500, 3000), Total_Bwd_Packets=random.randint(200, 1500),
        Total_Fwd_Bytes=random.randint(1_000_000, 6_000_000), Total_Bwd_Bytes=random.randint(500_000, 3_000_000),
        Fwd_Pkt_Len_Mean=800, Fwd_Pkt_Len_Std=250, Bwd_Pkt_Len_Mean=600, Bwd_Pkt_Len_Std=200,
        Flow_IAT_Mean=round(random.uniform(0.01, 0.03), 5), Flow_IAT_Std=0.01, Flow_IAT_Max=0.5, Flow_IAT_Min=0.001,
        Flow_Bytes_Sec=round(random.uniform(60_000, 150_000), 1), Flow_Packets_Sec=round(random.uniform(20, 80), 1),
        URG_Flag_Count=0, PSH_Flag_Count=random.randint(30, 100), SYN_Flag_Count=1,
        ACK_Flag_Count=random.randint(50, 200),
    )


def fuzzing(index: int) -> dict:
    return flow(
        Src_IP=f"10.20.60.{index % 40 + 70}", Dst_IP="10.20.40.20", Dst_Port=8080, Protocol=6,
        Flow_Duration=round(random.uniform(10, 45), 2),
        Total_Fwd_Packets=random.randint(300, 1500), Total_Bwd_Packets=random.randint(100, 600),
        Total_Fwd_Bytes=random.randint(200_000, 1_000_000), Total_Bwd_Bytes=random.randint(50_000, 300_000),
        Fwd_Pkt_Len_Mean=500, Fwd_Pkt_Len_Std=200, Bwd_Pkt_Len_Mean=300, Bwd_Pkt_Len_Std=100,
        Flow_IAT_Mean=0.02, Flow_IAT_Std=0.01, Flow_IAT_Max=0.5, Flow_IAT_Min=0.001,
        Flow_Bytes_Sec=round(random.uniform(10_000, 40_000), 1), Flow_Packets_Sec=round(random.uniform(20, 80), 1),
        URG_Flag_Count=random.randint(30, 80), SYN_Flag_Count=1, PSH_Flag_Count=random.randint(10, 50),
    )


def shellcode(index: int) -> dict:
    return flow(
        Src_IP=f"10.20.60.{index % 40 + 90}", Dst_IP="10.20.40.30", Dst_Port=4444, Protocol=6,
        Flow_Duration=round(random.uniform(0.01, 0.4), 4),
        Total_Fwd_Packets=random.randint(1, 5), Total_Bwd_Packets=random.randint(0, 2),
        Total_Fwd_Bytes=random.randint(40, 1200), Total_Bwd_Bytes=random.randint(0, 300),
        Fwd_Pkt_Len_Mean=180, Fwd_Pkt_Len_Std=90, Bwd_Pkt_Len_Mean=60, Bwd_Pkt_Len_Std=20,
        Flow_IAT_Mean=0.01, Flow_IAT_Std=0.005, Flow_IAT_Max=0.1, Flow_IAT_Min=0.0001,
        Flow_Bytes_Sec=round(random.uniform(1000, 15000), 1), Flow_Packets_Sec=round(random.uniform(20, 300), 1),
        URG_Flag_Count=0, PSH_Flag_Count=1, SYN_Flag_Count=1,
    )


def cloud_infra(index: int) -> dict:
    return flow(
        Src_IP=f"10.20.60.{index % 40 + 120}", Dst_IP="10.20.40.21", Dst_Port=8443, Protocol=6,
        Flow_Duration=round(random.uniform(40, 150), 2),
        Total_Fwd_Packets=random.randint(1000, 4000), Total_Bwd_Packets=random.randint(500, 2000),
        Total_Fwd_Bytes=random.randint(3_000_000, 12_000_000), Total_Bwd_Bytes=random.randint(1_000_000, 6_000_000),
        Fwd_Pkt_Len_Mean=900, Fwd_Pkt_Len_Std=300, Bwd_Pkt_Len_Mean=700, Bwd_Pkt_Len_Std=250,
        Flow_IAT_Mean=round(random.uniform(0.02, 0.05), 5), Flow_IAT_Std=0.02, Flow_IAT_Max=0.5, Flow_IAT_Min=0.001,
        Flow_Bytes_Sec=round(random.uniform(60_000, 150_000), 1), Flow_Packets_Sec=round(random.uniform(20, 60), 1),
        SYN_Flag_Count=1, ACK_Flag_Count=random.randint(50, 200), PSH_Flag_Count=random.randint(20, 80),
    )


# --- Zero-day behaviours: anomalous, but outside the expert vocabulary ----------
def zero_smb_lateral(index: int) -> dict:
    return flow(
        Src_IP=f"10.20.20.{index % 10 + 11}", Dst_IP=f"10.20.40.{index % 8 + 10}", Dst_Port=445, Protocol=6,
        Flow_Duration=round(random.uniform(20, 120), 2),
        Total_Fwd_Packets=random.randint(400, 3000), Total_Bwd_Packets=random.randint(200, 1500),
        Total_Fwd_Bytes=random.randint(200_000, 3_000_000), Total_Bwd_Bytes=random.randint(100_000, 1_000_000),
        Fwd_Pkt_Len_Mean=900, Fwd_Pkt_Len_Std=220, Bwd_Pkt_Len_Mean=700, Bwd_Pkt_Len_Std=180,
        Flow_IAT_Mean=round(random.uniform(0.001, 0.01), 6), Flow_IAT_Std=round(random.uniform(0.001, 0.005), 6),
        Flow_IAT_Max=0.05, Flow_IAT_Min=0.0001,
        Flow_Bytes_Sec=round(random.uniform(20_000, 100_000), 1), Flow_Packets_Sec=round(random.uniform(100, 600), 1),
        SYN_Flag_Count=1, ACK_Flag_Count=random.randint(50, 300), PSH_Flag_Count=random.randint(20, 120), FIN_Flag_Count=1,
    )


def zero_icmp_tunnel(index: int) -> dict:
    """ICMP echo payloads are a classic covert channel, but not in the MoE vocabulary."""
    return flow(
        Src_IP=f"10.20.20.{index % 10 + 11}", Dst_IP="203.0.113.77", Src_Port=0, Dst_Port=0, Protocol=1,
        Flow_Duration=round(random.uniform(180, 600), 2),
        Total_Fwd_Packets=random.randint(2000, 6000), Total_Bwd_Packets=random.randint(1500, 5000),
        Total_Fwd_Bytes=random.randint(800_000, 4_000_000), Total_Bwd_Bytes=random.randint(600_000, 3_000_000),
        Fwd_Pkt_Len_Mean=500, Fwd_Pkt_Len_Std=120, Bwd_Pkt_Len_Mean=480, Bwd_Pkt_Len_Std=100,
        Flow_IAT_Mean=round(random.uniform(0.05, 0.12), 4), Flow_IAT_Std=round(random.uniform(0.01, 0.05), 4),
        Flow_IAT_Max=round(random.uniform(0.5, 1.5), 4), Flow_IAT_Min=0.001,
        Flow_Bytes_Sec=round(random.uniform(6000, 20_000), 1), Flow_Packets_Sec=round(random.uniform(10, 30), 1),
        SYN_Flag_Count=0, ACK_Flag_Count=0, PSH_Flag_Count=0, FIN_Flag_Count=0,
    )


def zero_cryptomining(index: int) -> dict:
    return flow(
        Src_IP=f"10.20.30.{index % 5 + 11}", Dst_IP="203.0.113.200", Dst_Port=random.choice([3333, 14444, 5555]), Protocol=6,
        Flow_Duration=round(random.uniform(120, 600), 2),
        Total_Fwd_Packets=random.randint(200, 2000), Total_Bwd_Packets=random.randint(100, 1000),
        Total_Fwd_Bytes=random.randint(200_000, 2_000_000), Total_Bwd_Bytes=random.randint(100_000, 1_000_000),
        Fwd_Pkt_Len_Mean=420, Fwd_Pkt_Len_Std=160, Bwd_Pkt_Len_Mean=380, Bwd_Pkt_Len_Std=140,
        Flow_IAT_Mean=round(random.uniform(0.2, 1.2), 4), Flow_IAT_Std=round(random.uniform(0.05, 0.4), 4),
        Flow_IAT_Max=round(random.uniform(2, 8), 4), Flow_IAT_Min=0.05,
        Flow_Bytes_Sec=round(random.uniform(2000, 20_000), 1), Flow_Packets_Sec=round(random.uniform(2, 20), 1),
        SYN_Flag_Count=1, ACK_Flag_Count=random.randint(50, 300), PSH_Flag_Count=random.randint(20, 120), FIN_Flag_Count=0,
    )


@dataclass(frozen=True)
class Scenario:
    key: str
    name: str
    expected: str
    family: str
    generator: Callable[[int], dict]
    zero_day: bool = False


SCENARIOS = [
    Scenario("ddos-dns", "DNS reflection", "Rudra · DDoS (DNS Reflection)", "DDoS", ddos_dns),
    Scenario("ddos-ntp", "NTP reflection", "Rudra · DDoS (NTP Reflection)", "DDoS", ddos_ntp),
    Scenario("ddos-ssdp", "SSDP reflection", "Rudra · DDoS (SSDP Reflection)", "DDoS", ddos_ssdp),
    Scenario("ddos-ldap", "LDAP reflection", "Rudra · DDoS (LDAP Reflection)", "DDoS", ddos_ldap),
    Scenario("ddos-snmp", "SNMP reflection", "Rudra · DDoS (SNMP Reflection)", "DDoS", ddos_snmp),
    Scenario("ddos-udp", "UDP flood", "Rudra · DDoS (UDP Flood)", "DDoS", ddos_udp),
    Scenario("ddos-tcp", "TCP SYN flood", "Rudra · DDoS (TCP Flood)", "DDoS", ddos_tcp),
    Scenario("http-flood", "HTTP flood", "Indra · DDoS (HTTP Flood)", "DDoS", http_flood),
    Scenario("syn-scan", "SYN port scan", "Indra · Port Scan", "Reconnaissance", syn_port_scan),
    Scenario("ssh-bruteforce", "SSH brute force", "Indra/Varuna · SSH brute force", "Credential Attack", ssh_bruteforce),
    Scenario("ftp-bruteforce", "FTP brute force", "Indra/Varuna · FTP brute force", "Credential Attack", ftp_bruteforce),
    Scenario("rdp-bruteforce", "RDP brute force", "Indra/Varuna · RDP brute force", "Credential Attack", rdp_bruteforce),
    Scenario("web-sqli", "Web attack / SQLi", "Varuna · Web attack", "Web Exploitation", web_sqli),
    Scenario("slowloris", "Slowloris / slow HTTP", "Indra · DoS (Slowloris)", "DDoS", slowloris),
    Scenario("c2-beacon", "C2 beacon", "Maya · C2 Beaconing", "Command and Control", c2_beacon),
    Scenario("irc-botnet", "IRC botnet", "Maya · IRC-Botnet", "Command and Control", irc_botnet),
    Scenario("data-exfiltration", "Data exfiltration", "Varuna/Rudra · Data Exfiltration", "Exfiltration", data_exfiltration),
    Scenario("service-exploit", "Service exploit", "Garuda · Service Exploit", "Exploitation", service_exploit),
    Scenario("fuzzing", "Fuzzing / exploit probing", "Garuda · Fuzzing", "Exploitation", fuzzing),
    Scenario("shellcode", "Shellcode / analysis attempt", "Garuda · Fuzzing / Analysis Attempt", "Exploitation", shellcode),
    Scenario("cloud-infra", "Cloud infrastructure exploit", "Indra · Cloud Infrastructure Exploit", "Exploitation", cloud_infra),
    Scenario("smb-lateral", "SMB lateral movement", "ZERO-DAY · novel east-west behaviour", "Behavioral Anomaly", zero_smb_lateral, True),
    Scenario("icmp-tunnel", "ICMP covert tunnel", "ZERO-DAY · covert ICMP channel", "Behavioral Anomaly", zero_icmp_tunnel, True),
    Scenario("cryptomining", "Cryptomining pool", "ZERO-DAY · mining protocol", "Behavioral Anomaly", zero_cryptomining, True),
]
SCENARIOS_BY_KEY = {scenario.key: scenario for scenario in SCENARIOS}


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def train_baseline(client: SentryClient, flows: int, fresh: bool) -> None:
    status = client.authed("GET", "/api/sentry/status") or {}
    mode = status.get("mode", "?")
    if mode == "active" and not fresh:
        print("[Baseline] Engine already active; keeping the existing environment model.")
        return
    if fresh:
        print("[Baseline] Resetting the environment model (incidents and evidence are retained)…")
        if not client.authed("POST", "/api/sentry/reset?learn_time=24", {}):
            raise SystemExit("Could not reset the engine.")
        mode = "monitoring"
    if mode == "active":
        print("[Baseline] Engine active after reset; retraining on the simulated corporate baseline.")
    print(f"[Baseline] Streaming {flows} corporate flows across finance, engineering, sales, data-center, and IoT…")
    before = int((client.authed("GET", "/api/sentry/status") or {}).get("flows_processed", 0))
    batch_size = 100
    sent = 0
    while sent < flows:
        batch = [corp_benign(index) for index in range(sent, min(sent + batch_size, flows))]
        if not client.ingest_batch(batch):
            raise SystemExit("Baseline ingestion failed.")
        sent += len(batch)
        if sent % 300 == 0 or sent == flows:
            print(f"    … {sent}/{flows}")
        time.sleep(0.03)
    client.wait_for_processing(before, flows, timeout=120)
    print("[Baseline] Triggering hierarchical autoencoder training…")
    if not client.authed("POST", "/api/sentry/train", {}):
        raise SystemExit("Training request failed.")
    deadline = time.time() + 240
    while time.time() < deadline:
        time.sleep(4)
        status = client.authed("GET", "/api/sentry/status") or {}
        mode = status.get("mode", "?")
        if mode == "active":
            print(f"[Baseline] Active · model {status.get('model_versions', {}).get('autoencoder', '?')}")
            return
    raise SystemExit("Baseline training did not become active within 4 minutes.")


def describe(client: SentryClient, incidents: list[dict]) -> tuple[str, str]:
    families = sorted({incident["family"] for incident in incidents})
    labels: list[str] = []
    for incident in incidents[:3]:
        evidence = client.incident_evidence(incident["id"])
        if evidence:
            latest = evidence[0]
            labels.append(f"{latest.get('primary_expert') or 'unknown'}:{latest.get('detection_type') or '?'}")
    return ", ".join(families) or "—", ", ".join(sorted(set(labels))) or "—"


def run_scenarios(client: SentryClient, selected: list[Scenario], count: int, delay: float) -> dict:
    results = {}
    print(f"\n[Attack matrix] {len(selected)} scenarios × {count} flows\n")
    for scenario in selected:
        before = client.snapshot()
        status = client.authed("GET", "/api/sentry/status") or {}
        flows_before = int(status.get("flows_processed", 0))
        print(f"--- {scenario.name}  [expect {scenario.expected}]")
        for index in range(count):
            if not client.ingest(scenario.generator(index)):
                print("    ingest failed")
            time.sleep(delay)
        client.wait_for_processing(flows_before, count)
        changes = client.changed_incidents(before)
        signals = sum(max(1, row["count"] - before.get(row["id"], (0, ""))[0]) for row in changes)
        family, labels = describe(client, changes)
        result = "PASS" if signals else "NO SIGNAL"
        if scenario.zero_day and signals:
            result = "ZERO-DAY SIGNAL"
        results[scenario.key] = {
            "name": scenario.name,
            "expected": scenario.expected,
            "incidents": len(changes),
            "signals": signals,
            "family": family,
            "labels": labels,
            "zero_day": scenario.zero_day,
            "result": result,
        }
        if changes:
            print(f"    => {len(changes)} incident(s), {signals} new signal(s) · family {family} · {labels}\n")
        else:
            print("    => no new incident; below the current threshold\n")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="AttackSentry corporate baseline + full attack matrix")
    parser.add_argument("--scenario", default="all", choices=["all", "known", "zero-day", *SCENARIOS_BY_KEY])
    parser.add_argument("--count", type=int, default=20, help="flows per scenario")
    parser.add_argument("--baseline-flows", type=int, default=1200)
    parser.add_argument("--skip-baseline", action="store_true")
    parser.add_argument("--fresh-baseline", action="store_true", help="reset the environment model, then train a corporate baseline")
    parser.add_argument("--baseline-only", action="store_true")
    parser.add_argument("--delay", type=float, default=0.05, help="delay between attack flows")
    parser.add_argument("--list-scenarios", action="store_true")
    parser.add_argument("--url", default=BASE)
    args = parser.parse_args()

    if args.list_scenarios:
        for scenario in SCENARIOS:
            marker = "zero-day" if scenario.zero_day else "known"
            print(f"{scenario.key:18} {marker:8} {scenario.name:28} {scenario.expected}")
        return

    print("\n" + "=" * 78)
    print("  AttackSentry · corporate baseline + attack detection matrix")
    print("=" * 78)
    client = SentryClient(args.url)
    client.login()
    client.ensure_sensor()

    if not args.skip_baseline:
        train_baseline(client, args.baseline_flows, args.fresh_baseline)
    else:
        status = client.authed("GET", "/api/sentry/status") or {}
        print(f"[Baseline] Skipped · engine mode {status.get('mode', '?')}")

    if args.baseline_only:
        return

    if args.scenario == "all":
        selected = SCENARIOS
    elif args.scenario == "known":
        selected = [scenario for scenario in SCENARIOS if not scenario.zero_day]
    elif args.scenario == "zero-day":
        selected = [scenario for scenario in SCENARIOS if scenario.zero_day]
    else:
        selected = [SCENARIOS_BY_KEY[args.scenario]]

    results = run_scenarios(client, selected, args.count, args.delay)

    print("=" * 78)
    print("  RESULTS")
    print("=" * 78)
    print(f"  {'SCENARIO':20} {'EXPECTED':34} {'INC':>4} {'SIG':>4} {'OBSERVED FAMILY':22} RESULT")
    for result in results.values():
        print(f"  {result['name'][:20]:20} {result['expected'][:34]:34} {result['incidents']:4} {result['signals']:4} {result['family'][:22]:22} {result['result']}")
    passed = sum(1 for result in results.values() if result["signals"])
    zero = sum(1 for result in results.values() if result["zero_day"] and result["signals"])
    zero_total = sum(1 for scenario in selected if scenario.zero_day)
    zero_suffix = f" · {zero}/{zero_total} zero-day behaviours detected" if zero_total else ""
    print(f"\n  {passed}/{len(results)} scenarios produced new incidents{zero_suffix}")
    status = client.authed("GET", "/api/sentry/status") or {}
    print(f"  Engine {status.get('mode')} · {status.get('flows_processed')} flows · bundle {status.get('moe_bundle_version')}")
    print("  Open the console: http://localhost:5173\n")


if __name__ == "__main__":
    main()
