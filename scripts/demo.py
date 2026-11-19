#!/usr/bin/env python3
"""AttackSentry demo traffic generator.

Subcommands:
  setup                      Login as admin, create a sensor, print its API key
                             (also saves key_id/secret to .demo_key).
  baseline [--seconds N]     Stream realistic benign traffic (default 240s).
  attack  [--scenario S]     Stream a specific attack scenario:
                               ddos        DNS-reflection flood
                               scan        port scan (recon)
                               bruteforce  SSH brute force
                               beacon      C2 beaconing (periodic)
                               exfil       data exfiltration (large outbound)

The script talks to the backend at SENTRY_URL (default http://localhost:8000)
using sensor API-key auth on /api/ingest/flow.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BASE_URL = os.environ.get("SENTRY_URL", "http://localhost:8000")
KEY_FILE = REPO / "scripts" / ".demo_key"

# Realistic simulated environment: IP -> (hostname, OS, group)
HOSTS = {
    "192.168.1.10": ("DC-01", "Windows Server 2022", "domain-controllers"),
    "192.168.1.11": ("WEB-PROD-01", "Ubuntu 22.04", "web-servers"),
    "192.168.1.12": ("DB-MASTER", "Windows Server 2019", "database-servers"),
    "192.168.1.13": ("MAIL-01", "Ubuntu 20.04", "mail-servers"),
    "192.168.1.20": ("WORKSTATION-20", "Windows 11 Pro", "workstations"),
    "192.168.1.21": ("WORKSTATION-21", "Windows 11 Pro", "workstations"),
    "192.168.1.22": ("WORKSTATION-22", "Windows 10 Pro", "workstations"),
    "192.168.1.23": ("WORKSTATION-23", "macOS 14", "workstations"),
    "192.168.1.30": ("WORKSTATION-30", "Windows 11 Pro", "workstations"),
    "192.168.1.31": ("LAPTOP-DEV", "Ubuntu 24.04", "developers"),
    "192.168.1.32": ("LAPTOP-QA", "Windows 11 Pro", "qa"),
    "192.168.1.40": ("NAS-FINANCE", "Synology DSM", "storage"),
    "192.168.1.50": ("IOT-CAM-01", "Linux Embedded", "iot-devices"),
    "192.168.1.51": ("IOT-SENSOR-02", "Linux Embedded", "iot-devices"),
    "192.168.1.60": ("PRINTER-F2", "Embedded", "printers"),
    "192.168.1.99": ("VPN-GW", "pfSense", "network-infra"),
}

SERVERS = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]


def _rand():
    return random.SystemRandom()


def load_key():
    if not KEY_FILE.exists():
        print("No API key found. Run `python scripts/demo.py setup` first.", file=sys.stderr)
        sys.exit(1)
    return json.loads(KEY_FILE.read_text())


def _post(flows: list[dict], key_id: str, secret: str) -> None:
    body = json.dumps(flows).encode()
    req = urllib.request.Request(
        f"{BASE_URL}/api/ingest/flow", data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Sentry-Key-ID": key_id,
            "X-Sentry-Secret": secret,
        },
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as e:
        print(f"ingest HTTP {e.code}: {e.read()[:200]}")
    except Exception as e:
        print(f"ingest error: {e}")


def _flow(src_ip, dst_ip, src_port, dst_port, protocol, *, fwd_pkts, bwd_pkts,
          fwd_bytes, bwd_bytes, iat_mean, iat_std, duration, flags=None, pkt_len_mean=None):
    """Build a canonical flow dict (with realistic host metadata)."""
    fwd_len_mean = pkt_len_mean or (fwd_bytes / max(fwd_pkts, 1))
    flags = flags or {"SYN": 1, "ACK": max(fwd_pkts - 1, 0)}
    h = HOSTS.get(src_ip)
    return {
        "Src_IP": src_ip, "Dst_IP": dst_ip,
        "Hostname": h[0] if h else None,
        "OS": h[1] if h else None,
        "Subnet_Group": h[2] if h else "external",
        "Src_Port": src_port, "Dst_Port": dst_port, "Protocol": protocol,
        "Flow_Duration": duration,
        "Total_Fwd_Packets": fwd_pkts, "Total_Bwd_Packets": bwd_pkts,
        "Total_Fwd_Bytes": fwd_bytes, "Total_Bwd_Bytes": bwd_bytes,
        "Fwd_Pkt_Len_Min": max(fwd_len_mean * 0.6, 40), "Fwd_Pkt_Len_Max": fwd_len_mean * 1.4,
        "Fwd_Pkt_Len_Mean": fwd_len_mean, "Fwd_Pkt_Len_Std": fwd_len_mean * 0.2,
        "Bwd_Pkt_Len_Min": 40.0, "Bwd_Pkt_Len_Max": 1400.0,
        "Bwd_Pkt_Len_Mean": (bwd_bytes / max(bwd_pkts, 1)), "Bwd_Pkt_Len_Std": 200.0,
        "Flow_IAT_Mean": iat_mean, "Flow_IAT_Std": iat_std,
        "Flow_IAT_Max": iat_mean * 3, "Flow_IAT_Min": 0.0,
        "Flow_Bytes_Sec": (fwd_bytes + bwd_bytes) / max(duration, 0.001),
        "Flow_Packets_Sec": (fwd_pkts + bwd_pkts) / max(duration, 0.001),
        "FIN_Flag_Count": flags.get("FIN", 0), "SYN_Flag_Count": flags.get("SYN", 0),
        "RST_Flag_Count": flags.get("RST", 0), "PSH_Flag_Count": flags.get("PSH", 0),
        "ACK_Flag_Count": flags.get("ACK", 0), "URG_Flag_Count": flags.get("URG", 0),
    }


# ────────────────────────────────────────────────────────────────────────── #
# Benign traffic
# ────────────────────────────────────────────────────────────────────────── #
def benign_batch(rng, n=8):
    flows = []
    for _ in range(n):
        kind = rng.random()
        host = rng.choice(list(HOSTS))
        if kind < 0.4:  # web
            flows.append(_flow(host, rng.choice(["142.250.0.1", "151.101.0.1", "104.16.0.1"]),
                               rng.randint(40000, 60000), 443, 6,
                               fwd_pkts=rng.randint(8, 40), bwd_pkts=rng.randint(6, 40),
                               fwd_bytes=rng.randint(2000, 80000), bwd_bytes=rng.randint(4000, 120000),
                               iat_mean=rng.uniform(0.05, 0.5), iat_std=rng.uniform(0.02, 0.3),
                               duration=rng.uniform(0.5, 8)))
        elif kind < 0.6:  # DNS
            flows.append(_flow(host, "8.8.8.8", rng.randint(40000, 60000), 53, 17,
                               fwd_pkts=1, bwd_pkts=1, fwd_bytes=60, bwd_bytes=rng.randint(80, 400),
                               iat_mean=0.01, iat_std=0.005, duration=0.05, flags={"SYN": 0, "ACK": 0}))
        elif kind < 0.8:  # HTTPS streaming
            flows.append(_flow(host, "151.101.0.2", rng.randint(40000, 60000), 443, 6,
                               fwd_pkts=rng.randint(200, 1000), bwd_pkts=rng.randint(20, 100),
                               fwd_bytes=rng.randint(200000, 2000000), bwd_bytes=rng.randint(20000, 100000),
                               iat_mean=rng.uniform(0.001, 0.05), iat_std=rng.uniform(0.001, 0.02),
                               duration=rng.uniform(5, 30)))
        else:  # internal service (DB/AD)
            flows.append(_flow(host, rng.choice(SERVERS), rng.randint(40000, 60000), rng.choice([445, 1433, 389]), 6,
                               fwd_pkts=rng.randint(5, 30), bwd_pkts=rng.randint(5, 30),
                               fwd_bytes=rng.randint(1000, 40000), bwd_bytes=rng.randint(1000, 40000),
                               iat_mean=rng.uniform(0.01, 0.3), iat_std=rng.uniform(0.005, 0.1),
                               duration=rng.uniform(0.2, 5)))
    return flows


# ────────────────────────────────────────────────────────────────────────── #
# Attack scenarios
# ────────────────────────────────────────────────────────────────────────── #
def attack_ddos(rng, n=20):
    flows = []
    for _ in range(n):
        src = f"10.0.{rng.randint(1, 200)}.{rng.randint(1, 200)}"  # spoofed
        flows.append(_flow(src, "192.168.1.10", rng.randint(1, 65535), 53, 17,
                           fwd_pkts=rng.randint(20000, 60000), bwd_pkts=0,
                           fwd_bytes=rng.randint(1_000_000, 3_000_000), bwd_bytes=0,
                           iat_mean=0.0001, iat_std=0.0001, duration=rng.uniform(20, 60),
                           flags={"SYN": 0, "ACK": 0}, pkt_len_mean=512.0))
    return flows


def attack_scan(rng, n=50):
    flows = []
    scanner = rng.choice(list(HOSTS))
    for _ in range(n):
        dst_port = rng.randint(1, 65535)
        flows.append(_flow(scanner, rng.choice(list(HOSTS)), rng.randint(40000, 60000), dst_port, 6,
                           fwd_pkts=1, bwd_pkts=0, fwd_bytes=40, bwd_bytes=0,
                           iat_mean=0.001, iat_std=0.0005, duration=0.001,
                           flags={"SYN": 1, "ACK": 0, "RST": 0}))
    return flows


def attack_bruteforce(rng, n=40):
    flows = []
    attacker = rng.choice(list(HOSTS))
    for _ in range(n):
        flows.append(_flow(attacker, "192.168.1.10", rng.randint(30000, 50000), 22, 6,
                           fwd_pkts=rng.randint(4, 12), bwd_pkts=rng.randint(2, 6),
                           fwd_bytes=rng.randint(400, 1500), bwd_bytes=rng.randint(200, 800),
                           iat_mean=rng.uniform(0.1, 0.5), iat_std=rng.uniform(0.05, 0.2),
                           duration=rng.uniform(0.5, 3),
                           flags={"SYN": 1, "ACK": rng.randint(1, 6), "PSH": rng.randint(1, 4), "RST": rng.randint(0, 2)}))
    return flows


def attack_beacon(rng, n=12):
    flows = []
    bot = rng.choice(list(HOSTS))
    c2 = "203.0.113.99"
    for _ in range(n):
        flows.append(_flow(bot, c2, rng.randint(40000, 60000), 443, 6,
                           fwd_pkts=3, bwd_pkts=2, fwd_bytes=300, bwd_bytes=200,
                           iat_mean=0.05, iat_std=0.01, duration=0.5,
                           flags={"SYN": 1, "ACK": 2, "PSH": 1}))
    return flows


def attack_exfil(rng, n=15):
    flows = []
    insider = rng.choice(list(HOSTS))
    for _ in range(n):
        flows.append(_flow(insider, "198.51.100.77", rng.randint(40000, 60000), 443, 6,
                           fwd_pkts=rng.randint(5000, 20000), bwd_pkts=rng.randint(20, 60),
                           fwd_bytes=rng.randint(5_000_000, 40_000_000), bwd_bytes=rng.randint(10000, 30000),
                           iat_mean=0.0005, iat_std=0.0002, duration=rng.uniform(30, 90),
                           flags={"SYN": 1, "ACK": rng.randint(5000, 20000), "PSH": rng.randint(1000, 5000)}))
    return flows


def attack_webapp(rng, n=25):
    """SQLi / XSS probe bursts against the web server (port 80/443)."""
    flows = []
    attacker = rng.choice(list(HOSTS))
    for _ in range(n):
        flows.append(_flow(attacker, "192.168.1.11", rng.randint(40000, 60000), rng.choice([80, 443]), 6,
                           fwd_pkts=rng.randint(3, 20), bwd_pkts=rng.randint(2, 10),
                           fwd_bytes=rng.randint(200, 4000), bwd_bytes=rng.randint(200, 2000),
                           iat_mean=rng.uniform(0.02, 0.2), iat_std=rng.uniform(0.01, 0.1),
                           duration=rng.uniform(0.3, 3),
                           flags={"SYN": 1, "ACK": rng.randint(2, 12), "PSH": rng.randint(1, 6)}))
    return flows


def attack_rdp(rng, n=30):
    """RDP brute force against a workstation."""
    flows = []
    attacker = rng.choice(list(HOSTS))
    for _ in range(n):
        flows.append(_flow(attacker, "192.168.1.30", rng.randint(30000, 50000), 3389, 6,
                           fwd_pkts=rng.randint(4, 15), bwd_pkts=rng.randint(2, 8),
                           fwd_bytes=rng.randint(300, 2000), bwd_bytes=rng.randint(200, 1200),
                           iat_mean=rng.uniform(0.1, 0.4), iat_std=rng.uniform(0.05, 0.2),
                           duration=rng.uniform(0.5, 3),
                           flags={"SYN": 1, "ACK": rng.randint(1, 8), "PSH": rng.randint(1, 5), "RST": rng.randint(0, 2)}))
    return flows


def attack_fuzz(rng, n=20):
    """Fuzzing / shellcode probing — erratic packet sizes to random ports."""
    flows = []
    attacker = rng.choice(list(HOSTS))
    for _ in range(n):
        dst_port = rng.choice([21, 22, 25, 445, 1433, 3306])
        fwd_pkts = rng.randint(2, 12)
        flows.append(_flow(attacker, rng.choice(SERVERS), rng.randint(40000, 60000), dst_port, 6,
                           fwd_pkts=fwd_pkts, bwd_pkts=rng.randint(0, 4),
                           fwd_bytes=rng.randint(80, 4000), bwd_bytes=rng.randint(0, 800),
                           iat_mean=rng.uniform(0.005, 0.2), iat_std=rng.uniform(0.002, 0.1),
                           duration=rng.uniform(0.1, 2),
                           flags={"SYN": 1, "ACK": max(fwd_pkts - 1, 0), "PSH": rng.randint(0, 4), "URG": rng.randint(0, 2)}))
    return flows


SCENARIOS = {
    "ddos": attack_ddos,
    "scan": attack_scan,
    "bruteforce": attack_bruteforce,
    "beacon": attack_beacon,
    "exfil": attack_exfil,
    "webapp": attack_webapp,
    "rdp": attack_rdp,
    "fuzz": attack_fuzz,
}


# ────────────────────────────────────────────────────────────────────────── #
# CLI
# ────────────────────────────────────────────────────────────────────────── #
def _session():
    import http.cookiejar
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def cmd_setup(args):
    import urllib.request as u
    # Read admin password from Sentry/.env
    admin_pw = None
    envf = REPO / "Sentry" / ".env"
    for line in envf.read_text().splitlines() if envf.exists() else []:
        if line.startswith("SENTRY_BOOTSTRAP_ADMIN_PASSWORD="):
            admin_pw = line.split("=", 1)[1].strip()
    if not admin_pw:
        print("Could not read admin password from Sentry/.env", file=sys.stderr)
        sys.exit(1)

    opener = _session()

    # Login (sets httpOnly cookies in the jar)
    req = u.Request(f"{BASE_URL}/api/auth/login", data=json.dumps({"username": "admin", "password": admin_pw}).encode(),
                    method="POST", headers={"Content-Type": "application/json"})
    opener.open(req, timeout=5)
    print("logged in as admin")

    # Create sensor (cookie-authenticated)
    req = u.Request(f"{BASE_URL}/api/sensors", data=json.dumps({"name": "demo-sensor", "sensor_type": "virtual"}).encode(),
                    method="POST", headers={"Content-Type": "application/json"})
    resp = opener.open(req, timeout=5)
    sensor = json.loads(resp.read())
    print(f"created sensor {sensor['id']}")

    # Issue API key
    req = u.Request(f"{BASE_URL}/api/sensors/{sensor['id']}/api-key", data=b"", method="POST")
    resp = opener.open(req, timeout=5)
    key = json.loads(resp.read())
    KEY_FILE.write_text(json.dumps(key))
    print(f"saved API key to {KEY_FILE}")
    print(f"key_id : {key['key_id']}")


def cmd_baseline(args):
    key = load_key()
    rng = _rand()
    end = time.time() + args.seconds
    print(f"Streaming benign traffic for {args.seconds}s…")
    while time.time() < end:
        _post(benign_batch(rng), key["key_id"], key["secret"])
        time.sleep(0.5)


def cmd_attack(args):
    key = load_key()
    rng = _rand()
    scenario = args.scenario
    fn = SCENARIOS[scenario]
    print(f"Launching attack scenario: {scenario}")
    for _ in range(args.rounds):
        _post(fn(rng), key["key_id"], key["secret"])
        time.sleep(args.interval)


def main():
    p = argparse.ArgumentParser(prog="demo.py", description="AttackSentry demo traffic generator")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("setup")
    sp.set_defaults(fn=cmd_setup)

    bp = sub.add_parser("baseline")
    bp.add_argument("--seconds", type=int, default=240)
    bp.set_defaults(fn=cmd_baseline)

    ap = sub.add_parser("attack")
    ap.add_argument("--scenario", choices=sorted(SCENARIOS), required=True)
    ap.add_argument("--rounds", type=int, default=10)
    ap.add_argument("--interval", type=float, default=1.0)
    ap.set_defaults(fn=cmd_attack)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
