#!/usr/bin/env python3

import os
import time
import json
import logging
import requests
import threading
from typing import Dict, List
from dataclasses import dataclass, asdict
from http.server import BaseHTTPRequestHandler, HTTPServer


CF_API_BASE = "https://api.cloudflare.com/client/v4"


def get_env(name: str, default: str | None = None, required: bool = False) -> str:
    value = os.getenv(name, default)
    if required and not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def setup_logger() -> logging.Logger:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    return logging.getLogger("cloudflare-ddns")


logger = setup_logger()


@dataclass
class HealthState:
    status: str = "starting"         # starting / ok / error
    current_ip: str | None = None
    last_check: float | None = None
    last_success: float | None = None
    last_change: float | None = None
    last_error: str | None = None


health = HealthState()
health_lock = threading.Lock()


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/healthz", "/health", "/"):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")
            return

        with health_lock:
            data = asdict(health)

        body = json.dumps(data).encode("utf-8")

        # HTTP status: 200 for ok/starting, 500 for error
        code = 200 if data["status"] in ("ok", "starting") else 500
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # Silence default logging
    def log_message(self, format: str, *args) -> None:
        return


def run_health_server(port: int):
    server = HTTPServer(("0.0.0.0", port), HealthHandler)
    logger.info("Health endpoint listening on 0.0.0.0:%d", port)
    server.serve_forever()


def get_public_ip(ip_url: str) -> str:
    try:
        resp = requests.get(ip_url, timeout=5)
        resp.raise_for_status()
        ip = resp.text.strip()
        logger.debug("Detected external IP: %s", ip)
        return ip
    except Exception as e:
        raise RuntimeError(f"Failed to detect public IP from {ip_url}: {e}") from e


def get_zone_id(session: requests.Session, token: str, zone_name: str) -> str:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    params = {"name": zone_name, "status": "active"}

    resp = session.get(f"{CF_API_BASE}/zones", headers=headers, params=params, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise RuntimeError(f"Error fetching zone ID: {data}")

    result = data.get("result", [])
    if not result:
        raise RuntimeError(f"No active zone found for {zone_name}")

    zone_id = result[0]["id"]
    logger.info("Using zone %s (id=%s)", zone_name, zone_id)
    return zone_id


def get_record(session: requests.Session, token: str, zone_id: str, record_name: str) -> Dict:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    params = {"type": "A", "name": record_name}

    resp = session.get(
        f"{CF_API_BASE}/zones/{zone_id}/dns_records",
        headers=headers,
        params=params,
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise RuntimeError(f"Error fetching DNS record {record_name}: {data}")

    result = data.get("result", [])
    if not result:
        raise RuntimeError(f"No A record found for {record_name} in zone {zone_id}")

    record = result[0]
    return record


def update_record_ip(session: requests.Session, token: str, zone_id: str,
                     record: Dict, new_ip: str, ttl: int, proxied: bool) -> None:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    record_id = record["id"]
    name = record["name"]

    payload = {
        "type": "A",
        "name": name,
        "content": new_ip,
        "ttl": ttl,
        "proxied": proxied,
    }

    resp = session.put(
        f"{CF_API_BASE}/zones/{zone_id}/dns_records/{record_id}",
        headers=headers,
        json=payload,
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise RuntimeError(f"Failed to update record {name}: {data}")

    logger.info("Updated %s to %s (ttl=%s, proxied=%s)", name, new_ip, ttl, proxied)


def parse_records_env(records_env: str, zone_name: str) -> List[str]:
    """
    CF_RECORDS can contain:
      - full names
      - or just labels
      - or the zone apex
    """
    records: List[str] = []
    for raw in records_env.split(","):
        raw = raw.strip()
        if not raw:
            continue
        if raw == "@":
            records.append(zone_name)
        elif raw.endswith("." + zone_name) or raw == zone_name:
            records.append(raw)
        else:
            # treat as label
            records.append(f"{raw}.{zone_name}")
    return records


def main():
    token = get_env("CF_API_TOKEN", required=True)
    zone_name = get_env("CF_ZONE_NAME", required=True)
    records_env = get_env("CF_RECORDS", required=True)
    ip_url = get_env("IP_DISCOVERY_URL", "https://checkip.amazonaws.com")
    interval = int(get_env("CHECK_INTERVAL", "300"))
    ttl = int(get_env("CF_TTL", "120"))
    proxied = get_env("CF_PROXIED", "false").lower() in ("1", "true", "yes")
    health_port = int(get_env("HEALTH_PORT", "8080"))

    record_names = parse_records_env(records_env, zone_name)
    logger.info("Starting Cloudflare DDNS for zone %s", zone_name)
    logger.info("Records to manage: %s", ", ".join(record_names))
    logger.info("Check interval: %s seconds", interval)

    # initial health state
    with health_lock:
        health.status = "starting"
        health.last_error = None

    # start health server in background
    t = threading.Thread(target=run_health_server, args=(health_port,), daemon=True)
    t.start()

    session = requests.Session()
    zone_id: str | None = None
    last_ip: str | None = None
    records: Dict[str, Dict] = {}

    # Obtain zone ID : one-time
    while True:
        try:
            zone_id = get_zone_id(session, token, zone_name)
            # Successfully execute once
            break
        except Exception as e:
            logger.exception("Zone lookup failed")
            with health_lock:
                health.status = "error"
                health.last_error = f"Zone lookup failed: {e}"
            time.sleep(interval)
            continue

    # Cache record definitions (id, name) : one-time
    while True:
        try:
            for name in record_names:
                records[name] = get_record(session, token, zone_id, name)
                logger.info("Found record %s (id=%s) current IP=%s",
                            records[name]["name"], records[name]["id"], records[name]["content"])
            # Successfully execute once
            break
        except Exception as e:
            logger.exception("Record lookup failed")
            with health_lock:
                health.status = "error"
                health.last_error = f"Record lookup failed: {e}"
            time.sleep(interval)
            continue

    # Main loop
    while True:
        now = time.time()
        with health_lock:
            health.last_check = now

        try:
            current_ip = get_public_ip(ip_url)
        except Exception as e:
            logger.error("Public IP check failed: %s", e)
            with health_lock:
                health.status = "error"
                health.last_error = f"IP check failed: {e}"
            time.sleep(interval)
            continue

        ip_changed = last_ip != current_ip
        if ip_changed:
            logger.info("Detected IP change: %s -> %s", last_ip, current_ip)

        any_updated = False
        # 'local' health flag required so that reported health status can be
        # set back to 'ok' after the connection restores
        healthy = True

        # Re-read each record from Cloudflare and fix drift if needed
        for name in record_names:
            try:
                rec = get_record(session, token, zone_id, name)
                records[name] = rec
                remote_ip = rec.get("content")
                if remote_ip != current_ip:
                    logger.info("Record %s has IP %s, expected %s. Updating in Cloudflare.",
                                name, remote_ip, current_ip)
                    update_record_ip(session, token, zone_id, rec, current_ip, ttl, proxied)
                    any_updated = True
            except Exception as e:
                healthy = False
                logger.error("Failed to check/update record %s: %s", name, e)
                with health_lock:
                    health.status = "error"
                    health.last_error = f"Update failed for {name}: {e}"
                # continue with other records

        if any_updated:
            with health_lock:
                health.last_change = now

        # if we reach here, loop iteration succeeded (even if some records failed,
        # health.status will remain "error" and we won't overwrite it)
        with health_lock:
            if healthy:
                health.status = "ok"
                health.current_ip = current_ip
                health.last_success = now
                health.last_error = None

        last_ip = current_ip
        time.sleep(interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
