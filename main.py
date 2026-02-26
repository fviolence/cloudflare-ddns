#!/usr/bin/env python3

import os
import time
import json
import logging
import requests
import threading
import ipaddress
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from http.server import BaseHTTPRequestHandler, HTTPServer

CF_API_BASE = "https://api.cloudflare.com/client/v4"
CF_SUPPORTED_RECORD_TYPES = ("A", "AAAA")

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
    current_ipv4: str | None = None
    current_ipv6: str | None = None
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
        code = 200 if data["status"] in ("ok", "starting") else 500
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        return


def run_health_server(port: int):
    server = HTTPServer(("0.0.0.0", port), HealthHandler)
    logger.info("Health endpoint listening on 0.0.0.0:%d", port)
    server.serve_forever()


def get_public_ip(ip_url: str, family: str, retry: int = 3, retry_interval: int = 5) -> str:
    if family not in CF_SUPPORTED_RECORD_TYPES:
        raise ValueError(f"Unsupported family {family}")

    saved_e: Exception = None
    while retry > 0:
        retry -= 1
        try:
            resp = requests.get(ip_url, timeout=5)
            time.sleep(1)
            resp.raise_for_status()
            ip = resp.text.strip()

            if family == "A":
                ipaddress.IPv4Address(ip)
            elif family == "AAAA":
                ipaddress.IPv6Address(ip)

            return ip
        except Exception as e:
            saved_e = e
            time.sleep(retry_interval)

    raise RuntimeError(f"Failed to detect public {family} IP from {ip_url}: {saved_e}") from saved_e


def _headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def get_zone_id(session: requests.Session, token: str, zone_name: str,
                retry: int = 3, retry_interval: int = 5) -> str:
    params = {"name": zone_name, "status": "active"}
    resp = None

    # Avoid frequent timeout exceptions by making several get attempts
    while retry > 0:
        retry -= 1
        try:
            resp = session.get(
                f"{CF_API_BASE}/zones",
                headers=_headers(token),
                params=params,
                timeout=10
            )
            time.sleep(1)
        # except requests.Timeout as e:
        except Exception as e:
            if retry > 0:
                time.sleep(retry_interval)
                continue
            else:
                raise e
        break

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


def get_record(session: requests.Session, token: str, zone_id: str,
               record_name: str, record_type: str, retry: int = 3,
               retry_interval: int = 5) -> Optional[Dict]:
    params = {"type": record_type, "name": record_name}
    resp = None

    # Avoid frequent timeout exceptions by making several get attempts
    while retry > 0:
        retry -= 1
        try:
            resp = session.get(
                f"{CF_API_BASE}/zones/{zone_id}/dns_records",
                headers=_headers(token),
                params=params,
                timeout=10,
            )
            time.sleep(1)
        # except requests.Timeout as e:
        except Exception as e:
            if retry > 0:
                time.sleep(retry_interval)
                continue
            else:
                raise e
        break

    resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise RuntimeError(f"Error fetching DNS record {record_name} ({record_type}): {data}")

    result = data.get("result", [])
    return result[0] if result else None


def create_record(session: requests.Session, token: str, zone_id: str,
                  record_type: str, name: str, content: str, ttl: int, proxied: bool) -> Dict:
    payload = {
        "type": record_type,
        "name": name,
        "content": content,
        "ttl": ttl,
        "proxied": proxied,
    }
    resp = session.post(
        f"{CF_API_BASE}/zones/{zone_id}/dns_records",
        headers=_headers(token),
        json=payload,
        timeout=10,
    )
    time.sleep(1)
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise RuntimeError(f"Failed to create record {name} ({record_type}): {data}")
    rec = data["result"]
    logger.info("Created %s %s -> %s (ttl=%s, proxied=%s)", record_type, name, content, ttl, proxied)
    return rec


def update_record_content(session: requests.Session, token: str, zone_id: str,
                          record: Dict, record_type: str, new_content: str,
                          ttl: int, proxied: bool) -> None:
    record_id = record["id"]
    name = record["name"]

    payload = {
        "type": record_type,
        "name": name,
        "content": new_content,
        "ttl": ttl,
        "proxied": proxied,
    }

    resp = session.put(
        f"{CF_API_BASE}/zones/{zone_id}/dns_records/{record_id}",
        headers=_headers(token),
        json=payload,
        timeout=10,
    )
    time.sleep(1)
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise RuntimeError(f"Failed to update record {name} ({record_type}): {data}")

    logger.info("Updated %s %s -> %s (ttl=%s, proxied=%s)", record_type, name, new_content, ttl, proxied)


def parse_records_env(records_env: str, zone_name: str) -> List[str]:
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
            records.append(f"{raw}.{zone_name}")
    return records


def parse_types_env(types_env: str) -> List[str]:
    types: List[str] = []
    for t in types_env.split(","):
        t = t.strip().upper()
        if not t:
            continue
        if t not in CF_SUPPORTED_RECORD_TYPES:
            raise RuntimeError(f"Unsupported record type in CF_RECORD_TYPES: {t}")
        types.append(t)
    return types or ["A"]


def main():
    token = get_env("CF_API_TOKEN", required=True)
    zone_name = get_env("CF_ZONE_NAME", required=True)
    records_env = get_env("CF_RECORDS", required=True)

    record_types = parse_types_env(get_env("CF_RECORD_TYPES", "A"))
    create_missing = get_env("CF_CREATE_MISSING", "false").lower() in ("1", "true", "yes")

    ipv4_url = get_env("IPV4_DISCOVERY_URL", "https://ipv4.icanhazip.com")
    ipv6_url = get_env("IPV6_DISCOVERY_URL", "https://ipv6.icanhazip.com")

    interval = int(get_env("CHECK_INTERVAL", "300"))
    ttl = int(get_env("CF_TTL", "120"))
    proxied = get_env("CF_PROXIED", "false").lower() in ("1", "true", "yes")
    health_port = int(get_env("HEALTH_PORT", "8080"))

    record_names = parse_records_env(records_env, zone_name)

    logger.info("Starting Cloudflare DDNS for zone %s", zone_name)
    logger.info("Records to manage: %s", ", ".join(record_names))
    logger.info("Record types: %s", ", ".join(record_types))
    logger.info("Check interval: %s seconds", interval)

    with health_lock:
        health.status = "starting"
        health.last_error = None

    t = threading.Thread(target=run_health_server, args=(health_port,), daemon=True)
    t.start()

    session = requests.Session()
    zone_id = None
    retry_sec = 5
    while True:
        try:
            zone_id = get_zone_id(session, token, zone_name)
            break
        except Exception as e:
            logger.error(f"Failed to get zoneID: '{e}'")
            logger.error(f"Retry in {retry_sec}")
            with health_lock:
                health.status = "error"
                health.last_error = str(e)
            time.sleep(retry_sec)
            retry_sec = retry_sec * 2 if retry_sec < 30 else 30

    with health_lock:
        health.status = "starting"
        health.last_error = None

    last_ips: Dict[str, Optional[str]] = {t: None for t in record_types}

    while True:
        now = time.time()
        with health_lock:
            health.last_check = now

        # Discover current public IP(s)
        current_ips: Dict[str, str] = {}
        try:
            if "A" in record_types:
                current_ips["A"] = get_public_ip(ipv4_url, "A")
            if "AAAA" in record_types:
                current_ips["AAAA"] = get_public_ip(ipv6_url, "AAAA")
        except Exception as e:
            logger.error("%s", e)
            with health_lock:
                health.status = "error"
                health.last_error = str(e)
            time.sleep(interval)
            continue

        with health_lock:
            health.current_ipv4 = current_ips.get("A")
            health.current_ipv6 = current_ips.get("AAAA")

        any_updated = False
        healthy = True

        for rtype in record_types:
            current = current_ips.get(rtype)
            if not current:
                continue

            if last_ips.get(rtype) != current:
                logger.info("%s IP changed: %s -> %s", rtype, last_ips.get(rtype), current)

            for name in record_names:
                try:
                    rec = get_record(session, token, zone_id, name, rtype)
                    if rec is None:
                        if create_missing:
                            create_record(session, token, zone_id, rtype, name, current, ttl, proxied)
                            any_updated = True
                        continue

                    remote = rec.get("content")
                    if remote != current:
                        update_record_content(session, token, zone_id, rec, rtype, current, ttl, proxied)
                        any_updated = True
                except Exception as e:
                    healthy = False
                    logger.error("Failed to check/update %s %s: %s", rtype, name, e)
                    with health_lock:
                        health.status = "error"
                        health.last_error = f"Update failed for {rtype} {name}: {e}"

            last_ips[rtype] = current

        if any_updated:
            with health_lock:
                health.last_change = now

        with health_lock:
            if healthy:
                health.status = "ok"
                health.last_success = now
                health.last_error = None

        time.sleep(interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
