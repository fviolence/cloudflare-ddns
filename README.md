# cloudflare-ddns

Small containerized DDNS service for Cloudflare.

It periodically checks your public IP and keeps one or more **A records** in a Cloudflare zone pointing at that IP. It also exposes a small HTTP health endpoint and integrates with Docker’s `HEALTHCHECK`.

Typical use case: home servers with a dynamic IP, using Cloudflare as DNS.

---

## Features

- Keeps selected **A records** in sync with your current public IPv4
- Detects and **corrects manual changes** made via the Cloudflare UI
- Built-in **health endpoint** (`/healthz`) and Docker `HEALTHCHECK`
- Simple configuration via environment variables
- Designed to run as a lightweight Docker container
- Supports multiple records (e.g. `example.com`, `xyz.example.com`)

> **Note:** This tool currently manages **A records (IPv4)** only.

---

## How it works

1. Detects your current public IP (default via `https://checkip.amazonaws.com`).
2. For each configured record (e.g. `xyz.example.com`):
   - Fetches the current A record from Cloudflare.
   - If the IP doesn’t match the current public IP, it updates the record.
3. Repeats on a configurable interval.

In addition to reacting to IP changes, it also ensures that records stay correct even if someone edits them manually in the Cloudflare dashboard.

---

## Environment variables

Required:

- **`CF_API_TOKEN`** - Cloudflare API token, scoped to the specific zone you want to manage:
  - `Zone → DNS → Edit` (Optionally `Zone → Zone → Read`)

- **`CF_ZONE_NAME`** - Your Cloudflare zone, e.g.: `example.com`

- **`CF_RECORDS`** - Comma-separated list of records to manage. Each entry can be:
  - A label: `xyz` → becomes `xyz.example.com`
  - A full name: `xyz.example.com`
  - `@` or `example.com` for the zone apex

Optional:

* **`CHECK_INTERVAL`**
  How often to check/update (in seconds).
  Default: `300` (5 minutes)

* **`CF_TTL`**
  TTL to set on updated records.
  Default: `120`

* **`CF_PROXIED`**
  Whether to set `proxied` to `true` or `false` on updated A records:

  * `false` → DNS only

  * `true` → use Cloudflare proxy (for typical HTTP services). Default: `false`
    > Accepted values: `true`, `false`, `1`, `0`, `yes`, `no`

* **`IP_DISCOVERY_URL`**
  URL returning your public IP as plain text.
  Default: `https://checkip.amazonaws.com`

* **`HEALTH_PORT`**
  Port for the internal HTTP health server.
  Default: `8080`

---

## Health endpoint

The container runs a small HTTP server on `0.0.0.0:$HEALTH_PORT` (default `8080`) with:

* `GET /healthz`
* `GET /health`
* `GET /`

Example response:

```json
{
  "status": "ok",
  "current_ip": "203.0.113.42",
  "last_check": 1733300000.0,
  "last_success": 1733300000.0,
  "last_change": 1733299900.0,
  "last_error": null
}
```

`status` values:

* `starting` – service is initializing / hasn’t successfully synced yet
* `ok` – last run succeeded
* `error` – last run encountered an error (see `last_error`)

You can optionally map this port to the host for scraping or debugging:

```bash
curl http://127.0.0.1:8080/healthz
```

---

## Quick start (docker-compose)

```yaml
services:
  cloudflare-ddns:
    image: fviolence/cloudflare-ddns:latest
    container_name: cloudflare-ddns
    restart: unless-stopped
    environment:
      CF_API_TOKEN: "${CF_API_TOKEN}"
      CF_ZONE_NAME: "example.com"
      CF_RECORDS: "xyz"
      CHECK_INTERVAL: "300"
      CF_TTL: "120"
      CF_PROXIED: "false"
      HEALTH_PORT: "8080"
    # Optionally expose the health endpoint on the host:
    # ports:
    #   - "127.0.0.1:8080:8080"
```

To verify DNS:

```bash
dig A xyz.example.com +short
```

If you change the A record manually in the Cloudflare UI, the container will correct it on the next loop to match your current public IP.

---

## Limitations / TODO
* IPv4 only (A records). No AAAA/IPv6 support yet.
* Single global `CF_PROXIED` setting for all managed records.
* Designed for one zone per container (run multiple containers if you manage many zones).
