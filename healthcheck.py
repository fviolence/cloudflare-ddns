#!/usr/bin/env python3

import os
import sys
import json
import urllib.request

port = os.getenv("HEALTH_PORT", "8080")
url = f"http://127.0.0.1:{port}/healthz"

try:
    with urllib.request.urlopen(url, timeout=5) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        status = data.get("status", "error")
        # Treat "ok" and "starting" as healthy
        if status not in ("ok", "starting"):
            sys.exit(1)
except Exception:
    sys.exit(1)
