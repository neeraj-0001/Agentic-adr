#!/usr/bin/env python3
import asyncio
import threading
import time
import sys

sys.path.insert(0, ".")

from src.api.server import ADRServer


def run_server():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    server = ADRServer(port=8080)
    loop.run_until_complete(server.start())


print("Starting ADR server in background thread...")
thread = threading.Thread(target=run_server, daemon=True)
thread.start()
print("Server thread started, waiting for it to be ready...")
time.sleep(3)

import urllib.request

try:
    response = urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=5)
    print("Health check response:", response.read().decode())
except Exception as e:
    print("Health check failed:", e)

print("Keeping server running for 60 seconds...")
time.sleep(60)
print("Done")
