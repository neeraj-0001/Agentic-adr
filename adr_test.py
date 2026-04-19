print("Starting ADR test...")
import sys

sys.path.insert(0, ".")

from aiohttp import web
import asyncio


async def health(request):
    return web.json_response({"status": "healthy", "adr": True})


async def scan_input(request):
    data = await request.json()
    text = data.get("text", "")
    # Simple test - check for injection patterns
    dangerous = ["ignore previous", "disregard", "sudo", "rm -rf"]
    for pattern in dangerous:
        if pattern.lower() in text.lower():
            return web.json_response(
                {
                    "passed": False,
                    "guardrail_type": "prompt_injection",
                    "severity": "HIGH",
                    "description": "Dangerous pattern detected: " + pattern,
                }
            )
    return web.json_response(
        {
            "passed": True,
            "guardrail_type": "prompt_injection",
            "severity": "INFO",
            "description": "No threats detected",
        }
    )


app = web.Application()
app.router.add_get("/health", health)
app.router.add_post("/v1/scan/input", scan_input)


async def start_and_wait():
    print("Starting ADR server...")
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", 8080)
    await site.start()
    print("ADR Server running on port 8080")
    await asyncio.sleep(float("inf"))


asyncio.run(start_and_wait())
