print("Starting test...")
import sys

sys.path.insert(0, ".")

from aiohttp import web
import asyncio

print("Creating app...")
app = web.Application()


async def health(request):
    return web.json_response({"status": "healthy", "test": True})


app.router.add_get("/health", health)


async def start_and_wait():
    print("Starting server...")
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", 8080)
    await site.start()
    print("Server started on port 8080")
    await asyncio.sleep(float("inf"))


print("Running...")
asyncio.run(start_and_wait())
