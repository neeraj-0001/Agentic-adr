#!/usr/bin/env python3
import asyncio
import json
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from dataclasses import asdict

from aiohttp import web

from src.collector.telemetry import get_collector, init_otel
from src.storage.clickhouse_store import AgenticTraceStore
from src.killswitch.kill_switch import get_kill_switch, get_orchestrator
from src.guardrails.guardrails import (
    get_guardrail_orchestrator,
    scan_input,
    scan_output,
)
from src.ebpf.boundary_tracer import create_boundary_monitor


class ADRServer:
    def __init__(self, port: int = 8080):
        self.port = port
        self.app = web.Application()
        self._setup_routes()
        self.trace_store: Optional[AgenticTraceStore] = None
        self.kill_switch = get_kill_switch()
        self.guardrails = get_guardrail_orchestrator()
        self.monitor = None

    def _setup_routes(self):
        self.app.router.add_get("/health", self.health)
        self.app.router.add_post("/v1/initialize", self.initialize)
        self.app.router.add_post("/v1/spans", self.ingest_spans)
        self.app.router.add_get("/v1/traces/{trace_id}", self.get_trace)
        self.app.router.add_get("/v1/sessions/{session_id}", self.get_session)
        self.app.router.add_post("/v1/scan/input", self.scan_input)
        self.app.router.add_post("/v1/scan/output", self.scan_output)
        self.app.router.add_get("/v1/threats", self.get_threats)
        self.app.router.add_post("/v1/killswitch/trigger", self.trigger_killswitch)
        self.app.router.add_post("/v1/killswitch/release", self.release_killswitch)
        self.app.router.add_get("/v1/contained", self.get_contained_agents)
        self.app.router.add_get("/v1/agents/top", self.get_top_agents)
        self.app.router.add_get("/v1/events", self.get_security_events)

    async def health(self, request):
        return web.json_response(
            {
                "status": "healthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": "1.0.0",
                "components": {
                    "collector": "active",
                    "trace_store": "active" if self.trace_store else "disabled",
                    "kill_switch": "active",
                    "guardrails": "active",
                },
            }
        )

    async def initialize(self, request):
        try:
            data = await request.json()
            framework = data.get("framework", "unknown")
            endpoint = data.get("otel_endpoint", "http://localhost:4317")
            user_id = data.get("user_id", "anonymous")

            init_otel(framework, endpoint, user_id)

            if data.get("clickhouse_host"):
                self.trace_store = AgenticTraceStore(
                    host=data["clickhouse_host"],
                    port=data.get("clickhouse_port", 8123),
                    user=data.get("clickhouse_user", "default"),
                    password=data.get("clickhouse_password", ""),
                )

            if data.get("start_monitoring", False):
                self.monitor = create_boundary_monitor(data.get("monitor_config"))
                self.monitor.start_monitoring()

            return web.json_response({"status": "initialized", "framework": framework})
        except Exception as e:
            return web.json_response({"status": "error", "message": str(e)}, status=500)

    async def ingest_spans(self, request):
        try:
            data = await request.json()
            spans = data.get("spans", [])

            collector = get_collector()
            for span_data in spans:
                span = collector.start_span(
                    name=span_data.get("name", "unknown"),
                    kind=span_data.get("kind", "agent"),
                    agent_id=span_data.get("agent_id"),
                    attributes=span_data.get("attributes", {}),
                )
                await collector.end_span(
                    span,
                    status=span_data.get("status", "OK"),
                    attributes=span_data.get("attributes", {}),
                )

            if self.trace_store:
                for span_data in spans:
                    self.trace_store.insert_span(span_data)

            return web.json_response({"status": "ok", "spans_ingested": len(spans)})
        except Exception as e:
            return web.json_response({"status": "error", "message": str(e)}, status=500)

    async def get_trace(self, request):
        trace_id = request.match_info["trace_id"]
        if not self.trace_store:
            return web.json_response(
                {"status": "error", "message": "Trace store not initialized"},
                status=500,
            )

        trace = self.trace_store.get_trace(trace_id)
        return web.json_response({"trace_id": trace_id, "spans": trace})

    async def get_session(self, request):
        session_id = request.match_info["session_id"]
        if not self.trace_store:
            return web.json_response(
                {"status": "error", "message": "Trace store not initialized"},
                status=500,
            )

        summary = self.trace_store.get_session_summary(session_id)
        events = self.trace_store.get_session_events(session_id)
        return web.json_response(
            {"session_id": session_id, "summary": summary, "security_events": events}
        )

    async def scan_input(self, request):
        try:
            data = await request.json()
            text = data.get("text", "")
            context = data.get("context")

            result = scan_input(text, context)
            return web.json_response(asdict(result))
        except Exception as e:
            return web.json_response({"status": "error", "message": str(e)}, status=500)

    async def scan_output(self, request):
        try:
            data = await request.json()
            text = data.get("text", "")
            agent_id = data.get("agent_id")

            result = scan_output(text, agent_id)
            return web.json_response(asdict(result))
        except Exception as e:
            return web.json_response({"status": "error", "message": str(e)}, status=500)

    async def get_threats(self, request):
        if not self.trace_store:
            return web.json_response(
                {"status": "error", "message": "Trace store not initialized"},
                status=500,
            )

        min_level = int(request.query.get("min_level", 3))
        threats = self.trace_store.query_threats(min_threat_level=min_level)
        return web.json_response({"threats": threats, "count": len(threats)})

    async def trigger_killswitch(self, request):
        try:
            data = await request.json()
            agent_id = data["agent_id"]
            session_id = data["session_id"]
            reason = data["reason"]
            threat_score = data.get("threat_score", 0.8)
            container_id = data.get("container_id", "unknown")

            event = self.kill_switch.trigger(
                agent_id=agent_id,
                session_id=session_id,
                reason=reason,
                threat_score=threat_score,
                container_id=container_id,
            )
            return web.json_response({"status": "triggered", "event": asdict(event)})
        except Exception as e:
            return web.json_response({"status": "error", "message": str(e)}, status=500)

    async def release_killswitch(self, request):
        try:
            data = await request.json()
            agent_id = data["agent_id"]

            success = self.kill_switch.release(agent_id)
            return web.json_response(
                {"status": "released" if success else "failed", "agent_id": agent_id}
            )
        except Exception as e:
            return web.json_response({"status": "error", "message": str(e)}, status=500)

    async def get_contained_agents(self, request):
        contained = self.kill_switch.get_contained_agents()
        return web.json_response(
            {
                "contained_agents": [asdict(e) for e in contained],
                "count": len(contained),
            }
        )

    async def get_top_agents(self, request):
        if not self.trace_store:
            return web.json_response(
                {"status": "error", "message": "Trace store not initialized"},
                status=500,
            )

        limit = int(request.query.get("limit", 10))
        top_agents = self.trace_store.get_top_agents(limit)
        return web.json_response({"top_agents": top_agents})

    async def get_security_events(self, request):
        if not self.trace_store:
            return web.json_response(
                {"status": "error", "message": "Trace store not initialized"},
                status=500,
            )

        session_id = request.query.get("session_id")
        if session_id:
            events = self.trace_store.get_session_events(session_id)
        else:
            events = self.trace_store.query_threats(min_threat_level=3)

        return web.json_response({"events": events, "count": len(events)})

    async def start(self):
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", self.port)
        await site.start()
        print(f"ADR Server running on port {self.port}")
        await asyncio.sleep(float("inf"))


async def main():
    server = ADRServer(port=8080)
    await server.start()


if __name__ == "__main__":
    asyncio.run(main())
