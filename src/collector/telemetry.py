#!/usr/bin/env python3
import os
import time
import json
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum
import asyncio
from datetime import datetime, timezone

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider, SpanProcessor
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.sdk.resources import (
        Resource,
        SERVICE_NAME,
        SERVICE_VERSION,
        SERVICE_NAMESPACE,
    )
    from opentelemetry.trace import SpanKind, Status, StatusCode
    from opentelemetry.trace.propagation.tracecontext import (
        TraceContextTextMapPropagator,
    )
    from opentelemetry.context import Context
    from opentelemetry.propagate import set_global_textmap

    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    trace = None


class AgentFramework(Enum):
    CREWAI = 1
    AUTOGEN = 2
    LANGCHAIN = 3
    LLAMAINDEX = 4
    AGNO = 5
    CUSTOM = 99


class SpanKind(Enum):
    AGENT = "agent"
    TOOL = "tool"
    LLM = "llm"
    RETRIEVAL = "retrieval"
    ACTION = "action"


class ThreatLevel(Enum):
    SAFE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


GEN_AI_SYSTEMS = {
    "openai": "openai",
    "anthropic": "anthropic",
    "google": "vertexai",
    "aws": "bedrock",
    "azure": "azure-openai",
    "ollama": "ollama",
    "crewai": "crewai",
    "autogen": "autogen",
    "langchain": "langchain",
}


class TelemetrySpan:
    __slots__ = [
        "trace_id",
        "span_id",
        "parent_span_id",
        "framework",
        "agent_id",
        "session_id",
        "user_id",
        "kind",
        "name",
        "start_time",
        "end_time",
        "duration_ms",
        "attributes",
        "status",
        "error_message",
        "_otel_span",
    ]

    def __init__(
        self,
        trace_id: str,
        span_id: str,
        parent_span_id: Optional[str],
        framework: str,
        agent_id: str,
        session_id: str,
        user_id: Optional[str],
        kind: str,
        name: str,
        start_time: float,
        otel_span: Optional[Any] = None,
    ):
        self.trace_id = trace_id
        self.span_id = span_id
        self.parent_span_id = parent_span_id
        self.framework = framework
        self.agent_id = agent_id
        self.session_id = session_id
        self.user_id = user_id
        self.kind = kind
        self.name = name
        self.start_time = start_time
        self.end_time: Optional[float] = None
        self.duration_ms: Optional[float] = None
        self.attributes: Dict[str, Any] = {}
        self.status = "OK"
        self.error_message: Optional[str] = None
        self._otel_span = otel_span

    def complete(self):
        self.end_time = time.time()
        self.duration_ms = (self.end_time - self.start_time) * 1000


class AgenticTelemetryCollector:
    def __init__(
        self,
        service_name: str = "agentic-adr",
        otel_endpoint: str = "http://localhost:4317",
        export_interval_ms: int = 5000,
    ):
        self.service_name = service_name
        self.otel_endpoint = otel_endpoint
        self.export_interval_ms = export_interval_ms
        self._tracer: Optional[Any] = None
        self._provider: Optional[Any] = None
        self.spans: List[TelemetrySpan] = []
        self._pending_spans: Dict[str, TelemetrySpan] = {}
        self._lock = asyncio.Lock()
        self._batch_size = 100
        self._flush_interval = 5.0
        self._last_flush = time.time()
        self._user_id: Optional[str] = None
        self._session_id: str = self._generate_id()
        self._framework: Optional[str] = None

        if OTEL_AVAILABLE:
            self._setup_otel()

    def _setup_otel(self):
        resource = Resource.create(
            {
                SERVICE_NAME: self.service_name,
                SERVICE_VERSION: "1.0.0",
                "deployment.environment": os.environ.get("ENV", "production"),
                "session.id": self._session_id,
            }
        )

        self._provider = TracerProvider(resource=resource)

        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )

            otlp_exporter = OTLPSpanExporter(endpoint=self.otel_endpoint, insecure=True)
            self._provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
        except Exception:
            pass

        self._provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
        trace.set_tracer_provider(self._provider)
        self._tracer = trace.get_tracer(__name__, "1.0.0")

        set_global_textmap(TraceContextTextMapPropagator())

    def _generate_id(self) -> str:
        import uuid

        return uuid.uuid4().hex[:16]

    def set_context(
        self,
        user_id: str,
        session_id: Optional[str] = None,
        framework: Optional[str] = None,
    ):
        self._user_id = user_id
        if session_id:
            self._session_id = session_id
        self._framework = framework

    def _map_kind_to_otel(self, kind: str) -> int:
        mapping = {
            "agent": 1,
            "tool": 2,
            "llm": 3,
            "retrieval": 4,
            "action": 5,
        }
        return mapping.get(kind.lower(), 1)

    def start_span(
        self,
        name: str,
        kind: SpanKind = SpanKind.AGENT,
        agent_id: Optional[str] = None,
        parent_span_id: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> TelemetrySpan:
        import uuid

        trace_id = uuid.uuid4().hex[:32]
        span_id = uuid.uuid4().hex[:16]
        framework = self._framework or "unknown"
        agent_id = agent_id or framework

        span_attributes = attributes or {}
        span_attributes.update(
            {
                "framework": framework,
                "agent.id": agent_id,
                "session.id": self._session_id,
            }
        )

        otel_span = None
        if OTEL_AVAILABLE and self._tracer:
            otel_kind = self._map_kind_to_otel(
                kind.value if isinstance(kind, Enum) else kind
            )
            otel_span = self._tracer.start_span(
                name=name, kind=otel_kind, attributes=span_attributes
            )

        span = TelemetrySpan(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            framework=framework,
            agent_id=agent_id,
            session_id=self._session_id,
            user_id=self._user_id,
            kind=kind.value if isinstance(kind, Enum) else kind,
            name=name,
            start_time=time.time(),
            otel_span=otel_span,
        )

        self._pending_spans[span_id] = span
        return span

    async def end_span(
        self,
        span: TelemetrySpan,
        status: str = "OK",
        error_message: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ):
        span.complete()
        span.status = status
        span.error_message = error_message
        if attributes:
            span.attributes.update(attributes)

        if OTEL_AVAILABLE and span._otel_span:
            if status != "OK":
                span._otel_span.set_status(
                    Status(StatusCode.ERROR, error_message or "Error")
                )
            for key, value in span.attributes.items():
                span._otel_span.set_attribute(key, value)
            span._otel_span.end()

        async with self._lock:
            if span.span_id in self._pending_spans:
                del self._pending_spans[span.span_id]
            self.spans.append(span)

            if (
                len(self.spans) >= self._batch_size
                or (time.time() - self._last_flush) > self._flush_interval
            ):
                await self._flush()

    async def _flush(self):
        if not self.spans:
            return

        payload = []
        for span in self.spans:
            span_data = {
                "trace_id": span.trace_id,
                "span_id": span.span_id,
                "parent_span_id": span.parent_span_id,
                "framework": span.framework,
                "agent_id": span.agent_id,
                "session_id": span.session_id,
                "user_id": span.user_id,
                "kind": span.kind,
                "name": span.name,
                "start_time": span.start_time,
                "end_time": span.end_time,
                "duration_ms": span.duration_ms,
                "status": span.status,
                "error_message": span.error_message,
                "attributes": span.attributes,
            }

            if OTEL_AVAILABLE and "gen_ai" not in span.attributes:
                span_data["attributes"]["gen_ai.system"] = GEN_AI_SYSTEMS.get(
                    span.framework, span.framework
                )

            payload.append(span_data)

        self.spans.clear()
        self._last_flush = time.time()

        await self._send_to_otel(payload)

    async def _send_to_otel(self, spans: List[Dict]):
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                await session.post(
                    self.otel_endpoint + "/v1/traces",
                    json={"resourceSpans": [{"spans": spans}]},
                    timeout=aiohttp.ClientTimeout(total=5),
                )
        except Exception:
            pass

    async def flush(self):
        async with self._lock:
            await self._flush()

    def record_llm_usage(
        self,
        span: TelemetrySpan,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        total_tokens: int,
    ):
        span.attributes.update(
            {
                "gen_ai.request.model": model,
                "gen_ai.usage.input_tokens": prompt_tokens,
                "gen_ai.usage.output_tokens": completion_tokens,
                "gen_ai.usage.total_tokens": total_tokens,
            }
        )

    def record_gen_ai_request(
        self,
        span: TelemetrySpan,
        model: str,
        provider: str,
        messages: List[Dict[str, Any]],
        temperature: Optional[float] = None,
    ):
        span.attributes.update(
            {
                "gen_ai.request.model": model,
                "gen_ai.system": provider,
                "gen_ai.prompt.messages": messages,
            }
        )
        if temperature is not None:
            span.attributes["gen_ai.request.temperature"] = temperature

    def record_gen_ai_response(
        self,
        span: TelemetrySpan,
        model: str,
        response_id: str,
        content: str,
        finish_reason: str,
    ):
        span.attributes.update(
            {
                "gen_ai.response.id": response_id,
                "gen_ai.response.model": model,
                "gen_ai.completion.content": content,
                "gen_ai.completion.finish_reason": finish_reason,
            }
        )


class FrameworkInstrumentor:
    def __init__(self, collector: AgenticTelemetryCollector):
        self.collector = collector
        self._instrumented = {}
        self._patched_methods = {}

    def instrument_crewai(self):
        try:
            from crewai import Agent, Crew, Task
            import crewai.agent

            original_execute = Agent.execute_task

            async def instrumented_execute(self, task, context):
                role = getattr(self, "role", "agent")
                span = self.collector.start_span(
                    name="crewai.agent." + role,
                    kind=SpanKind.AGENT,
                    agent_id=getattr(self, "role", "agent"),
                    attributes={
                        "agent.role": getattr(self, "role", "unknown"),
                        "agent.goal": str(getattr(self, "goal", ""))[:200],
                        "gen_ai.system": "crewai",
                    },
                )
                try:
                    result = await original_execute(self, task, context)
                    self.collector.record_llm_usage(span, "unknown", 0, 0, 0)
                    await self.collector.end_span(
                        span, "OK", attributes={"output_tokens": str(result)[:500]}
                    )
                    return result
                except Exception as e:
                    await self.collector.end_span(span, "ERROR", str(e))
                    raise

            Agent.execute_task = instrumented_execute
            self._instrumented["crewai"] = True
        except ImportError:
            pass

    def instrument_autogen(self):
        try:
            import autogen

            original_reply = autogen.ConversableAgent.generate_reply

            async def instrumented_reply(self, messages, sender, **kwargs):
                agent_name = getattr(self, "name", "agent")
                span = self.collector.start_span(
                    name="autogen.agent." + agent_name,
                    kind=SpanKind.AGENT,
                    agent_id=agent_name,
                    attributes={
                        "agent.name": agent_name,
                        "message_count": len(messages),
                        "gen_ai.system": "autogen",
                    },
                )
                try:
                    reply = await original_reply(self, messages, sender, **kwargs)
                    await self.collector.end_span(span, "OK")
                    return reply
                except Exception as e:
                    await self.collector.end_span(span, "ERROR", str(e))
                    raise

            autogen.ConversableAgent.generate_reply = instrumented_reply
            self._instrumented["autogen"] = True
        except ImportError:
            pass

    def instrument_langchain(self):
        try:
            from langchain_core.callbacks import AsyncCallbackHandler

            class OtelCallbackHandler(AsyncCallbackHandler):
                def __init__(self, collector):
                    self.collector = collector
                    self._current_span = None
                    self._llm_span = None

                async def on_chain_start(self, serialized, inputs, **kwargs):
                    chain_name = (
                        serialized.get("name", "chain")
                        if isinstance(serialized, dict)
                        else str(serialized)
                    )
                    self._current_span = self.collector.start_span(
                        name=f"langchain.{chain_name}",
                        kind=SpanKind.ACTION,
                        attributes={
                            "gen_ai.system": "langchain",
                            "chain.name": chain_name,
                            "input_keys": list(inputs.keys())
                            if isinstance(inputs, dict)
                            else [],
                        },
                    )

                async def on_chain_end(self, outputs, **kwargs):
                    if self._current_span:
                        await self.collector.end_span(self._current_span, "OK")
                        self._current_span = None

                async def on_llm_start(self, serialized, prompts, **kwargs):
                    llm_name = (
                        serialized.get("name", "llm")
                        if isinstance(serialized, dict)
                        else str(serialized)
                    )
                    self._llm_span = self.collector.start_span(
                        name=f"langchain.llm.{llm_name}",
                        kind=SpanKind.LLM,
                        attributes={
                            "gen_ai.system": "langchain",
                            "gen_ai.prompt.messages": prompts,
                        },
                    )

                async def on_llm_end(self, response, **kwargs):
                    if self._llm_span:
                        if hasattr(response, "usage"):
                            self.collector.record_llm_usage(
                                self._llm_span,
                                getattr(response, "model_name", "unknown"),
                                getattr(response.usage, "prompt_tokens", 0),
                                getattr(response.usage, "completion_tokens", 0),
                                getattr(response.usage, "total_tokens", 0),
                            )
                        await self.collector.end_span(self._llm_span, "OK")
                        self._llm_span = None

                async def on_tool_start(self, serialized, inputs, **kwargs):
                    tool_name = (
                        serialized.get("name", "tool")
                        if isinstance(serialized, dict)
                        else str(serialized)
                    )
                    span = self.collector.start_span(
                        name=f"langchain.tool.{tool_name}",
                        kind=SpanKind.TOOL,
                        attributes={
                            "gen_ai.system": "langchain",
                            "tool.name": tool_name,
                        },
                    )
                    self._current_span = span

                async def on_tool_end(self, outputs, **kwargs):
                    if self._current_span:
                        await self.collector.end_span(self._current_span, "OK")
                        self._current_span = None

            self._instrumented["langchain"] = OtelCallbackHandler(self.collector)
        except ImportError:
            pass

    def instrument_llamaindex(self):
        try:
            from llama_index.core.callbacks import CallbackManager

            class OtelLlamaIndexHandler:
                def __init__(self, collector):
                    self.collector = collector

                def on_retrieve_start(self, query):
                    span = self.collector.start_span(
                        name="llamaindex.retrieve",
                        kind=SpanKind.RETRIEVAL,
                        attributes={
                            "gen_ai.system": "llamaindex",
                            "query": str(query)[:200],
                        },
                    )
                    self._current_span = span

                def on_retrieve_end(self, nodes):
                    if hasattr(self, "_current_span"):
                        self.collector.end_span(
                            self._current_span,
                            "OK",
                            attributes={"nodes_retrieved": len(nodes)},
                        )
                        self._current_span = None

            self._instrumented["llamaindex"] = OtelLlamaIndexHandler(self.collector)
        except ImportError:
            pass

    def get_instrumentor(self, framework: str):
        return self._instrumented.get(framework)


collector_global = AgenticTelemetryCollector()
instrumentor_global = FrameworkInstrumentor(collector_global)


def get_collector() -> AgenticTelemetryCollector:
    return collector_global


def get_instrumentor() -> FrameworkInstrumentor:
    return instrumentor_global


def init_otel(
    framework: str,
    endpoint: str = "http://localhost:4317",
    user_id: str = "anonymous",
    session_id: Optional[str] = None,
    service_name: str = "agentic-adr",
):
    collector_global.otel_endpoint = endpoint
    collector_global.service_name = service_name
    collector_global.set_context(user_id, session_id, framework)

    inst = get_instrumentor()
    if framework.lower() == "crewai":
        inst.instrument_crewai()
    elif framework.lower() == "autogen":
        inst.instrument_autogen()
    elif framework.lower() == "langchain":
        inst.instrument_langchain()
    elif framework.lower() == "llamaindex":
        inst.instrument_llamaindex()

    return collector_global
