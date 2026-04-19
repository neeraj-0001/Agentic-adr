#!/usr/bin/env python3
import clickhouse_connect
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import json
import hashlib
import time


class GuardrailResult:
    def __init__(
        self, passed: bool, guardrail_type: str, severity: str, description: str
    ):
        self.passed = passed
        self.guardrail_type = guardrail_type
        self.severity = severity
        self.description = description


class AgenticTraceStore:
    def __init__(
        self,
        host: str = "localhost",
        port: int = 8123,
        database: str = "agentic_adr",
        user: str = "default",
        password: str = "",
    ):
        self.client = clickhouse_connect.get_client(
            host=host, port=port, database=database, username=user, password=password
        )
        self.database = database
        self._ensure_schema()
        self._create_materialized_views()

    def _ensure_schema(self):
        self.client.command("CREATE DATABASE IF NOT EXISTS " + self.database)

        self.client.command(
            """
            CREATE TABLE IF NOT EXISTS """
            + self.database
            + """.observations (
                sort_key String,
                trace_id String,
                span_id String,
                parent_span_id String,
                framework String,
                agent_id String,
                session_id String,
                user_id String,
                kind String,
                name String,
                start_time DateTime64(6),
                end_time DateTime64(6),
                duration_ms Float64,
                status String,
                error_message String,
                attributes JSON,
                threat_level UInt8,
                gen_ai_system String DEFAULT '',
                gen_ai_request_model String DEFAULT '',
                gen_ai_usage_input_tokens UInt64 DEFAULT 0,
                gen_ai_usage_output_tokens UInt64 DEFAULT 0,
                created_at DateTime DEFAULT now()
            ) ENGINE = ReplacingMergeTree(sort_key)
            ORDER BY (trace_id, span_id, start_time)
            PARTITION BY toYYYYMM(start_time)
            TTL created_at + INTERVAL 30 DAY
            SETTINGS index_granularity = 8192
        """
        )

        self.client.command(
            """
            CREATE TABLE IF NOT EXISTS """
            + self.database
            + """.security_events (
                event_id String,
                trace_id String,
                span_id String,
                event_type String,
                severity String,
                source String,
                description String,
                evidence JSON,
                mitigations JSON,
                created_at DateTime DEFAULT now(),
                version UInt8 DEFAULT 1
            ) ENGINE = ReplacingMergeTree(sort_key, version)
            ORDER BY (event_id, created_at)
            PARTITION BY toYYYYMM(created_at)
            TTL created_at + INTERVAL 90 DAY
        """
        )

        self.client.command(
            """
            CREATE TABLE IF NOT EXISTS """
            + self.database
            + """.agent_sessions (
                session_id String,
                user_id String,
                framework String,
                start_time DateTime64(6),
                end_time DateTime64(6),
                total_spans UInt64 DEFAULT 0,
                total_cost_usd Float64 DEFAULT 0,
                total_tokens UInt64 DEFAULT 0,
                threat_events UInt8 DEFAULT 0,
                status String DEFAULT 'active',
                metadata JSON,
                version UInt8 DEFAULT 1
            ) ENGINE = ReplacingMergeTree(sort_key, version)
            ORDER BY (session_id, start_time)
            TTL start_time + INTERVAL 60 DAY
        """
        )

        self.client.command(
            """
            CREATE TABLE IF NOT EXISTS """
            + self.database
            + """.kill_switch_events (
                event_id String,
                agent_id String,
                session_id String,
                action String,
                threat_score Float64,
                container_id String,
                detection_time_ms Float64,
                containment_time_ms Float64,
                total_time_ms Float64,
                status String,
                created_at DateTime DEFAULT now()
            ) ENGINE = ReplacingMergeTree(event_id)
            ORDER BY (agent_id, created_at)
            TTL created_at + INTERVAL 30 DAY
        """
        )

        self.client.command(
            """
            CREATE TABLE IF NOT EXISTS """
            + self.database
            + """.boundary_events (
                event_id String,
                event_type String,
                timestamp DateTime64(6),
                pid UInt32,
                ppid UInt32,
                uid UInt32,
                comm String,
                threat_score Float64,
                args JSON,
                metadata JSON
            ) ENGINE = MergeTree()
            ORDER BY (event_type, timestamp)
            PARTITION BY toYYYYMM(timestamp)
            TTL timestamp + INTERVAL 7 DAY
        """
        )

        self.client.command(
            """
            CREATE TABLE IF NOT EXISTS """
            + self.database
            + """.guardrail_results (
                result_id String,
                guardrail_type String,
                passed Boolean,
                severity String,
                description String,
                agent_id String DEFAULT '',
                session_id String DEFAULT '',
                created_at DateTime DEFAULT now()
            ) ENGINE = ReplacingMergeTree(result_id)
            ORDER BY (guardrail_type, created_at)
            TTL created_at + INTERVAL 30 DAY
        """
        )

    def _create_materialized_views(self):
        try:
            self.client.command(
                """
                CREATE MATERIALIZED VIEW IF NOT EXISTS """
                + self.database
                + """.mv_session_stats
                ENGINE = SummingMergeTree()
                ORDER BY (session_id, framework)
                AS SELECT
                    session_id,
                    framework,
                    count() as span_count,
                    sum(duration_ms) / 1000 as total_duration_sec,
                    avg(duration_ms) as avg_duration_ms,
                    sumIf(1, status = 'ERROR') as error_count,
                    max(threat_level) as max_threat_level,
                    sum(gen_ai_usage_input_tokens) as total_input_tokens,
                    sum(gen_ai_usage_output_tokens) as total_output_tokens,
                    toStartOfHour(start_time) as hour
                FROM """
                + self.database
                + """.observations
                GROUP BY session_id, framework, hour
            """
            )
        except Exception:
            pass

        try:
            self.client.command(
                """
                CREATE MATERIALIZED VIEW IF NOT EXISTS """
                + self.database
                + """.mv_agent_stats
                ENGINE = SummingMergeTree()
                ORDER BY (agent_id, framework)
                AS SELECT
                    agent_id,
                    framework,
                    count() as total_spans,
                    sumIf(1, status = 'ERROR') as error_count,
                    avg(duration_ms) as avg_latency_ms,
                    max(threat_level) as max_threat_level,
                    countIf(threat_level >= 3) as high_threat_count,
                    toStartOfDay(start_time) as day
                FROM """
                + self.database
                + """.observations
                GROUP BY agent_id, framework, day
            """
            )
        except Exception:
            pass

        try:
            self.client.command(
                """
                CREATE MATERIALIZED VIEW IF NOT EXISTS """
                + self.database
                + """.mv_framework_usage
                ENGINE = SummingMergeTree()
                ORDER BY (framework, day)
                AS SELECT
                    framework,
                    toStartOfDay(start_time) as day,
                    count() as total_calls,
                    avg(duration_ms) as avg_latency_ms,
                    sum(duration_ms) as total_duration_ms,
                    uniqExact(session_id) as unique_sessions,
                    sum(gen_ai_usage_input_tokens) as total_input_tokens,
                    sum(gen_ai_usage_output_tokens) as total_output_tokens
                FROM """
                + self.database
                + """.observations
                WHERE kind = 'llm'
                GROUP BY framework, day
            """
            )
        except Exception:
            pass

        try:
            self.client.command(
                """
                CREATE MATERIALIZED VIEW IF NOT EXISTS """
                + self.database
                + """.mv_threat_timeline
                ENGINE = SummingMergeTree()
                ORDER BY (threat_level, hour)
                AS SELECT
                    threat_level,
                    toStartOfHour(start_time) as hour,
                    count() as event_count,
                    uniqExact(agent_id) as unique_agents,
                    framework
                FROM """
                + self.database
                + """.observations
                WHERE threat_level >= 2
                GROUP BY threat_level, hour, framework
            """
            )
        except Exception:
            pass

    def insert_span(self, span_data: Dict[str, Any]):
        trace_id = span_data.get("trace_id", "")
        span_id = span_data.get("span_id", "")
        sort_key = trace_id + "_" + span_id
        threat_level = self._calculate_threat_level(span_data)

        attrs = span_data.get("attributes", {})
        gen_ai_system = attrs.get("gen_ai.system", "")
        gen_ai_request_model = attrs.get("gen_ai.request.model", "")
        gen_ai_usage_input = attrs.get("gen_ai.usage.input_tokens", 0)
        gen_ai_usage_output = attrs.get("gen_ai.usage.output_tokens", 0)

        self.client.insert(
            self.database,
            table="observations",
            data=[
                {
                    "sort_key": sort_key,
                    "trace_id": trace_id,
                    "span_id": span_id,
                    "parent_span_id": span_data.get("parent_span_id", ""),
                    "framework": span_data.get("framework", "unknown"),
                    "agent_id": span_data.get("agent_id", "unknown"),
                    "session_id": span_data.get("session_id", ""),
                    "user_id": span_data.get("user_id", "anonymous"),
                    "kind": span_data.get("kind", "agent"),
                    "name": span_data.get("name", ""),
                    "start_time": datetime.fromtimestamp(
                        span_data.get("start_time", 0), tz=timezone.utc
                    ),
                    "end_time": datetime.fromtimestamp(
                        span_data.get("end_time", 0), tz=timezone.utc
                    )
                    if span_data.get("end_time")
                    else None,
                    "duration_ms": span_data.get("duration_ms", 0),
                    "status": span_data.get("status", "OK"),
                    "error_message": span_data.get("error_message", ""),
                    "attributes": json.dumps(attrs),
                    "threat_level": threat_level,
                    "gen_ai_system": gen_ai_system,
                    "gen_ai_request_model": gen_ai_request_model,
                    "gen_ai_usage_input_tokens": gen_ai_usage_input,
                    "gen_ai_usage_output_tokens": gen_ai_usage_output,
                }
            ],
        )

    def _calculate_threat_level(self, span_data: Dict) -> int:
        threat = 0
        attrs = span_data.get("attributes", {})
        attrs_str = str(attrs).lower()

        if "prompt_injection" in attrs_str:
            threat = 4
        elif "exfiltration" in attrs_str:
            threat = 4
        elif "unauthorized_tool" in attrs_str:
            threat = 3
        elif span_data.get("status") == "ERROR":
            threat = 2
        elif span_data.get("duration_ms", 0) > 30000:
            threat = 1

        return threat

    def insert_security_event(self, event: Dict[str, Any]):
        trace_id = event.get("trace_id", "")
        event_type = event.get("event_type", "")
        created_at = str(event.get("created_at", ""))
        event_id = hashlib.sha256(
            (trace_id + event_type + created_at).encode()
        ).hexdigest()[:32]

        self.client.insert(
            self.database,
            table="security_events",
            data=[
                {
                    "event_id": event_id,
                    "trace_id": trace_id,
                    "span_id": event.get("span_id", ""),
                    "event_type": event_type,
                    "severity": event.get("severity", "LOW"),
                    "source": event.get("source", "system"),
                    "description": event.get("description", ""),
                    "evidence": json.dumps(event.get("evidence", {})),
                    "mitigations": json.dumps(event.get("mitigations", [])),
                }
            ],
        )

    def insert_kill_switch_event(self, event: Dict[str, Any]):
        self.client.insert(
            self.database,
            table="kill_switch_events",
            data=[
                {
                    "event_id": event.get("event_id", ""),
                    "agent_id": event.get("agent_id", ""),
                    "session_id": event.get("session_id", ""),
                    "action": event.get("action", ""),
                    "threat_score": event.get("threat_score", 0.0),
                    "container_id": event.get("container_id", ""),
                    "detection_time_ms": event.get("detection_time_ms", 0.0),
                    "containment_time_ms": event.get("containment_time_ms", 0.0),
                    "total_time_ms": event.get("total_time_ms", 0.0),
                    "status": event.get("status", ""),
                }
            ],
        )

    def insert_guardrail_result(self, result: GuardrailResult):
        result_id = hashlib.sha256(
            (
                str(result.guardrail_type) + str(result.description) + str(time.time())
            ).encode()
        ).hexdigest()[:32]
        self.client.insert(
            self.database,
            table="guardrail_results",
            data=[
                {
                    "result_id": result_id,
                    "guardrail_type": result.guardrail_type,
                    "passed": result.passed,
                    "severity": result.severity,
                    "description": result.description,
                }
            ],
        )

    def get_trace(self, trace_id: str) -> List[Dict[str, Any]]:
        result = self.client.query(
            """
            SELECT * FROM """
            + self.database
            + """.observations
            WHERE trace_id = \uff1f"""
            + trace_id
            + """\uff1f
            ORDER BY start_time
        """
        )
        return [dict(row) for row in result.result_rows]

    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        result = self.client.query(
            """
            SELECT
                session_id,
                user_id,
                framework,
                min(start_time) as start_time,
                max(end_time) as end_time,
                count() as total_spans,
                sumIf(1, status='ERROR') as error_count,
                avg(duration_ms) as avg_duration_ms,
                max(threat_level) as max_threat_level
            FROM """
            + self.database
            + """.observations
            WHERE session_id = \uff1f"""
            + session_id
            + """\uff1f
            GROUP BY session_id, user_id, framework
        """
        )
        rows = result.result_rows
        return dict(rows[0]) if rows else {}

    def query_threats(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        min_threat_level: int = 3,
    ) -> List[Dict]:
        start_str = (
            start_time.strftime("%Y-%m-%d %H:%M:%S") if start_time else "1970-01-01"
        )
        end_str = end_time.strftime("%Y-%m-%d %H:%M:%S") if end_time else "2100-01-01"

        result = self.client.query(
            """
            SELECT * FROM """
            + self.database
            + """.observations
            WHERE threat_level >= """
            + str(min_threat_level)
            + """
              AND start_time BETWEEN \uff1f"""
            + start_str
            + """\uff1f AND \uff1f"""
            + end_str
            + """\uff1f
            ORDER BY start_time DESC
            LIMIT 1000
        """
        )
        return [dict(row) for row in result.result_rows]

    def get_cost_analysis(self, session_id: str) -> Dict[str, Any]:
        result = self.client.query(
            """
            SELECT
                framework,
                count() as span_count,
                sum(duration_ms) / 1000 as total_seconds,
                avg(duration_ms) as avg_latency_ms,
                sum(gen_ai_usage_input_tokens) as total_input_tokens,
                sum(gen_ai_usage_output_tokens) as total_output_tokens
            FROM """
            + self.database
            + """.observations
            WHERE session_id = \uff1f"""
            + session_id
            + """\uff1f
              AND kind = 'llm'
            GROUP BY framework
        """
        )
        return {"cost_breakdown": [dict(row) for row in result.result_rows]}

    def get_top_agents(self, limit: int = 10) -> List[Dict]:
        result = self.client.query(
            """
            SELECT
                agent_id,
                framework,
                count() as total_spans,
                sumIf(1, status='ERROR') as errors,
                avg(duration_ms) as avg_duration_ms
            FROM """
            + self.database
            + """.observations
            WHERE start_time > now() - INTERVAL 24 HOUR
            GROUP BY agent_id, framework
            ORDER BY total_spans DESC
            LIMIT """
            + str(limit)
            + """
        """
        )
        return [dict(row) for row in result.result_rows]

    def get_session_events(self, session_id: str) -> List[Dict[str, Any]]:
        result = self.client.query(
            """
            SELECT * FROM """
            + self.database
            + """.security_events
            WHERE trace_id IN (
                SELECT DISTINCT trace_id FROM """
            + self.database
            + """.observations
                WHERE session_id = \uff1f"""
            + session_id
            + """\uff1f
            )
            ORDER BY created_at DESC
        """
        )
        return [dict(row) for row in result.result_rows]

    def get_session_stats_mv(self, session_id: str) -> Dict[str, Any]:
        result = self.client.query(
            """
            SELECT * FROM """
            + self.database
            + """.mv_session_stats
            WHERE session_id = \uff1f"""
            + session_id
            + """\uff1f
            ORDER BY hour DESC
        """
        )
        return {"stats": [dict(row) for row in result.result_rows]}

    def get_agent_stats_mv(self, agent_id: str) -> Dict[str, Any]:
        result = self.client.query(
            """
            SELECT * FROM """
            + self.database
            + """.mv_agent_stats
            WHERE agent_id = \uff1f"""
            + agent_id
            + """\uff1f
            ORDER BY day DESC
        """
        )
        return {"stats": [dict(row) for row in result.result_rows]}

    def get_framework_usage_mv(self, framework: str, days: int = 7) -> Dict[str, Any]:
        result = self.client.query(
            """
            SELECT * FROM """
            + self.database
            + """.mv_framework_usage
            WHERE framework = \uff1f"""
            + framework
            + """\uff1f
              AND day > now() - INTERVAL """
            + str(days)
            + """ DAY
            ORDER BY day DESC
        """
        )
        return {"usage": [dict(row) for row in result.result_rows]}

    def get_threat_timeline_mv(self, min_threat_level: int = 3) -> List[Dict]:
        result = self.client.query(
            """
            SELECT * FROM """
            + self.database
            + """.mv_threat_timeline
            WHERE threat_level >= """
            + str(min_threat_level)
            + """
              AND hour > now() - INTERVAL 24 HOUR
            ORDER BY hour DESC
        """
        )
        return [dict(row) for row in result.result_rows]

    def get_kill_switch_metrics(self) -> Dict[str, Any]:
        result = self.client.query(
            """
            SELECT
                count() as total_events,
                avg(total_time_ms) as avg_containment_time_ms,
                max(total_time_ms) as max_containment_time_ms,
                countIf(total_time_ms > 500) as budget_exceeded_count,
                countIf(status = 'terminated') as terminations,
                countIf(status = 'quarantined') as quarantines
            FROM """
            + self.database
            + """.kill_switch_events
            WHERE created_at > now() - INTERVAL 24 HOUR
        """
        )
        rows = result.result_rows
        return dict(rows[0]) if rows else {}
