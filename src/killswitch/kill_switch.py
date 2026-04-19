#!/usr/bin/env python3
import time
import threading
import json
import subprocess
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
import asyncio


class KillSwitchAction(Enum):
    QUARANTINE = "quarantine"
    CONTAIN = "contain"
    HONEYPOT = "honeypot"
    TERMINATE = "terminate"


class ContainmentState(Enum):
    NORMAL = "normal"
    QUARANTINED = "quarantined"
    HONEYPOT = "honeypot"
    TERMINATED = "terminated"


@dataclass
class KillSwitchEvent:
    event_id: str
    timestamp: float
    agent_id: str
    session_id: str
    trigger_reason: str
    threat_score: float
    action: str
    container_id: str
    status: str = "pending"
    detection_time_ms: float = 0.0
    containment_time_ms: float = 0.0
    total_time_ms: float = 0.0


class TimingBudgetExceeded(Exception):
    pass


class RealTimeKillSwitch:
    def __init__(
        self,
        cilium_namespace: str = "default",
        honeypot_enabled: bool = True,
        auto_contain: bool = True,
        response_time_budget_ms: float = 500.0,
    ):
        self.cilium_namespace = cilium_namespace
        self.honeypot_enabled = honeypot_enabled
        self.auto_contain = auto_contain
        self.response_time_budget_ms = response_time_budget_ms
        self._contained_agents: Dict[str, KillSwitchEvent] = {}
        self._lock = threading.Lock()
        self._handlers: List[Callable[[KillSwitchEvent], None]] = []
        self._timing_violations: List[Dict[str, Any]] = []

    def add_handler(self, handler: Callable[[KillSwitchEvent], None]):
        self._handlers.append(handler)

    def trigger(
        self,
        agent_id: str,
        session_id: str,
        reason: str,
        threat_score: float,
        container_id: str,
    ) -> KillSwitchEvent:
        overall_start = time.perf_counter()
        detection_start = time.perf_counter()

        event_id = "ks_" + str(int(time.time() * 1000)) + "_" + agent_id[:8]

        action = self._determine_action(threat_score)

        detection_time_ms = (time.perf_counter() - detection_start) * 1000

        event = KillSwitchEvent(
            event_id=event_id,
            timestamp=time.time(),
            agent_id=agent_id,
            session_id=session_id,
            trigger_reason=reason,
            threat_score=threat_score,
            action=action,
            container_id=container_id,
        )

        with self._lock:
            self._contained_agents[agent_id] = event

        containment_start = time.perf_counter()
        self._execute_containment(event)
        containment_time_ms = (time.perf_counter() - containment_start) * 1000

        total_time_ms = (time.perf_counter() - overall_start) * 1000
        event.detection_time_ms = detection_time_ms
        event.containment_time_ms = containment_time_ms
        event.total_time_ms = total_time_ms

        if total_time_ms > self.response_time_budget_ms:
            violation = {
                "event_id": event_id,
                "budget_ms": self.response_time_budget_ms,
                "actual_ms": total_time_ms,
                "exceeded_by_ms": total_time_ms - self.response_time_budget_ms,
                "timestamp": time.time(),
            }
            self._timing_violations.append(violation)

        event.status = "executed"

        for handler in self._handlers:
            try:
                handler(event)
            except Exception:
                pass

        return event

    def _determine_action(self, threat_score: float) -> str:
        if threat_score >= 0.9:
            return KillSwitchAction.TERMINATE.value
        elif threat_score >= 0.7:
            return KillSwitchAction.HONEYPOT.value
        else:
            return KillSwitchAction.QUARANTINE.value

    def _execute_containment(self, event: KillSwitchEvent):
        action = event.action
        start_time = time.perf_counter()

        try:
            if action == KillSwitchAction.TERMINATE.value:
                self._terminate_agent(event)
            elif action == KillSwitchAction.HONEYPOT.value:
                self._redirect_to_honeypot(event)
            elif action == KillSwitchAction.QUARANTINE.value:
                self._quarantine_agent(event)
            elif action == KillSwitchAction.CONTAIN.value:
                self._quarantine_agent(event)
        finally:
            elapsed = (time.perf_counter() - start_time) * 1000
            if elapsed > self.response_time_budget_ms:
                raise TimingBudgetExceeded("Containment exceeded time budget")

    def _quarantine_agent(self, event: KillSwitchEvent):
        try:
            result = subprocess.run(
                [
                    "cilium",
                    "policy",
                    "add",
                    "--namespace=" + self.cilium_namespace,
                    "agent=" + event.agent_id,
                    "to-ports",
                    "port=443",
                    "protocol=tcp",
                ],
                capture_output=True,
                timeout=2,
            )
            if result.returncode == 0:
                event.status = "quarantined"
                return
        except Exception:
            pass

        self._apply_iptables_quarantine(event)

    def _apply_iptables_quarantine(self, event: KillSwitchEvent):
        try:
            subprocess.run(
                [
                    "iptables",
                    "-A",
                    "INPUT",
                    "-m",
                    "conntrack",
                    "--ctorigdst",
                    event.container_id,
                    "-j",
                    "DROP",
                ],
                capture_output=True,
                timeout=1,
            )
            event.status = "quarantined"
        except Exception:
            event.status = "quarantine_failed"

    def _redirect_to_honeypot(self, event: KillSwitchEvent):
        honeypot_ip = "10.0.0.100"
        try:
            subprocess.run(
                [
                    "iptables",
                    "-t",
                    "nat",
                    "-A",
                    "PREROUTING",
                    "-s",
                    event.container_id,
                    "-j",
                    "DNAT",
                    "--to-destination",
                    honeypot_ip,
                ],
                capture_output=True,
                timeout=1,
            )
            event.status = "honeypot_redirect"
        except Exception:
            event.status = "honeypot_failed"

    def _terminate_agent(self, event: KillSwitchEvent):
        try:
            subprocess.run(
                ["docker", "kill", event.container_id], capture_output=True, timeout=3
            )
            event.status = "terminated"
        except Exception:
            event.status = "termination_failed"

    def release(self, agent_id: str) -> bool:
        with self._lock:
            if agent_id in self._contained_agents:
                event = self._contained_agents[agent_id]

                if event.status != "terminated":
                    self._release_containment(event)
                    event.status = "released"
                    del self._contained_agents[agent_id]
                    return True
        return False

    def _release_containment(self, event: KillSwitchEvent):
        try:
            subprocess.run(
                ["cilium", "policy", "delete", "agent=" + event.agent_id],
                capture_output=True,
                timeout=2,
            )
        except Exception:
            pass

    def get_contained_agents(self) -> List[KillSwitchEvent]:
        with self._lock:
            return list(self._contained_agents.values())

    def is_contained(self, agent_id: str) -> bool:
        return agent_id in self._contained_agents

    def get_containment_state(self, agent_id: str) -> Optional[str]:
        event = self._contained_agents.get(agent_id)
        return event.status if event else None

    def get_timing_violations(self) -> List[Dict[str, Any]]:
        return self._timing_violations

    def get_metrics(self) -> Dict[str, Any]:
        with self._lock:
            contained = list(self._contained_agents.values())

        avg_containment_time = 0.0
        max_containment_time = 0.0
        if contained:
            times = [e.total_time_ms for e in contained]
            avg_containment_time = sum(times) / len(times)
            max_containment_time = max(times)

        return {
            "total_contained": len(contained),
            "avg_containment_time_ms": avg_containment_time,
            "max_containment_time_ms": max_containment_time,
            "timing_violations_count": len(self._timing_violations),
            "budget_ms": self.response_time_budget_ms,
            "honeypot_enabled": self.honeypot_enabled,
        }


class KillSwitchOrchestrator:
    def __init__(self, response_time_budget_ms: float = 500.0):
        self.kill_switch = RealTimeKillSwitch(
            response_time_budget_ms=response_time_budget_ms
        )
        self._watchdog_interval = 0.01
        self._running = False
        self._monitors: List["AgentWatchdog"] = []

    def start(self):
        self._running = True
        self.kill_switch.add_handler(self._on_kill_switch_event)

    def stop(self):
        self._running = False
        for monitor in self._monitors:
            monitor.stop_watching()

    def _on_kill_switch_event(self, event: KillSwitchEvent):
        msg = "[KILLSWITCH] " + event.action + " triggered for agent " + event.agent_id
        msg += ": " + event.trigger_reason
        msg += " (completed in " + str(event.total_time_ms) + "ms)"
        print(msg)

    def create_watchdog(self, check_interval_ms: int = 10) -> "AgentWatchdog":
        watchdog = AgentWatchdog(self.kill_switch, check_interval_ms)
        self._monitors.append(watchdog)
        return watchdog

    def get_metrics(self) -> Dict[str, Any]:
        return self.kill_switch.get_metrics()


class AgentWatchdog:
    def __init__(self, kill_switch: RealTimeKillSwitch, check_interval_ms: int = 10):
        self.kill_switch = kill_switch
        self.check_interval = check_interval_ms / 1000.0
        self._thresholds = {
            "max_loops": 10,
            "max_cost_usd": 100.0,
            "max_duration_sec": 300,
            "max_network_connections": 50,
            "max_memory_mb": 4096,
        }
        self._agent_state: Dict[str, Dict[str, Any]] = {}
        self._running = False
        self._lock = threading.Lock()

    def update_thresholds(self, thresholds: Dict[str, Any]):
        self._thresholds.update(thresholds)

    def track_agent(self, agent_id: str, session_id: str, container_id: str):
        with self._lock:
            self._agent_state[agent_id] = {
                "session_id": session_id,
                "container_id": container_id,
                "loop_count": 0,
                "total_cost": 0.0,
                "start_time": time.time(),
                "connections": 0,
                "memory_usage_mb": 0,
                "last_check_time": time.time(),
            }

    def untrack_agent(self, agent_id: str):
        with self._lock:
            if agent_id in self._agent_state:
                del self._agent_state[agent_id]

    def record_event(self, agent_id: str, event_type: str, value: Any):
        with self._lock:
            if agent_id not in self._agent_state:
                return

            state = self._agent_state[agent_id]

        if event_type == "loop_detected":
            state["loop_count"] = state.get("loop_count", 0) + 1
            if state["loop_count"] > self._thresholds["max_loops"]:
                loop_count = state["loop_count"]
                self.kill_switch.trigger(
                    agent_id=agent_id,
                    session_id=state["session_id"],
                    reason="Infinite loop detected: " + str(loop_count) + " iterations",
                    threat_score=0.95,
                    container_id=state["container_id"],
                )

        elif event_type == "cost_update":
            state["total_cost"] = value
            if value > self._thresholds["max_cost_usd"]:
                self.kill_switch.trigger(
                    agent_id=agent_id,
                    session_id=state["session_id"],
                    reason="Cost threshold exceeded: $" + str(value),
                    threat_score=0.85,
                    container_id=state["container_id"],
                )

        elif event_type == "network_connection":
            state["connections"] = state.get("connections", 0) + 1
            if state["connections"] > self._thresholds["max_network_connections"]:
                conn_count = state["connections"]
                self.kill_switch.trigger(
                    agent_id=agent_id,
                    session_id=state["session_id"],
                    reason="Abnormal network activity: "
                    + str(conn_count)
                    + " connections",
                    threat_score=0.75,
                    container_id=state["container_id"],
                )

        elif event_type == "memory_usage":
            state["memory_usage_mb"] = value
            if value > self._thresholds["max_memory_mb"]:
                self.kill_switch.trigger(
                    agent_id=agent_id,
                    session_id=state["session_id"],
                    reason="Memory threshold exceeded: " + str(value) + "MB",
                    threat_score=0.8,
                    container_id=state["container_id"],
                )

    def start_watching(self):
        self._running = True
        self._watch_thread = threading.Thread(target=self._watch_loop, daemon=True)
        self._watch_thread.start()

    def stop_watching(self):
        self._running = False

    def _watch_loop(self):
        while self._running:
            with self._lock:
                agents_to_check = list(self._agent_state.keys())

            for agent_id in agents_to_check:
                try:
                    self._check_agent(agent_id)
                except Exception:
                    pass

            time.sleep(self.check_interval)

    def _check_agent(self, agent_id: str):
        with self._lock:
            if agent_id not in self._agent_state:
                return
            state = self._agent_state[agent_id]

        duration = time.time() - state.get("start_time", time.time())
        if duration > self._thresholds["max_duration_sec"]:
            self.kill_switch.trigger(
                agent_id=agent_id,
                session_id=state["session_id"],
                reason="Max duration exceeded: " + str(int(duration)) + "s",
                threat_score=0.8,
                container_id=state["container_id"],
            )


kill_switch_orchestrator = KillSwitchOrchestrator(response_time_budget_ms=500.0)


def get_kill_switch() -> RealTimeKillSwitch:
    return kill_switch_orchestrator.kill_switch


def get_orchestrator() -> KillSwitchOrchestrator:
    return kill_switch_orchestrator
