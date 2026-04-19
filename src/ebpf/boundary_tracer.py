#!/usr/bin/env python3
import struct
import os
import subprocess
import threading
import json
import time
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import errno


class EventType(Enum):
    PROCESS_EXEC = 1
    NETWORK_CONNECT = 2
    FILE_OPEN = 3
    SYSCALL = 4
    TLS_DECRYPT = 5
    MEMORY_ALLOC = 6
    MODULE_LOAD = 7


@dataclass
class BoundaryEvent:
    event_type: str
    timestamp: float
    pid: int
    ppid: int
    uid: int
    comm: str
    args: Dict[str, Any]
    threat_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class eBPFError(Exception):
    pass


class eBPFProgramNotLoaded(eBPFError):
    pass


class eBPFVerifierError(eBPFError):
    pass


class RealEBPFTracer:
    BPF_SOURCE_TEMPLATE = """
#include <uapi/linux/ptrace.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/bpf.h>
#include <linux/filter.h>

BPF_PERF_OUTPUT(process_events);
BPF_PERF_OUTPUT(network_events);
BPF_PERF_OUTPUT(file_events);
BPF_PERF_OUTPUT(syscalls);

struct process_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[256];
    char filename[512];
    u64 timestamp;
    u64 duration_ns;
};

struct network_event_t {
    u32 pid;
    u32 family;
    u16 sport;
    u16 dport;
    char comm[64];
    char addr[128];
    u64 timestamp;
    u8 direction;
};

struct file_event_t {
    u32 pid;
    u32 uid;
    char comm[64];
    char filename[256];
    u32 mode;
    u64 timestamp;
};

struct syscall_event_t {
    u32 pid;
    u32 uid;
    char comm[64];
    u32 syscall_number;
    u64 timestamp;
    u64 args[6];
};

RAW_TRACEPOINT_PROBE(sched_process_exec)
{
    struct task_struct *parent;
    struct signal_struct *signal;
    struct task_struct *task = (struct task_struct *)ctx->args[0];
    struct task_struct *child = (struct task_struct *)ctx->args[1];

    struct process_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = bpf_get_current_ppid();
    event.uid = bpf_get_current_uid_gid();
    event.timestamp = bpf_ktime_get_ns();
    bpf_probe_read_user(event.comm, sizeof(event.comm), child->comm);

    process_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int trace_connect(struct pt_regs *ctx)
{
    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    struct sock *sk = sock->sk;
    struct sockaddr_in *addr;

    struct network_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    event.direction = 1;

    bpf_get_current_comm(event.comm, sizeof(event.comm));

    if (sk) {
        event.family = sk->sk_family;
        event.sport = bpf_ntohs(sk->sk_src_port);
        bpf_probe_read(&addr, sizeof(addr), &sk->sk_daddr);
    }

    network_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int trace_openat(struct pt_regs *ctx)
{
    struct file_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid();
    event.timestamp = bpf_ktime_get_ns();

    bpf_get_current_comm(event.comm, sizeof(event.comm));

    char *filename = (char *)PT_REGS_PARM2(ctx);
    bpf_probe_read_user(event.filename, sizeof(event.filename), filename);
    event.mode = PT_REGS_PARM3(ctx);

    file_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

    def __init__(self, rules: Optional[Dict[str, Any]] = None):
        self.rules = rules or self._default_rules()
        self.events: List[BoundaryEvent] = []
        self._running = False
        self._handlers: List[Callable[[BoundaryEvent], None]] = []
        self._event_buffer_size = 10000
        self._bpf_loaded = False
        self._bpf_progs: Dict[str, int] = {}
        self._simulation_mode = True

    def _default_rules(self) -> Dict[str, Any]:
        return {
            "suspicious_processes": [
                "/bin/sh",
                "/bin/bash",
                "curl",
                "wget",
                "nc",
                "ncat",
                "kubectl",
                "python",
                "node",
                "java",
                "perl",
                "ruby",
                "php",
            ],
            "suspicious_ports": [4444, 5555, 6666, 7777, 8888],
            "suspicious_domains": [],
            "allowed_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            "max_syscalls_per_second": 1000,
            "max_network_connections_per_minute": 100,
            "process_whitelist": ["systemd", "init", "kworker", "migration"],
        }

    def is_simulation_mode(self) -> bool:
        return self._simulation_mode

    def load_bpf_program(self) -> bool:
        if not os.geteuid() == 0:
            self._simulation_mode = True
            return False

        try:
            bpf_source = self.BPF_SOURCE_TEMPLATE

            with open("/tmp/agentic_adr_bpf.c", "w") as f:
                f.write(bpf_source)

            result = subprocess.run(
                [
                    "clang",
                    "-O2",
                    "-target",
                    "bpf",
                    "-Wall",
                    "-I/usr/include/x86_64-linux-gnu",
                    "-c",
                    "/tmp/agentic_adr_bpf.c",
                    "-o",
                    "/tmp/agentic_adr_bpf.o",
                ],
                capture_output=True,
                timeout=30,
            )

            if result.returncode != 0:
                self._simulation_mode = True
                return False

            self._bpf_loaded = True
            self._simulation_mode = False
            return True

        except FileNotFoundError:
            self._simulation_mode = True
            return False
        except Exception:
            self._simulation_mode = True
            return False

    def add_handler(self, handler: Callable[[BoundaryEvent], None]):
        self._handlers.append(handler)

    def _calculate_threat_score(self, event: BoundaryEvent) -> float:
        score = 0.0

        if event.event_type == "process_exec":
            cmd = event.args.get("filename", "")
            for susp in self.rules.get("suspicious_processes", []):
                if susp in cmd:
                    score += 0.5
                    break

            for whitelisted in self.rules.get("process_whitelist", []):
                if whitelisted in event.comm:
                    score -= 0.3
                    break

        elif event.event_type == "network_connect":
            dest = event.args.get("address", "")
            for net in self.rules.get("suspicious_domains", []):
                if net in dest:
                    score += 0.8
                    break

            port = event.args.get("dport", 0)
            if port in self.rules.get("suspicious_ports", []):
                score += 0.7

            if event.args.get("direction") == "egress":
                allowed = False
                for cidr in self.rules.get("allowed_networks", []):
                    if self._ip_in_cidr(dest, cidr):
                        allowed = True
                        break
                if not allowed:
                    score += 0.4

        return min(max(score, 0.0), 1.0)

    def _ip_in_cidr(self, ip: str, cidr: str) -> bool:
        try:
            if not ip or not cidr:
                return False
            parts = cidr.split("/")
            network = parts[0]
            mask_bits = int(parts[1]) if len(parts) > 1 else 32

            ip_parts = [int(x) for x in ip.split(".")]
            net_parts = [int(x) for x in network.split(".")]

            ip_int = (
                (ip_parts[0] << 24)
                | (ip_parts[1] << 16)
                | (ip_parts[2] << 8)
                | ip_parts[3]
            )
            net_int = (
                (net_parts[0] << 24)
                | (net_parts[1] << 16)
                | (net_parts[2] << 8)
                | net_parts[3]
            )

            mask = (0xFFFFFFFF << (32 - mask_bits)) & 0xFFFFFFFF

            return (ip_int & mask) == (net_int & mask)
        except Exception:
            return False

    def start(self):
        self._running = True

        if not self.load_bpf_program():
            pass

        if self._simulation_mode:
            self._start_simulation()
        else:
            self._start_real_monitoring()

    def stop(self):
        self._running = False

        if not self._simulation_mode and self._bpf_loaded:
            self._cleanup_bpf()

    def _start_real_monitoring(self):
        pass

    def _start_simulation(self):
        import random

        def simulate():
            event_types = ["process_exec", "network_connect", "file_open", "syscall"]
            dangerous_events = [
                {"type": "process_exec", "filename": "/bin/sh", "comm": "python"},
                {
                    "type": "network_connect",
                    "dport": 4444,
                    "address": "10.0.0.50",
                    "comm": "curl",
                },
                {"type": "file_open", "filename": "/etc/shadow", "comm": "python"},
            ]

            while self._running:
                if random.random() < 0.1:
                    event_data = random.choice(dangerous_events)
                else:
                    event_data = {
                        "type": random.choice(event_types),
                        "filename": "/usr/bin/python3",
                        "comm": "python",
                    }

                event = BoundaryEvent(
                    event_type=event_data.get("type", "unknown"),
                    timestamp=time.time(),
                    pid=random.randint(1000, 9999),
                    ppid=random.randint(1000, 9999),
                    uid=random.randint(0, 65535),
                    comm=event_data.get("comm", "unknown"),
                    args=event_data,
                )

                event.threat_score = self._calculate_threat_score(event)

                self._add_event(event)

                for handler in self._handlers:
                    try:
                        handler(event)
                    except Exception:
                        pass

                time.sleep(0.5)

        thread = threading.Thread(target=simulate, daemon=True)
        thread.start()

    def _add_event(self, event: BoundaryEvent):
        self.events.append(event)
        if len(self.events) > self._event_buffer_size:
            self.events = self.events[-self._event_buffer_size :]

    def _cleanup_bpf(self):
        for prog_name, prog_fd in self._bpf_progs.items():
            try:
                os.close(prog_fd)
            except Exception:
                pass
        self._bpf_progs.clear()
        self._bpf_loaded = False

    def get_recent_events(
        self, count: int = 100, event_type: Optional[str] = None
    ) -> List[BoundaryEvent]:
        events = self.events[-count:]
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events

    def get_high_threat_events(self, threshold: float = 0.5) -> List[BoundaryEvent]:
        return [e for e in self.events if e.threat_score >= threshold]

    def check_process_baseline(self, pid: int) -> Dict[str, Any]:
        process_events = [e for e in self.events if e.pid == pid]
        if not process_events:
            return {"total_events": 0, "avg_threat_score": 0.0, "last_event_time": 0}

        return {
            "total_events": len(process_events),
            "avg_threat_score": sum(e.threat_score for e in process_events)
            / len(process_events),
            "last_event_time": max(e.timestamp for e in process_events),
            "event_types": list(set(e.event_type for e in process_events)),
        }

    def get_event_counts(self) -> Dict[str, int]:
        counts = {}
        for event in self.events:
            counts[event.event_type] = counts.get(event.event_type, 0) + 1
        return counts

    def get_threat_summary(self) -> Dict[str, Any]:
        high_threat = self.get_high_threat_events(0.5)
        return {
            "total_events": len(self.events),
            "high_threat_count": len(high_threat),
            "simulation_mode": self._simulation_mode,
            "bpf_loaded": self._bpf_loaded,
            "event_counts": self.get_event_counts(),
        }


class PolicyEngine:
    def __init__(self):
        self.rules = {
            "exec_rules": [
                {
                    "pattern": "nc|netcat|ncat",
                    "action": "BLOCK",
                    "reason": "Suspicious network tool",
                },
                {
                    "pattern": "rm -rf",
                    "action": "BLOCK",
                    "reason": "Destructive command",
                },
                {
                    "pattern": "curl.*http://",
                    "action": "ALERT",
                    "reason": "HTTP traffic detected",
                },
            ],
            "network_rules": [
                {
                    "dest_port": 4444,
                    "action": "QUARANTINE",
                    "reason": "Known malware port",
                },
                {
                    "dest_port": 5555,
                    "action": "QUARANTINE",
                    "reason": "Known malware port",
                },
                {
                    "external": True,
                    "action": "ALERT",
                    "reason": "External network connection",
                },
            ],
        }

    def evaluate(self, event: BoundaryEvent) -> Dict[str, Any]:
        if event.threat_score >= 0.8:
            return {
                "action": "QUARANTINE",
                "reason": "High threat score: " + str(event.threat_score),
                "score": event.threat_score,
            }

        if event.event_type == "process_exec":
            for rule in self.rules.get("exec_rules", []):
                pattern = rule.get("pattern", "")
                args_str = str(event.args)
                if pattern in args_str:
                    return {
                        "action": rule.get("action", "ALERT"),
                        "reason": rule.get("reason", "Pattern match"),
                        "score": event.threat_score,
                    }

        if event.event_type == "network_connect":
            for rule in self.rules.get("network_rules", []):
                if rule.get("dest_port") == event.args.get("dport"):
                    return {
                        "action": rule.get("action", "ALERT"),
                        "reason": rule.get("reason", "Port match"),
                        "score": event.threat_score,
                    }

        return {
            "action": "ALLOW",
            "reason": "No policy match",
            "score": event.threat_score,
        }


class AgentBoundaryMonitor:
    def __init__(
        self, container_id: Optional[str] = None, node_name: Optional[str] = None
    ):
        self.container_id = container_id or os.environ.get("HOSTNAME", "unknown")
        self.node_name = node_name or os.environ.get("NODE_NAME", "unknown")
        self.tracer = RealEBPFTracer()
        self._policy_engine = PolicyEngine()
        self._quarantine_enabled = False
        self._running = False

    def start_monitoring(self):
        self._running = True
        self.tracer.start()

        def event_handler(event: BoundaryEvent):
            verdict = self._policy_engine.evaluate(event)

            if verdict["action"] == "BLOCK":
                self._handle_block(event, verdict)
            elif verdict["action"] == "ALERT":
                self._handle_alert(event, verdict)
            elif verdict["action"] == "QUARANTINE":
                self._handle_quarantine(event, verdict)

        self.tracer.add_handler(event_handler)

    def stop_monitoring(self):
        self._running = False
        self.tracer.stop()

    def _handle_block(self, event: BoundaryEvent, verdict: Dict):
        reason = verdict.get("reason", "policy violation")
        print(
            "[BLOCK] "
            + event.event_type
            + " from PID "
            + str(event.pid)
            + ": "
            + reason
        )

    def _handle_alert(self, event: BoundaryEvent, verdict: Dict):
        reason = verdict.get("reason", "suspicious activity")
        print(
            "[ALERT] "
            + event.event_type
            + " from PID "
            + str(event.pid)
            + ": "
            + reason
        )

    def _handle_quarantine(self, event: BoundaryEvent, verdict: Dict):
        reason = verdict.get("reason", "critical threat")
        print("[QUARANTINE] PID " + str(event.pid) + " - " + reason)
        self._trigger_kill_switch(event.pid)

    def _trigger_kill_switch(self, pid: int):
        print("[KILLSWITCH] Triggered for PID " + str(pid))

    def get_threat_summary(self) -> Dict[str, Any]:
        return self.tracer.get_threat_summary()

    def is_monitoring(self) -> bool:
        return self._running

    def is_simulation_mode(self) -> bool:
        return self.tracer.is_simulation_mode()


def create_boundary_monitor(
    config: Optional[Dict[str, Any]] = None,
) -> AgentBoundaryMonitor:
    return AgentBoundaryMonitor()
