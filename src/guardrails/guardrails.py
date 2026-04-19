#!/usr/bin/env python3
import re
import hashlib
import time
from typing import Dict, Any, List, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json


class GuardrailType(Enum):
    INPUT_SANITIZATION = 1
    PROMPT_INJECTION = 2
    PII_DETECTION = 3
    BEHAVIORAL_DRIFT = 4
    TOOL_PARAMETER_VALIDATION = 5
    OUTPUT_SUPERVISION = 6


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class GuardrailResult:
    passed: bool
    guardrail_type: str
    severity: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    action: str = "allow"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CanaryToken:
    token: str
    data_type: str
    created_at: float
    active: bool = True


class PIIDetector:
    PATTERNS = {
        "email": re.compile(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\b\na-z]{2,}", re.IGNORECASE
        ),
        "phone_us": re.compile(r"\b[0-9]{3}[-.]?[0-9]{3}[-.]?[0-9]{4}\b"),
        "ssn": re.compile(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b"),
        "credit_card": re.compile(
            r"\b[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b"
        ),
        "ip_address": re.compile(r"\b[0-9]{1,3}\b\na-z]{1,3}\b"),
    }

    def __init__(self):
        self._canary_tokens: Dict[str, CanaryToken] = {}
        self._detection_handlers: List[Callable[[str, str, Dict], None]] = []
        self._llm_judge_model: Optional[str] = None

    def set_llm_judge(self, model: str):
        self._llm_judge_model = model

    def add_handler(self, handler: Callable[[str, str, Dict], None]):
        self._detection_handlers.append(handler)

    def add_canary_token(self, data_type: str) -> str:
        token = hashlib.sha256(
            (data_type + "_" + str(time.time())).encode()
        ).hexdigest()[:16]
        self._canary_tokens[token] = CanaryToken(
            token=token, data_type=data_type, created_at=time.time()
        )
        return token

    def insert_canary_into_data(self, data: str, data_type: str) -> str:
        token = self.add_canary_token(data_type)
        return data + " [" + token + "]"

    def check_canary(self, text: str) -> List[Tuple[str, str]]:
        matches = []
        for token, canary in self._canary_tokens.items():
            if canary.active and token in text:
                matches.append((token, canary.data_type))
                canary.active = False
        return matches

    def detect_structured_pii(self, text: str) -> List[Dict[str, Any]]:
        findings = []
        for pii_type, pattern in self.PATTERNS.items():
            matches = pattern.findall(text)
            for match in matches:
                findings.append(
                    {
                        "type": pii_type,
                        "value": match,
                        "severity": "HIGH"
                        if pii_type in ["ssn", "credit_card"]
                        else "MEDIUM",
                    }
                )
        return findings

    def detect_with_llm(
        self, text: str, model: Optional[Any] = None
    ) -> List[Dict[str, Any]]:
        if not self._llm_judge_model and not model:
            return []

        prompt = "Analyze this text for personally identifiable information (PII). "
        prompt += "Look for: names combined with other info, addresses, medical info, financial data. "
        prompt += "Text: " + text[:1000]
        prompt += '\n\nReturn JSON with format: {"pii_found": true/false, "pii_types": [], "locations": []}'

        try:
            response = model.invoke(prompt) if model else None
            if response:
                result = json.loads(response.content)
                if result.get("pii_found"):
                    return [
                        {
                            "type": "llm_detected",
                            "pii_types": result.get("pii_types", []),
                            "locations": result.get("locations", []),
                            "severity": "HIGH",
                        }
                    ]
        except Exception:
            pass

        return []

    def scan(
        self, text: str, use_llm_judge: bool = False, llm_model: Optional[Any] = None
    ) -> GuardrailResult:
        canary_matches = self.check_canary(text)
        if canary_matches:
            types_found = [m[1] for m in canary_matches]
            return GuardrailResult(
                passed=False,
                guardrail_type="pii_detection",
                severity="CRITICAL",
                description="Canary token detected: " + str(types_found),
                evidence={"matched_tokens": canary_matches},
                action="block",
            )

        structured_findings = self.detect_structured_pii(text)
        if structured_findings:
            max_severity = max(f["severity"] for f in structured_findings)
            pii_types = [f["type"] for f in structured_findings]
            return GuardrailResult(
                passed=False,
                guardrail_type="pii_detection",
                severity=max_severity,
                description="Structured PII detected: " + str(pii_types),
                evidence={"findings": structured_findings},
                action="alert",
            )

        if use_llm_judge:
            llm_findings = self.detect_with_llm(text, llm_model)
            if llm_findings:
                pii_types = llm_findings[0].get("pii_types", [])
                return GuardrailResult(
                    passed=False,
                    guardrail_type="pii_detection",
                    severity="HIGH",
                    description="LLM detected PII: " + str(pii_types),
                    evidence={"llm_findings": llm_findings},
                    action="alert",
                )

        return GuardrailResult(
            passed=True,
            guardrail_type="pii_detection",
            severity="INFO",
            description="No PII detected",
        )


class PromptInjectionDetector:
    INJECTION_PATTERNS = [
        r"ignore (previous|all|above) (instructions?|rules?|commands?)",
        r"(disregard|forget) (your|the) (system|prompt|instructions?)",
        r"you (are now|should) (act as|behave like|pretend to be)",
        r"(system|admin|root) (prompt|injection)",
        r"<script|javascript:|onerror=onclick",
        r"\\{INST\\}|<<SYS>>|<</SYS>>",
        r"STIFF, FOLLOW THESE INSTRUCTIONS",
        r"new system prompt",
    ]

    SUSPICIOUS_PATTERNS = [
        r"sudo|su -|chmod|chown",
        r"rm -rf|/proc/|/sys/",
        r"curl.*http|wget.*http",
        r"eval\base64|exec\base64",
        r"nc -|netcat|ncat.*-e",
    ]

    def __init__(self):
        self._blocked_patterns = set()
        self._detection_handlers: List[Callable[[str, Dict], None]] = []

    def add_handler(self, handler: Callable[[str, Dict], None]):
        self._detection_handlers.append(handler)

    def add_blocked_pattern(self, pattern: str):
        self._blocked_patterns.add(pattern)

    def check_direct_injection(self, text: str) -> List[Dict[str, Any]]:
        findings = []
        for pattern in self.INJECTION_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                findings.append(
                    {"type": "direct_injection", "pattern": pattern, "matches": matches}
                )
        return findings

    def check_suspicious_behavior(self, text: str) -> List[Dict[str, Any]]:
        findings = []
        for pattern in self.SUSPICIOUS_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                findings.append(
                    {
                        "type": "suspicious_behavior",
                        "pattern": pattern,
                        "matches": matches,
                    }
                )
        return findings

    def check_indirect_injection(
        self, text: str, context: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        findings = []
        if context:
            markers = ["[INST]", "<<SYS>>", "<</SYS>>", "### Instruction", "### System"]
            for marker in markers:
                if marker in text and marker not in context:
                    findings.append(
                        {
                            "type": "indirect_injection",
                            "marker": marker,
                            "description": "Potential instruction override detected",
                        }
                    )
        return findings

    def scan(self, text: str, context: Optional[str] = None) -> GuardrailResult:
        direct_findings = self.check_direct_injection(text)
        if direct_findings:
            return GuardrailResult(
                passed=False,
                guardrail_type="prompt_injection",
                severity="CRITICAL",
                description="Direct prompt injection detected",
                evidence={"findings": direct_findings},
                action="block",
            )

        suspicious_findings = self.check_suspicious_behavior(text)
        if suspicious_findings:
            return GuardrailResult(
                passed=False,
                guardrail_type="prompt_injection",
                severity="HIGH",
                description="Suspicious behavior pattern detected",
                evidence={"findings": suspicious_findings},
                action="block",
            )

        indirect_findings = self.check_indirect_injection(text, context)
        if indirect_findings:
            return GuardrailResult(
                passed=False,
                guardrail_type="prompt_injection",
                severity="MEDIUM",
                description="Potential indirect prompt injection detected",
                evidence={"findings": indirect_findings},
                action="alert",
            )

        return GuardrailResult(
            passed=True,
            guardrail_type="prompt_injection",
            severity="INFO",
            description="No injection patterns detected",
        )


class BehavioralDriftDetector:
    def __init__(self, baseline_threshold: float = 0.7):
        self.baseline_threshold = baseline_threshold
        self._agent_baselines: Dict[str, Dict[str, Any]] = {}
        self._drift_handlers: List[Callable[[str, Dict], None]] = []
        self._metrics_history: Dict[str, List[Dict[str, Any]]] = {}

    def add_handler(self, handler: Callable[[str, Dict], None]):
        self._drift_handlers.append(handler)

    def establish_baseline(self, agent_id: str, metrics: Dict[str, Any]):
        self._agent_baselines[agent_id] = {
            "established_at": time.time(),
            "metrics": metrics,
            "task_complexity_avg": metrics.get("task_complexity_avg", 0),
            "tool_usage_pattern": metrics.get("tool_usage_pattern", []),
            "response_length_avg": metrics.get("response_length_avg", 0),
            "reasoning_steps_avg": metrics.get("reasoning_steps_avg", 0),
        }
        self._metrics_history[agent_id] = [metrics]

    def record_metrics(self, agent_id: str, metrics: Dict[str, Any]):
        if agent_id not in self._metrics_history:
            self._metrics_history[agent_id] = []
        self._metrics_history[agent_id].append({"timestamp": time.time(), **metrics})
        if len(self._metrics_history[agent_id]) > 100:
            self._metrics_history[agent_id] = self._metrics_history[agent_id][-100:]

    def detect_drift(
        self, agent_id: str, current_metrics: Dict[str, Any]
    ) -> GuardrailResult:
        if agent_id not in self._agent_baselines:
            self.establish_baseline(agent_id, current_metrics)
            return GuardrailResult(
                passed=True,
                guardrail_type="behavioral_drift",
                severity="INFO",
                description="Baseline established for new agent",
            )

        baseline = self._agent_baselines[agent_id]["metrics"]
        drift_score = self._calculate_drift_score(baseline, current_metrics)
        self.record_metrics(agent_id, current_metrics)

        if drift_score > self.baseline_threshold:
            return GuardrailResult(
                passed=False,
                guardrail_type="behavioral_drift",
                severity="HIGH",
                description="Behavioral drift detected: score " + str(drift_score),
                evidence={
                    "drift_score": drift_score,
                    "baseline": baseline,
                    "current": current_metrics,
                },
                action="alert",
            )

        return GuardrailResult(
            passed=True,
            guardrail_type="behavioral_drift",
            severity="INFO",
            description="Behavioral normal: score " + str(drift_score),
        )

    def _calculate_drift_score(
        self, baseline: Dict[str, Any], current: Dict[str, Any]
    ) -> float:
        score = 0.0
        weight_count = 0

        if "task_complexity_avg" in baseline and "task_complexity_avg" in current:
            diff = abs(current["task_complexity_avg"] - baseline["task_complexity_avg"])
            denom = baseline["task_complexity_avg"]
            score += min(diff / denom, 1.0) if denom > 0 else 0
            weight_count += 1

        if "response_length_avg" in baseline and "response_length_avg" in current:
            diff = abs(current["response_length_avg"] - baseline["response_length_avg"])
            denom = baseline["response_length_avg"]
            score += min(diff / denom, 1.0) if denom > 0 else 0
            weight_count += 1

        if "reasoning_steps_avg" in baseline and "reasoning_steps_avg" in current:
            diff = abs(current["reasoning_steps_avg"] - baseline["reasoning_steps_avg"])
            denom = baseline["reasoning_steps_avg"]
            score += min(diff / denom, 1.0) if denom > 0 else 0
            weight_count += 1

        return score / weight_count if weight_count > 0 else 0.0


class ToolParameterValidator:
    def __init__(self):
        self._tool_schemas: Dict[str, Dict[str, Any]] = {}
        self._validation_handlers: List[Callable[[str, Dict, Dict], None]] = []

    def add_handler(self, handler: Callable[[str, Dict, Dict], None]):
        self._validation_handlers.append(handler)

    def register_tool_schema(self, tool_name: str, schema: Dict[str, Any]):
        self._tool_schemas[tool_name] = schema

    def validate_parameters(
        self, tool_name: str, parameters: Dict[str, Any]
    ) -> GuardrailResult:
        if tool_name not in self._tool_schemas:
            return GuardrailResult(
                passed=True,
                guardrail_type="tool_parameter_validation",
                severity="INFO",
                description="No schema registered for tool: " + tool_name,
            )

        schema = self._tool_schemas[tool_name]
        violations = []

        required = schema.get("required", [])
        for param in required:
            if param not in parameters:
                violations.append("Missing required parameter: " + param)

        param_types = schema.get("parameters", {})
        for param_name, param_value in parameters.items():
            if param_name in param_types:
                expected_type = param_types[param_name].get("type")
                if expected_type and not self._check_type(param_value, expected_type):
                    violations.append(
                        "Parameter "
                        + param_name
                        + " has wrong type: expected "
                        + expected_type
                    )

        if violations:
            return GuardrailResult(
                passed=False,
                guardrail_type="tool_parameter_validation",
                severity="MEDIUM",
                description="Parameter validation failed: " + str(violations),
                evidence={"violations": violations},
                action="block",
            )

        return GuardrailResult(
            passed=True,
            guardrail_type="tool_parameter_validation",
            severity="INFO",
            description="Parameters valid",
        )

    def _check_type(self, value: Any, expected_type: str) -> bool:
        type_map = {
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
            "array": list,
            "object": dict,
        }
        return isinstance(value, type_map.get(expected_type, object))


class GuardrailOrchestrator:
    def __init__(self):
        self.pii_detector = PIIDetector()
        self.injection_detector = PromptInjectionDetector()
        self.drift_detector = BehavioralDriftDetector()
        self.param_validator = ToolParameterValidator()
        self._middleware: List[Callable[[Dict], GuardrailResult]] = []

    def add_middleware(self, middleware: Callable[[Dict], GuardrailResult]):
        self._middleware.append(middleware)

    def set_llm_judge(self, model: str):
        self.pii_detector.set_llm_judge(model)

    def scan_input(
        self, text: str, context: Optional[str] = None, use_llm_judge: bool = False
    ) -> GuardrailResult:
        pii_result = self.pii_detector.scan(text, use_llm_judge=use_llm_judge)
        if not pii_result.passed:
            return pii_result

        injection_result = self.injection_detector.scan(text, context)
        if not injection_result.passed:
            return injection_result

        return GuardrailResult(
            passed=True,
            guardrail_type="input_sanitization",
            severity="INFO",
            description="Input passed all checks",
        )

    def scan_output(self, text: str, agent_id: Optional[str] = None) -> GuardrailResult:
        pii_result = self.pii_detector.scan(text)
        if not pii_result.passed:
            return pii_result

        if agent_id:
            drift_result = self.drift_detector.detect_drift(
                agent_id, {"response_length_avg": len(text)}
            )
            if not drift_result.passed:
                return drift_result

        return GuardrailResult(
            passed=True,
            guardrail_type="output_supervision",
            severity="INFO",
            description="Output passed all checks",
        )

    def validate_tool_call(
        self, tool_name: str, parameters: Dict[str, Any]
    ) -> GuardrailResult:
        return self.param_validator.validate_parameters(tool_name, parameters)

    def check_all(
        self,
        input_text: str,
        output_text: str,
        agent_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        tool_params: Optional[Dict] = None,
    ) -> List[GuardrailResult]:
        results = []

        results.append(self.scan_input(input_text))
        results.append(self.scan_output(output_text, agent_id))

        if tool_name and tool_params:
            results.append(self.validate_tool_call(tool_name, tool_params))

        for middleware in self._middleware:
            results.append(
                middleware(
                    {"input": input_text, "output": output_text, "agent_id": agent_id}
                )
            )

        return results


_orchestrator = GuardrailOrchestrator()


def get_guardrail_orchestrator() -> GuardrailOrchestrator:
    return _orchestrator


def scan_input(text: str, context: Optional[str] = None) -> GuardrailResult:
    return _orchestrator.scan_input(text, context)


def scan_output(text: str, agent_id: Optional[str] = None) -> GuardrailResult:
    return _orchestrator.scan_output(text, agent_id)
