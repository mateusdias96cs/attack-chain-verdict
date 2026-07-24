"""Agente híbrido de parsing Bronze -> Silver (Windows telemetry / Groq)."""
from .agent import AgentResult, parse_log
from .parser import deterministic_parse

__all__ = ["parse_log", "deterministic_parse", "AgentResult"]
