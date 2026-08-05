"""
Agente 4 — orquestração do veredito final.

Recebe o HANDOFF-DE-VEREDITO (cadeia do Agente 2 + candidatos ATT&CK por evento do
Agente 3), monta um prompt compacto, pede ao Gemini o `ChainVerdictReport` estruturado
e aplica uma trava de GROUNDING: a técnica atribuída a um evento tem de estar entre os
candidatos daquele evento (ou "NONE"). Se o LLM escapar disso, o agente corrige para
"NONE" e anota — o veredito final nunca cita um T-ID que o RAG não recuperou.

Formato do handoff (produzido por `mitre-rag/rag_candidates.py` no venv do RAG):
    {
      "entity": "SCRANTON/pbeesly",
      "prior_chain_verdict": {"verdict": "attack", "plausibility": 0.9,
                              "likely_tactics": [...]} | null,
      "events": [
        {"index": 0, "time": "02:55:56", "description": "<NL>", "raw": "<linha>",
         "candidates": [{"attack_id": "T1036.005", "name": "...", "score": 0.71,
                         "tactics": "Defense Evasion", "is_subtechnique": true}, ...]},
        ...
      ]
    }
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .gemini_client import GeminiVerdict
from .schema import ChainVerdictReport, ConfidenceLevel, EventVerdict

# Teto de candidatos por evento. Precisa acomodar TODO o union (rerank top_k ∪ e5_extra),
# senão trunca os candidatos recuperados pelo e5 no fim da lista — foi o que escondia
# T1071/T1571 do evento de C2, cujos primeiros slots vêm de um rerank ruidoso.
MAX_CANDIDATES_PER_EVENT = 10
MAX_DESC_CHARS = 400


@dataclass
class VerdictResult:
    report: ChainVerdictReport | None = None
    usage: dict = field(default_factory=dict)
    trace: list = field(default_factory=list)


def build_prompt(handoff: dict) -> str:
    """Renderiza a cadeia + candidatos num texto compacto para o Gemini."""
    entity = handoff.get("entity", "?")
    prior = handoff.get("prior_chain_verdict") or {}
    lines = [f"CHAIN ENTITY: {entity}"]
    if prior:
        lines.append(
            f"PRIOR TEMPORAL SCREEN (agent 2): verdict={prior.get('verdict')} "
            f"plausibility={prior.get('plausibility')} "
            f"tactics={prior.get('likely_tactics')}")
    lines.append(f"EVENTS ({len(handoff.get('events', []))}), in chronological order:")
    for ev in handoff.get("events", []):
        idx = ev.get("index")
        time = ev.get("time", "")
        desc = (ev.get("description") or ev.get("raw") or "").strip()[:MAX_DESC_CHARS]
        lines.append(f"\n[event {idx}] {time}")
        lines.append(f"  observation: {desc}")
        cands = (ev.get("candidates") or [])[:MAX_CANDIDATES_PER_EVENT]
        if not cands:
            lines.append("  candidates: (none retrieved)")
            continue
        lines.append("  candidate techniques (choose one id, or NONE):")
        for c in cands:
            sub = " [sub]" if c.get("is_subtechnique") else ""
            score = c.get("score")
            score_str = f" | rag_score: {score:.3f}" if isinstance(score, (int, float)) else ""
            lines.append(
                f"    - {c.get('attack_id')} {c.get('name')}{sub}"
                f" | tactics: {c.get('tactics', '')}{score_str}")
    lines.append(
        "\nReturn one EventVerdict per event above, in the same order, choosing the "
        "assigned technique ONLY from that event's candidate ids (or NONE).")
    return "\n".join(lines)


def _level_for(conf: float) -> ConfidenceLevel:
    if conf >= 0.75:
        return ConfidenceLevel.high
    if conf >= 0.4:
        return ConfidenceLevel.medium
    if conf > 0.0:
        return ConfidenceLevel.low
    return ConfidenceLevel.none


def _ground(report: ChainVerdictReport, handoff: dict, trace: list) -> ChainVerdictReport:
    """Trava de grounding + coerência confidence/level. Corrige in-place com anotação."""
    events = handoff.get("events", [])
    # mapa index -> {ids candidatos, nome por id}
    allowed: list[dict] = []
    for ev in events:
        cands = ev.get("candidates") or []
        ids = {c.get("attack_id") for c in cands}
        names = {c.get("attack_id"): c.get("name", "") for c in cands}
        # tática vem do metadado do candidato do RAG, nunca do LLM: é a fase da
        # cadeia de ataque e não deve depender do que o modelo escreveu.
        tactics = {c.get("attack_id"): (c.get("tactics") or "") for c in cands}
        allowed.append({"ids": ids, "names": names, "tactics": tactics})

    n_in, n_out = len(events), len(report.events)
    if n_out != n_in:
        trace.append(f"⚠ Gemini devolveu {n_out} vereditos p/ {n_in} eventos (ajustando).")

    fixed: list[EventVerdict] = []
    for i, ev in enumerate(events):
        v = report.events[i] if i < len(report.events) else EventVerdict(
            event=ev.get("raw", f"event {i}"),
            step_title=f"Passo {i + 1} sem veredito do modelo",
            attack_id="NONE", technique_name="",
            confidence=0.0, confidence_level=ConfidenceLevel.none,
            rationale="O modelo não devolveu veredito para este passo da cadeia.")
        ids = allowed[i]["ids"]
        if v.attack_id != "NONE" and v.attack_id not in ids:
            trace.append(
                f"⚠ evento {i}: técnica {v.attack_id} fora dos candidatos do RAG "
                f"→ corrigida p/ NONE.")
            v.attack_id = "NONE"
            v.technique_name = ""
            v.confidence = 0.0
            v.confidence_level = ConfidenceLevel.none
            v.rationale = (v.rationale + " [correção: técnica fora dos candidatos do RAG]").strip()
        elif v.attack_id != "NONE" and not v.technique_name:
            v.technique_name = allowed[i]["names"].get(v.attack_id, "")
        # tática: sempre do candidato do RAG (ou vazia quando não há técnica)
        v.tactic = allowed[i]["tactics"].get(v.attack_id, "") if v.attack_id != "NONE" else ""
        # título do passo: se o modelo deixou vazio, cai para a descrição do evento
        if not (v.step_title or "").strip():
            fallback = (ev.get("description") or ev.get("raw") or f"Passo {i + 1}").strip()
            v.step_title = fallback[:120]
            trace.append(f"⚠ evento {i}: step_title vazio → usando a descrição do evento.")
        # coerência confidence <-> level
        expected = _level_for(v.confidence)
        if v.attack_id == "NONE":
            v.confidence, v.confidence_level = 0.0, ConfidenceLevel.none
        elif v.confidence_level != expected:
            v.confidence_level = expected
        fixed.append(v)

    report.events = fixed
    return report


class VerdictAgent:
    def __init__(self, gemini: GeminiVerdict | None = None):
        self.gemini = gemini or GeminiVerdict()

    def run(self, handoff: dict) -> VerdictResult:
        res = VerdictResult()
        if not handoff.get("events"):
            raise ValueError("handoff sem 'events' — nada para julgar.")
        prompt = build_prompt(handoff)
        res.trace.append(f"prompt: {len(handoff['events'])} eventos, "
                         f"~{(len(prompt) + 3) // 4} tokens de input estimados")
        report = self.gemini.judge(prompt)
        res.usage = dict(self.gemini.last_usage)
        report = _ground(report, handoff, res.trace)
        res.report = report
        res.trace.append(
            f"gemini: {res.usage.get('total_tokens', '?')} tokens "
            f"(in={res.usage.get('prompt_tokens', '?')}, "
            f"out={res.usage.get('output_tokens', '?')})")
        return res
