"""
Agente 2 — Correlação temporal + PORTÃO DE TRIAGEM determinístico (híbrido).

Fluxo:
  1. Materializa/abre a Gold (fact_security_event) na DuckDB.
  2. Correlação determinística (0 tokens): timelines por entidade + arestas de artefato
     numa linha do tempo única (event_utc_time; source_file nunca é fronteira).
  3. PORTÃO DE TRIAGEM determinístico (0 tokens, triage.py + triage_rules.yaml): decide
     por cadeia se tem CARACTERÍSTICA de ataque. Escala só as cadeias que disparam regra
     (high, ou 2+ medium) OU as sorteadas na amostragem de auditoria. As demais são
     declaradas legítimas com prova auditável — e NÃO gastam cota de LLM.
  4. (Opcional) Groq pontua a plausibilidade só das cadeias ESCALADAS (token-limitado).
  5. Reporta cadeias triadas + as arestas cross-dia que provam a continuidade dia1↔dia2.

Economia: o LLM (Groq aqui, Gemini no Agente 4) só é acionado no subconjunto escalado.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from . import triage
from .correlate import artifact_edges, entity_timelines
from .gold import open_gold
from .plausibility import GroqPlausibility


@dataclass
class CorrelationResult:
    chains: list = field(default_factory=list)        # escaladas: [(Chain, ChainVerdict|None)]
    triaged: list = field(default_factory=list)       # todas: [(Chain, TriageDecision)]
    cross_day_edges: list = field(default_factory=list)
    total_tokens: int = 0
    llm_calls: int = 0
    n_escalated: int = 0
    n_clear: int = 0
    n_sampled: int = 0
    trace: list = field(default_factory=list)


def _prescore(c) -> int:
    """Ranking determinístico dentro do conjunto escalado (qual cadeia olhar primeiro)."""
    arts = " ".join((s.artifact or "") + " " + (s.image_name or "") for s in c.steps).lower()
    cats = {s.category for s in c.steps}
    score = len(c.steps)
    if "network_connect" in cats and "process_create" in cats:
        score += 50
    if any(k in arts for k in ("powershell", "cmd.exe", ".scr", "certutil",
                               "psexec", "rundll32", "net.exe", "net1")):
        score += 40
    if c.cross_day:
        score += 30
    return score


def _sample_clear(clear_decisions, budget: int) -> set:
    """Sorteio DETERMINÍSTICO de até `budget` cadeias 'clear' para auditoria pelo LLM
    (rede de segurança contra ataque novo fora das regras). Estável e reproduzível:
    ordena por hash da entidade e pega os primeiros — mesma entrada, mesma amostra."""
    if budget <= 0 or not clear_decisions:
        return set()
    ordered = sorted(clear_decisions,
                     key=lambda d: hashlib.sha1(d.entity.encode()).hexdigest())
    return {d.entity for d in ordered[:budget]}


def run(sample: int | None = None,
        rebuild: bool = False,
        top_n: int = 5,
        min_steps: int = 4,
        use_triage: bool = True,
        rules_path=None,
        sample_budget: int = 1,
        use_llm: bool = False,
        dry_run: bool = False,
        groq: GroqPlausibility | None = None,
        con=None) -> CorrelationResult:
    res = CorrelationResult()
    con = con or open_gold(sample=sample, rebuild=rebuild)

    chains = entity_timelines(con, min_steps=min_steps)
    edges = artifact_edges(con, cross_day_only=True, limit=100)
    res.cross_day_edges = edges
    res.trace.append(f"determinístico: {len(chains)} timelines de entidade, "
                     f"{len(edges)} arestas de artefato cross-dia")

    # ---- PORTÃO DE TRIAGEM (0 tokens) -------------------------------------------------
    if use_triage:
        rules = triage.load_rules(rules_path) if rules_path else triage.load_rules()
        decisions = [triage.triage_chain(c, rules) for c in chains]
    else:
        # sem portão: tudo é "escalado" (comportamento antigo, para comparação)
        rules = []
        decisions = [triage.TriageDecision(entity=c.entity, decision="escalate")
                     for c in chains]

    by_entity = {c.entity: (c, d) for c, d in zip(chains, decisions)}
    escalated_d = [d for d in decisions if d.decision == "escalate"]
    clear_d = [d for d in decisions if d.decision == "clear"]

    # amostragem: sorteia parte dos 'clear' para auditoria do LLM
    sampled = _sample_clear(clear_d, sample_budget)
    for d in clear_d:
        if d.entity in sampled:
            d.sampled_for_audit = True

    res.triaged = [(by_entity[d.entity][0], d) for d in decisions]
    res.n_escalated = len(escalated_d)
    res.n_clear = len(clear_d)
    res.n_sampled = len(sampled)
    res.trace.append(
        f"triagem: {res.n_escalated} escaladas (regra disparou), {res.n_clear} legítimas, "
        f"{res.n_sampled} amostradas p/ auditoria; {len(rules)} regras")

    # conjunto que segue para o LLM: escaladas ∪ amostradas
    to_llm_entities = {d.entity for d in escalated_d} | sampled
    candidates = [by_entity[e][0] for e in to_llm_entities]
    candidates.sort(key=_prescore, reverse=True)
    candidates = candidates[:top_n]

    if not use_llm:
        res.chains = [(c, None) for c in candidates]
        res.trace.append("Groq desativado (portão determinístico decide; sem gasto de token).")
        return res

    groq = groq or GroqPlausibility()
    for c in candidates:
        if dry_run:
            est = groq.dry_run(c)
            res.trace.append(f"[dry-run] {c.entity}: input≈{est} tokens")
            res.chains.append((c, None))
            continue
        v = groq.score(c)
        res.llm_calls += 1
        res.total_tokens += v.total_tokens
        res.chains.append((c, v))
        tag = v.error or f"{v.verdict} p={v.plausibility:.2f} {v.likely_tactics}"
        res.trace.append(f"LLM {c.entity}: {tag} ({v.total_tokens} tok)")

    res.chains.sort(key=lambda cv: (cv[1].plausibility if cv[1] else 0.0), reverse=True)
    return res
