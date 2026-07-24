"""
Agente 2 — Correlação temporal (híbrido).

Fluxo:
  1. Materializa/abre a Gold (fact_security_event) na DuckDB.
  2. Correlação determinística (0 tokens): timelines por entidade + arestas de artefato
     numa linha do tempo única (event_utc_time; source_file nunca é fronteira).
  3. Groq pontua a plausibilidade das top-N cadeias candidatas (token-limitado).
  4. Reporta cadeias rankeadas + as arestas cross-dia que provam a continuidade
     dia1↔dia2 (mesmo traço de ataque atravessando o gap de ~4,5h).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .correlate import artifact_edges, entity_timelines
from .gold import open_gold
from .plausibility import GroqPlausibility


@dataclass
class CorrelationResult:
    chains: list = field(default_factory=list)        # [(Chain, ChainVerdict|None)]
    cross_day_edges: list = field(default_factory=list)
    total_tokens: int = 0
    llm_calls: int = 0
    trace: list = field(default_factory=list)


def run(sample: int | None = None,
        rebuild: bool = False,
        top_n: int = 5,
        min_steps: int = 4,
        use_llm: bool = True,
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

    # ranking preliminar determinístico: prioriza cadeias com sinais fortes
    def prescore(c):
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

    chains.sort(key=prescore, reverse=True)
    candidates = chains[:top_n]

    if not use_llm:
        res.chains = [(c, None) for c in candidates]
        res.trace.append("LLM desativado (só ranking determinístico).")
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

    # re-rank final pela plausibilidade do LLM quando disponível
    res.chains.sort(key=lambda cv: (cv[1].plausibility if cv[1] else 0.0), reverse=True)
    return res
