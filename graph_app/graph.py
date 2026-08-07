"""
Orquestração LangGraph do pipeline de 4 agentes (visualização + execução).

Este grafo existe para MOSTRAR e RODAR a disposição dos agentes no LangGraph Studio.
Os nós espelham os 4 agentes reais do projeto:

    START → agent1_silver → agent2_temporal → agent3_rag → agent4_verdict → END

Constraints reais preservadas:
  - SPLIT DE VENVS: o Agente 3 (e5/torch) vive em mitre-rag/.venv e é chamado por
    SUBPROCESS (o nó agent3_rag reusa verdict_agent.cli.rag_candidates). O Agente 4
    (Gemini) e este grafo rodam no venv 3.12 de graph_app/.
  - GROUNDING: o veredito final só cita técnicas que o RAG recuperou (trava no Agente 4).

Modos dos nós:
  - agent1_silver / agent2_temporal: modo LEVE/demo — operam sobre a fixture já
    correlacionada (eventos silver + linha do tempo). Representam os estágios de
    parsing e correlação sem reprocessar os 1,6 GB de NDJSON bruto.
  - agent3_rag / agent4_verdict: execução REAL (RAG local e Gemini).
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Annotated, Any, TypedDict

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

FIXTURE = REPO / "verdict_agent" / "fixtures" / "apt29_chain.json"


def _keep_last(_old, new):
    return new


class PipelineState(TypedDict, total=False):
    """Estado compartilhado que flui pelos 4 agentes."""
    entity: Annotated[str, _keep_last]
    silver_events: Annotated[list[dict], _keep_last]   # saída Agente 1
    chain: Annotated[dict, _keep_last]                 # saída Agente 2 (linha do tempo única)
    triage: Annotated[dict, _keep_last]                # decisão do PORTÃO determinístico
    handoff: Annotated[dict, _keep_last]               # saída Agente 3 (candidatos/evento)
    verdict: Annotated[dict, _keep_last]               # saída Agente 4 (veredito estruturado)
    report_text: Annotated[str, _keep_last]            # a mesma saída, já narrada para leitura
    trace: Annotated[list[str], lambda old, new: (old or []) + (new or [])]


# --------------------------------------------------------------------------
# Nó 1 — Agente 1 (Silver parser). Modo leve: coleta/normaliza os eventos silver.
# --------------------------------------------------------------------------
def agent1_silver(state: PipelineState) -> dict[str, Any]:
    chain = state.get("chain") or {}
    events = chain.get("events") if chain else None
    # Sem entrada? carrega a fixture APT29 (start-of-pipeline demonstrável).
    if not events and not state.get("silver_events"):
        fx = json.loads(FIXTURE.read_text(encoding="utf-8"))
        state = {**state, "entity": fx.get("entity"), "chain": fx}
        events = fx["events"]
    events = events or []
    silver = []
    for ev in events:
        s = ev.get("silver") or {}
        silver.append({"time": ev.get("time"), "raw": ev.get("raw"), **s})
    return {
        "entity": state.get("entity"),
        "chain": state.get("chain"),
        "silver_events": silver,
        "trace": [f"agent1_silver: {len(silver)} eventos silver normalizados (parser determinístico)"],
    }


# --------------------------------------------------------------------------
# Nó 2 — Agente 2 (Correlação temporal + PORTÃO DE TRIAGEM). Modo leve: linha do tempo
# única por tempo. INVARIANTE: ordena por event_utc_time; source_file NUNCA é fronteira.
# O portão determinístico (0 tokens) decide se a cadeia escala ao veredito LLM ou é
# declarada legítima — economizando cota do Gemini nos casos benignos.
# --------------------------------------------------------------------------
def agent2_temporal(state: PipelineState) -> dict[str, Any]:
    from temporal_agent import triage as T

    chain = dict(state.get("chain") or {})
    events = list(chain.get("events") or [])
    events.sort(key=lambda e: e.get("time") or "")   # ordenação temporal única
    chain["events"] = events
    chain.setdefault("entity", state.get("entity"))

    # PORTÃO: triagem determinística sobre os eventos silver (regras de escopo evento).
    rules = T.load_rules()
    silver = state.get("silver_events") or [{"time": e.get("time"), "raw": e.get("raw"),
                                             **(e.get("silver") or {})} for e in events]
    decision = T.triage_events(silver, rules, entity=chain.get("entity", "?"))
    chain["prior_chain_verdict"] = decision.to_prior_verdict()

    if decision.decision == "escalate":
        msg = (f"escala ao veredito — regras: "
               f"{', '.join(h.rule_id for h in decision.fired)} {decision.attack_ids}")
    else:
        msg = "legítima (nenhuma regra disparou) — não gasta cota do Gemini"
    return {
        "chain": chain,
        "triage": {"decision": decision.decision,
                   "attack_ids": decision.attack_ids, "tactics": decision.tactics,
                   "fired_rules": [h.rule_id for h in decision.fired],
                   "benign_evidence": decision.benign_evidence},
        "trace": [f"agent2_temporal: {len(events)} passos numa linha do tempo única; portão: {msg}"],
    }


def route_after_triage(state: PipelineState) -> str:
    """Aresta condicional: só escala ao RAG/Gemini se o portão apontou característica de
    ataque. Cadeia legítima curto-circuita para o relatório benigno (0 tokens de LLM)."""
    return "escalate" if (state.get("triage") or {}).get("decision") == "escalate" else "clear"


# --------------------------------------------------------------------------
# Nó alternativo — relatório de USO LEGÍTIMO com prova auditável (sem LLM).
# --------------------------------------------------------------------------
def agent_legitimate(state: PipelineState) -> dict[str, Any]:
    tri = state.get("triage") or {}
    be = tri.get("benign_evidence") or {}
    lines = [f"VEREDITO: USO LEGÍTIMO — {state.get('entity', '?')}",
             "Nenhuma regra de ataque disparou no portão determinístico (0 tokens de LLM).",
             ""]
    if be.get("medium_uncorroborated"):
        lines.append("Sinais fracos (medium) sem corroboração, insuficientes para escalar: "
                     + ", ".join(be["medium_uncorroborated"]))
    lines.append("Prova auditável (indicadores de ataque conhecidos ausentes):")
    for ps in be.get("positive_signals", []):
        lines.append(f"  - {ps}")
    text = "\n".join(lines)
    return {
        "verdict": {"overall_verdict": "benign", "source": "deterministic_triage",
                    "benign_evidence": be},
        "report_text": text,
        "trace": ["agent_legitimate: veredito benigno emitido sem gastar cota do Gemini"],
    }


# --------------------------------------------------------------------------
# Nó 3 — Agente 3 (RAG técnica). REAL, via SUBPROCESS no venv do mitre-rag.
# --------------------------------------------------------------------------
def agent3_rag(state: PipelineState) -> dict[str, Any]:
    from verdict_agent.cli import rag_candidates

    chain = state.get("chain") or {}
    with tempfile.NamedTemporaryFile("w", suffix=".chain.json", delete=False,
                                     encoding="utf-8") as tf:
        json.dump(chain, tf, ensure_ascii=False)
        chain_path = Path(tf.name)
    handoff = rag_candidates(chain_path, top_k=4)   # subprocess → mitre-rag/.venv
    n_cand = sum(len(e.get("candidates", [])) for e in handoff.get("events", []))
    return {
        "handoff": handoff,
        "trace": [f"agent3_rag: {len(handoff.get('events', []))} eventos classificados, "
                  f"{n_cand} candidatos ATT&CK (union rerank∪e5, via subprocess mitre-rag/.venv)"],
    }


# --------------------------------------------------------------------------
# Nó 4 — Agente 4 (Veredito final). REAL, Gemini + trava de grounding.
# --------------------------------------------------------------------------
def agent4_verdict(state: PipelineState) -> dict[str, Any]:
    from verdict_agent.agent import VerdictAgent
    from verdict_agent.cli import render_report

    handoff = state.get("handoff") or {}
    res = VerdictAgent().run(handoff)
    return {
        "verdict": res.report.model_dump(mode="json"),
        # o Studio mostra o estado como JSON; sem este campo a cadeia narrada não
        # apareceria legível na interface, só o objeto aninhado.
        "report_text": render_report(res.report),
        "trace": [f"agent4_verdict: veredito {res.report.overall_verdict.value} "
                  f"p={res.report.overall_confidence:.2f} "
                  f"({res.usage.get('total_tokens', '?')} tokens Gemini)"],
    }


# --------------------------------------------------------------------------
# Montagem do grafo (o objeto que o LangGraph Studio carrega e desenha).
# --------------------------------------------------------------------------
def build_graph():
    from langgraph.graph import END, START, StateGraph

    g = StateGraph(PipelineState)
    g.add_node("agent1_silver", agent1_silver)
    g.add_node("agent2_temporal", agent2_temporal)
    g.add_node("agent_legitimate", agent_legitimate)
    g.add_node("agent3_rag", agent3_rag)
    g.add_node("agent4_verdict", agent4_verdict)

    g.add_edge(START, "agent1_silver")
    g.add_edge("agent1_silver", "agent2_temporal")
    # PORTÃO: escala ao RAG/Gemini só se houver característica de ataque; senão vai
    # direto ao relatório de legítimo (curto-circuito que economiza cota).
    g.add_conditional_edges("agent2_temporal", route_after_triage,
                            {"escalate": "agent3_rag", "clear": "agent_legitimate"})
    g.add_edge("agent3_rag", "agent4_verdict")
    g.add_edge("agent4_verdict", END)
    g.add_edge("agent_legitimate", END)
    return g.compile()


graph = build_graph()
