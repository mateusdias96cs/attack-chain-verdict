"""
CLI do agente de correlação temporal.

Exemplos:
  # amostra rápida (constrói gold 40k/arquivo), correlaciona e pontua via Groq
  python -m temporal_agent.cli --sample 40000

  # dataset completo (783k), reconstrução completa
  python -m temporal_agent.cli --rebuild

  # portão determinístico decide, sem gastar token (default: Groq desligado)
  python -m temporal_agent.cli --sample 40000

  # também pontua as cadeias ESCALADAS com o Groq (gasta token)
  python -m temporal_agent.cli --sample 40000 --groq

  # estima tokens sem chamar a API
  python -m temporal_agent.cli --sample 40000 --groq --dry-run
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load_dotenv():
    import os
    env = Path(".env")
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


def main(argv=None):
    p = argparse.ArgumentParser(description="Agente de correlação temporal (Gold + Groq)")
    p.add_argument("--sample", type=int, default=None, help="linhas por arquivo (rápido)")
    p.add_argument("--rebuild", action="store_true", help="reconstrói a gold do zero")
    p.add_argument("--top-n", type=int, default=5)
    p.add_argument("--min-steps", type=int, default=4)
    p.add_argument("--groq", action="store_true",
                   help="pontua as cadeias escaladas com o Groq (gasta token)")
    p.add_argument("--no-triage", action="store_true",
                   help="desliga o portão determinístico (escala tudo, comportamento antigo)")
    p.add_argument("--sample-budget", type=int, default=1,
                   help="quantas cadeias 'legítimas' amostrar p/ auditoria do LLM")
    p.add_argument("--no-llm", action="store_true", help=argparse.SUPPRESS)  # compat
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--json", action="store_true", help="saída em JSON")
    args = p.parse_args(argv)

    _load_dotenv()
    from .agent import run

    res = run(sample=args.sample, rebuild=args.rebuild, top_n=args.top_n,
              min_steps=args.min_steps, use_triage=not args.no_triage,
              sample_budget=args.sample_budget, use_llm=args.groq, dry_run=args.dry_run)

    if args.json:
        out = {
            "triage_summary": {"escalated": res.n_escalated, "clear": res.n_clear,
                               "sampled": res.n_sampled},
            "triaged": [
                {**c.summary(),
                 "decision": d.decision,
                 "sampled_for_audit": d.sampled_for_audit,
                 "attack_ids": d.attack_ids,
                 "tactics": d.tactics,
                 "fired_rules": [{"rule_id": h.rule_id, "attack_id": h.attack_id,
                                  "level": h.level, "evidence": h.evidence} for h in d.fired],
                 "benign_evidence": d.benign_evidence,
                 "steps": [s.line() for s in c.steps]}
                for c, d in res.triaged
            ],
            "cross_day_edges": [
                {k: (str(e[k]) if k in ("a_time", "b_time") else e[k])
                 for k in ("kind", "a_file", "b_file", "a_host", "b_host",
                           "a_img", "b_img", "gap_seconds", "key")}
                for e in res.cross_day_edges[:20]
            ],
            "total_tokens": res.total_tokens,
        }
        print(json.dumps(out, ensure_ascii=False, indent=2, default=str))
        return

    print("=" * 78, file=sys.stderr)
    for t in res.trace:
        print("· " + t, file=sys.stderr)
    print(f"· LLM chamadas: {res.llm_calls} | tokens totais: {res.total_tokens}", file=sys.stderr)
    print("=" * 78, file=sys.stderr)

    verdict_by_entity = {c.entity: v for c, v in res.chains}
    escalated = [(c, d) for c, d in res.triaged if d.decision == "escalate" or d.sampled_for_audit]
    clear = [(c, d) for c, d in res.triaged if d.decision == "clear" and not d.sampled_for_audit]

    print("\n########## ESCALADAS AO VEREDITO (portão determinístico disparou) ##########")
    if not escalated:
        print("  (nenhuma — nenhuma cadeia com característica de ataque nesta amostra)")
    for i, (c, d) in enumerate(escalated, 1):
        s = c.summary()
        motivo = "AMOSTRADA p/ auditoria" if (d.sampled_for_audit and d.decision == "clear") \
            else f"regras: {', '.join(h.rule_id for h in d.fired)}"
        print(f"\n[{i}] {s['entity']}  | passos={s['n_steps']} cross_dia={s['cross_day']} "
              f"span={s['span_seconds']}s")
        print(f"    motivo do escalonamento: {motivo}")
        if d.fired:
            print(f"    ATT&CK: {d.attack_ids}  táticas: {d.tactics}")
            for h in d.fired:
                print(f"      · [{h.level}] {h.rule_id} {h.attack_id} :: {h.evidence}")
        v = verdict_by_entity.get(c.entity)
        if v:
            print(f"    veredito Groq: {v.verdict} (p={v.plausibility:.2f}) {v.likely_tactics}")
            if v.rationale:
                print(f"    porquê: {v.rationale}")
        for st in c.steps[:6]:
            print("      ", st.line())
        if len(c.steps) > 6:
            print(f"       …(+{len(c.steps)-6} passos)")

    print("\n########## LEGÍTIMAS (nada disparou — prova auditável, sem gasto de cota) ##########")
    if not clear:
        print("  (nenhuma)")
    for i, (c, d) in enumerate(clear[:8], 1):
        s = c.summary()
        print(f"\n[{i}] {s['entity']}  | passos={s['n_steps']}  → USO LEGÍTIMO")
        be = d.benign_evidence
        if be.get("medium_uncorroborated"):
            print(f"    sinais medium sem corroboração (insuficientes p/ escalar): "
                  f"{be['medium_uncorroborated']}")
        for ps in be.get("positive_signals", []):
            print(f"    prova: {ps}")
    if len(clear) > 8:
        print(f"\n  …(+{len(clear)-8} outras cadeias legítimas)")

    print("\n########## CONTINUIDADE DIA1↔DIA2 (arestas de artefato cross-dia) ##########")
    if not res.cross_day_edges:
        print("  (nenhuma — pode faltar cobertura na amostra; tente --rebuild)")
    for e in res.cross_day_edges[:8]:
        print(f"  [{e['kind']}] {e['a_file']}→{e['b_file']} gap={e['gap_seconds']}s "
              f"(~{e['gap_seconds']/3600:.1f}h) {e['a_host']}({e['a_img']})→"
              f"{e['b_host']}({e['b_img']}) key={str(e['key'])[:44]}")


if __name__ == "__main__":
    main()
