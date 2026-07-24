"""
CLI do agente de correlação temporal.

Exemplos:
  # amostra rápida (constrói gold 40k/arquivo), correlaciona e pontua via Groq
  python -m temporal_agent.cli --sample 40000

  # dataset completo (783k), reconstrução completa
  python -m temporal_agent.cli --rebuild

  # só correlação determinística (0 tokens)
  python -m temporal_agent.cli --sample 40000 --no-llm

  # estima tokens sem chamar a API
  python -m temporal_agent.cli --sample 40000 --dry-run
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
    p.add_argument("--no-llm", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--json", action="store_true", help="saída em JSON")
    args = p.parse_args(argv)

    _load_dotenv()
    from .agent import run

    res = run(sample=args.sample, rebuild=args.rebuild, top_n=args.top_n,
              min_steps=args.min_steps, use_llm=not args.no_llm, dry_run=args.dry_run)

    if args.json:
        out = {
            "chains": [
                {**c.summary(),
                 "verdict": (v.verdict if v else None),
                 "plausibility": (v.plausibility if v else None),
                 "likely_tactics": (v.likely_tactics if v else None),
                 "rationale": (v.rationale if v else None),
                 "steps": [s.line() for s in c.steps]}
                for c, v in res.chains
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

    print("\n########## CADEIAS CANDIDATAS (rankeadas por plausibilidade) ##########")
    for i, (c, v) in enumerate(res.chains, 1):
        s = c.summary()
        verd = f"{v.verdict} (p={v.plausibility:.2f}) táticas={v.likely_tactics}" if v else "—"
        print(f"\n[{i}] {s['entity']}  | passos={s['n_steps']} cross_dia={s['cross_day']} "
              f"span={s['span_seconds']}s files={s['source_files']}")
        print(f"    veredito: {verd}")
        if v and v.rationale:
            print(f"    porquê: {v.rationale}")
        for st in c.steps[:8]:
            print("      ", st.line())
        if len(c.steps) > 8:
            print(f"       …(+{len(c.steps)-8} passos)")

    print("\n########## CONTINUIDADE DIA1↔DIA2 (arestas de artefato cross-dia) ##########")
    if not res.cross_day_edges:
        print("  (nenhuma — pode faltar cobertura na amostra; tente --rebuild)")
    for e in res.cross_day_edges[:8]:
        print(f"  [{e['kind']}] {e['a_file']}→{e['b_file']} gap={e['gap_seconds']}s "
              f"(~{e['gap_seconds']/3600:.1f}h) {e['a_host']}({e['a_img']})→"
              f"{e['b_host']}({e['b_img']}) key={str(e['key'])[:44]}")


if __name__ == "__main__":
    main()
