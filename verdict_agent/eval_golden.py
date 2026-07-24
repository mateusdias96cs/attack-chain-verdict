"""
Avaliação do pipeline num GOLDEN SET rotulado (15 casos, dificuldade crescente).

Mede os dois estágios que decidem a resposta final:
  - Agente 3 (RAG): a técnica-gabarito foi RECUPERADA no conjunto de candidatos? (recall)
  - Agente 4 (Gemini): a técnica ATRIBUÍDA bate com o gabarito? (acurácia do veredito)

Métricas:
  - recall@candidatos (A3): gabarito presente nos candidatos (e em que rank)
  - acurácia estrita (A4): atribuída == gabarito exato
  - acurácia por família (A4): aceita pai↔subtécnica (não aceita irmãs)
  - NONE-rate: casos em que o A4 honestamente não atribuiu técnica
  - correções de grounding: vezes que a trava rebaixou uma técnica fora dos candidatos
  - acurácia por faixa de dificuldade (fácil 1-5 / média 6-10 / difícil 11-15)

Eficiência: 1 subprocess no venv do mitre-rag (um load de torch p/ os 15 eventos) +
15 chamadas Gemini (uma por caso, independentes — testa variabilidade das respostas).

Uso: .venv/bin/python -m verdict_agent.eval_golden [--out resultados.json]
"""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .agent import VerdictAgent
from .cli import rag_candidates

HERE = Path(__file__).resolve().parent
GOLDEN = HERE / "golden_set.json"


def acceptable(assigned: str, gab: str) -> bool:
    """Aceita a atribuição: exata, OU pai↔subtécnica. NÃO aceita subtécnicas irmãs."""
    if not assigned or assigned == "NONE":
        return False
    if assigned == gab:
        return True
    a_base, g_base = assigned.split(".")[0], gab.split(".")[0]
    if a_base != g_base:
        return False
    a_sub, g_sub = ("." in assigned), ("." in gab)
    return (not g_sub and a_sub) or (g_sub and not a_sub)


def band(diff: int) -> str:
    return "fácil" if diff <= 5 else ("média" if diff <= 10 else "difícil")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Avaliação golden-set do pipeline (A3+A4)")
    ap.add_argument("--out", help="grava o JSON de resultados")
    ap.add_argument("--top-k", type=int, default=4)
    args = ap.parse_args(argv)

    gs = json.loads(GOLDEN.read_text(encoding="utf-8"))
    cases = gs["cases"]

    # 1) estágio RAG único: todos os 15 eventos numa "cadeia" (retrieval é por-evento)
    chain = {"entity": "golden_eval", "prior_chain_verdict": None, "events": [
        {"time": f"00:{i:02d}:00", "raw": c["raw"], "silver": c["silver"]}
        for i, c in enumerate(cases)]}
    with tempfile.NamedTemporaryFile("w", suffix=".chain.json", delete=False,
                                     encoding="utf-8") as tf:
        json.dump(chain, tf, ensure_ascii=False)
        chain_path = Path(tf.name)
    print(f"→ estágio RAG (subprocess mitre-rag): classificando {len(cases)} casos…")
    handoff = rag_candidates(chain_path, args.top_k)
    ev_by_idx = {e["index"]: e for e in handoff["events"]}

    agent = VerdictAgent()
    rows, gtokens = [], 0
    print(f"→ estágio veredito (Gemini): {len(cases)} chamadas independentes…\n")
    for i, c in enumerate(cases):
        gab = c["gabarito"]["id"]
        cand = ev_by_idx[i]["candidates"]
        cand_ids = [x["attack_id"] for x in cand]
        # recall do gabarito nos candidatos (aceita exata ou família pai↔sub)
        rank = next((j + 1 for j, cid in enumerate(cand_ids)
                     if cid == gab or acceptable(cid, gab)), None)
        recalled = rank is not None

        # veredito A4 do caso isolado (1 evento)
        single = {"entity": c["id"], "prior_chain_verdict": None,
                  "events": [ev_by_idx[i]]}
        res = agent.run(single)
        gtokens += res.usage.get("total_tokens", 0) or 0
        v = res.report.events[0]
        corrected = any("fora dos candidatos" in t for t in res.trace)
        rows.append({
            "id": c["id"], "difficulty": c["difficulty"], "band": band(c["difficulty"]),
            "gabarito": gab, "gab_name": c["gabarito"]["name"],
            "recalled": recalled, "recall_rank": rank,
            "assigned": v.attack_id, "assigned_name": v.technique_name,
            "confidence": v.confidence, "level": v.confidence_level.value,
            "strict": v.attack_id == gab, "accept": acceptable(v.attack_id, gab),
            "is_none": v.attack_id == "NONE", "grounding_corrected": corrected,
            "candidates": cand_ids,
        })

    # ---- métricas agregadas ----
    n = len(rows)
    recall = sum(r["recalled"] for r in rows)
    strict = sum(r["strict"] for r in rows)
    accept = sum(r["accept"] for r in rows)
    none = sum(r["is_none"] for r in rows)
    corr = sum(r["grounding_corrected"] for r in rows)
    by_band = {}
    for b in ("fácil", "média", "difícil"):
        br = [r for r in rows if r["band"] == b]
        by_band[b] = (sum(r["accept"] for r in br), len(br))

    # ---- impressão ----
    print(f"{'id':<4}{'dif':<4}{'gabarito':<12}{'recall':<9}{'atribuída':<12}"
          f"{'conf':<12}{'ok'}")
    print("-" * 68)
    for r in rows:
        rc = f"#{r['recall_rank']}" if r["recalled"] else "MISS"
        ok = "✔" if r["strict"] else ("~" if r["accept"] else "✗")
        conf = f"{r['confidence']:.2f} {r['level'][:3]}"
        print(f"{r['id']:<4}{r['difficulty']:<4}{r['gabarito']:<12}{rc:<9}"
              f"{r['assigned']:<12}{conf:<12}{ok}")
    print("-" * 68)
    print(f"A3 recall@candidatos : {recall}/{n} ({recall/n:.0%})")
    print(f"A4 acurácia estrita  : {strict}/{n} ({strict/n:.0%})")
    print(f"A4 acurácia família  : {accept}/{n} ({accept/n:.0%})  (aceita pai↔sub)")
    print(f"NONE-rate            : {none}/{n}   | correções grounding: {corr}/{n}")
    print("por dificuldade (acurácia família):  " +
          "  ".join(f"{b}={v[0]}/{v[1]}" for b, v in by_band.items()))
    print(f"tokens Gemini totais : {gtokens} (~{gtokens // max(n,1)}/caso)")
    print("legenda ok: ✔ exata | ~ família (pai/sub) | ✗ errada/NONE")

    if args.out:
        Path(args.out).write_text(json.dumps({
            "summary": {"n": n, "a3_recall": recall, "a4_strict": strict,
                        "a4_family": accept, "none_rate": none,
                        "grounding_corrections": corr, "gemini_tokens": gtokens,
                        "by_band": by_band},
            "rows": rows}, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n💾 resultados em {args.out}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
