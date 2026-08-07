"""
Ponte Agente 2/3 → Agente 4 (roda no venv do mitre-rag, que tem torch/e5).

Lê uma CADEIA (saída do agente de correlação temporal) e, para CADA evento, usa o
classificador RAG (e5; cross-encoder desligado, ver DEFAULT_USE_RERANKER em agent.py)
para recuperar os top-k candidatos ATT&CK.
Emite o HANDOFF-DE-VEREDITO que o Agente 4 (Gemini) consome para decidir, por evento,
qual técnica realmente se aplica.

Este script é o "estágio de candidatos": retrieval puro e determinístico, 0 tokens de
nuvem. A arbitragem/decisão fica no Agente 4.

Uso:  ./.venv/bin/python rag_candidates.py <chain.json> <handoff.json> [top_k]

Formato de entrada (chain.json):
    {
      "entity": "SCRANTON/pbeesly",
      "prior_chain_verdict": {...} | null,
      "events": [
        {"time": "02:55:56", "raw": "<linha compacta>",
         "silver": {<registro silver do agente 1>} | null,
         "description": "<NL já pronta>" | null},
        ...
      ]
    }
"""
import json
import sys

from agent import TechniqueClassifier, describe_silver_event


def _describe(ev: dict) -> str:
    """Escolhe a melhor descrição NL disponível para o evento."""
    if ev.get("description"):
        return str(ev["description"]).strip()
    if ev.get("silver"):
        return describe_silver_event(ev["silver"])
    return str(ev.get("raw") or "").strip()


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    chain_path, out_path = sys.argv[1], sys.argv[2]
    top_k = int(sys.argv[3]) if len(sys.argv) > 3 else 4

    chain = json.loads(open(chain_path, encoding="utf-8").read())
    events = chain.get("events") or []
    if not events:
        raise ValueError(f"cadeia sem 'events' em {chain_path!r}")

    # pool maior: com procedure examples cada técnica tem vários chunks; um pool amplo
    # garante técnicas DISTINTAS suficientes após o dedup do candidates().
    clf = TechniqueClassifier(pool=40)
    out_events = []
    for i, ev in enumerate(events):
        desc = _describe(ev)
        if not desc or len(desc) < 10:
            raise ValueError(f"descrição vazia/curta no evento {i}: {desc!r}")
        # UNION técnica ∪ procedure: cobertura abstrata + concreta, dedup por attack_id.
        matches = clf.candidates(desc, top_k=top_k, e5_extra=6)
        if not matches:
            raise ValueError(f"retrieval VAZIO no evento {i} — quebra silenciosa")
        out_events.append({
            "index": i,
            "time": ev.get("time", ""),
            "raw": ev.get("raw", ""),
            "description": desc,
            "candidates": [
                {"attack_id": m.attack_id, "name": m.name, "score": round(m.score, 4),
                 "tactics": m.tactics, "is_subtechnique": m.is_subtechnique}
                for m in matches
            ],
        })

    handoff = {
        "entity": chain.get("entity", "?"),
        "prior_chain_verdict": chain.get("prior_chain_verdict"),
        "technique_count": clf.technique_count,
        "events": out_events,
    }
    open(out_path, "w", encoding="utf-8").write(
        json.dumps(handoff, ensure_ascii=False, indent=2))
    print(f"candidatos OK: {len(out_events)} eventos, top_k={top_k} "
          f"(índice: {clf.technique_count} técnicas) → {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
