"""
Estágio 3 do teste E2E (roda no venv do mitre-rag).

Lê o handoff produzido pelos agentes 1 e 2 (JSON), classifica cada descrição na
técnica ATT&CK e escreve os resultados. Falhas NÃO são engolidas: exceção propaga
(exit != 0) e resultados vazios são marcados explicitamente com erro.

Uso:  ./.venv/bin/python e2e_stage3.py <handoff.json> <out.json>
"""
import json
import sys

from agent import TechniqueClassifier, describe_chain, describe_silver_event


def main() -> int:
    handoff_path, out_path = sys.argv[1], sys.argv[2]
    handoff = json.loads(open(handoff_path, encoding="utf-8").read())

    clf = TechniqueClassifier()
    result = {"technique_count": clf.technique_count, "events": [], "chain": None}

    for item in handoff["events"]:
        desc = describe_silver_event(item["silver"])
        if not desc or len(desc) < 20:
            raise ValueError(f"descrição vazia/curta para evento {item['label']!r}: {desc!r}")
        matches = clf.classify(desc, top_k=3)
        if not matches:
            raise ValueError(f"retrieval retornou VAZIO para {item['label']!r} — quebra silenciosa")
        result["events"].append({
            "label": item["label"],
            "expect_family": item.get("expect_family"),
            "description": desc,
            "top3": [{"id": m.attack_id, "name": m.name, "score": m.score} for m in matches],
        })

    steps = handoff.get("chain") or []
    if steps:
        cdesc = describe_chain(steps)
        cmatches = clf.classify(cdesc, top_k=3)
        if not cmatches:
            raise ValueError("retrieval da cadeia retornou VAZIO — quebra silenciosa")
        result["chain"] = {
            "n_steps": len(steps),
            "description_head": cdesc[:200],
            "top3": [{"id": m.attack_id, "name": m.name, "score": m.score} for m in cmatches],
        }

    open(out_path, "w", encoding="utf-8").write(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"stage3 OK: {len(result['events'])} eventos + "
          f"{'1 cadeia' if result['chain'] else '0 cadeia'} classificados")
    return 0


if __name__ == "__main__":
    sys.exit(main())
