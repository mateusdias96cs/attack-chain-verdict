"""
Avaliação de RECALL do Agente 3 no golden set — SEM Gemini (só retrieval).

Mede se a técnica-gabarito entra no conjunto de candidatos do `candidates()`.
Serve para A/B do índice (técnicas vs +procedures) sem gastar cota do A4.

Uso: ./.venv/bin/python eval_recall.py
"""
import json
from pathlib import Path

from agent import TechniqueClassifier, describe_silver_event

GOLDEN = Path(__file__).resolve().parent.parent / "verdict_agent" / "golden_set.json"


def acceptable(a: str, g: str) -> bool:
    if not a or a == "NONE":
        return False
    if a == g:
        return True
    ab, gb = a.split(".")[0], g.split(".")[0]
    if ab != gb:
        return False
    return ("." in a) != ("." in g)


def main():
    cases = json.loads(GOLDEN.read_text(encoding="utf-8"))["cases"]
    clf = TechniqueClassifier(pool=40)
    print(f"índice: {clf.technique_count} vetores\n")
    print(f"{'id':<4}{'dif':<4}{'gabarito':<12}{'recall':<9}{'#cand':<6}candidatos")
    print("-" * 90)
    hit = 0
    for c in cases:
        g = c["gabarito"]["id"]
        cands = clf.candidates(describe_silver_event(c["silver"]), top_k=4, e5_extra=6)
        ids = [m.attack_id for m in cands]
        rank = next((i + 1 for i, cid in enumerate(ids) if cid == g or acceptable(cid, g)), None)
        hit += rank is not None
        rc = f"#{rank}" if rank else "MISS"
        print(f"{c['id']:<4}{c['difficulty']:<4}{g:<12}{rc:<9}{len(ids):<6}{', '.join(ids[:9])}")
    print("-" * 90)
    print(f"A3 recall@candidatos: {hit}/{len(cases)} ({hit/len(cases):.0%})")


if __name__ == "__main__":
    main()
