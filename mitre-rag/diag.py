"""
Diagnóstico da regressão do Process Injection (T1055) sob reranking.

Para cada query-alvo, mostra:
  1) ranking do BI-ENCODER (e5) com scores de similaridade
  2) ranking do CROSS-ENCODER (reranker) com scores brutos
  3) onde o T1055 caiu, e QUAIS docs o cross-encoder promoveu acima dele
  4) o texto embeddado (nome+descrição) do T1055 vs. do competidor nº1

Rode:  ./.venv/bin/python diag.py
"""

from llama_index.core import VectorStoreIndex, Settings
from llama_index.vector_stores.chroma import ChromaVectorStore
import chromadb

from config import CHROMA_DIR, COLLECTION, get_embed_model, get_reranker

TARGET = "T1055"
POOL = 20
QUERIES = [
    ("PT", "injetar código malicioso em outro processo em execução"),
    ("EN", "inject malicious code into another running process"),
]


def aid(n):
    return n.metadata.get("attack_id", "")

def name(n):
    return n.metadata.get("name", "")

def short(txt, n=220):
    return " ".join(txt.split())[:n]


def main():
    Settings.embed_model = get_embed_model()
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    collection = client.get_collection(COLLECTION)
    index = VectorStoreIndex.from_vector_store(ChromaVectorStore(chroma_collection=collection))
    retriever = index.as_retriever(similarity_top_k=POOL)
    reranker = get_reranker(top_n=POOL)   # reranqueia TODOS para ver onde T1055 parou

    for lang, query in QUERIES:
        print("\n" + "=" * 78)
        print(f"[{lang}] QUERY: {query!r}")
        print("=" * 78)

        pool = retriever.retrieve(query)
        # IMPORTANTE: capturar score/ordem do e5 ANTES do rerank —
        # postprocess_nodes sobrescreve node.score in-place com o score do CE.
        e5_rank = {aid(n): i for i, n in enumerate(pool, 1)}
        e5_score = {aid(n): n.score for n in pool}
        e5_top10 = [(aid(n), name(n), n.score) for n in pool[:10]]
        text_by_id = {aid(n): n.get_content() for n in pool}

        reranked = reranker.postprocess_nodes(pool, query_str=query)

        print("\n--- 1) BI-ENCODER e5 (similaridade) — top 10 ---")
        for i, (a, nm, sc) in enumerate(e5_top10, 1):
            mark = "  <<< ALVO" if a == TARGET else ""
            print(f"  #{i:<2d} {sc:.3f}  {a:11s} {nm}{mark}")

        print("\n--- 2) CROSS-ENCODER reranker (score bruto) — top 10 ---")
        ce_rank = {aid(n): i for i, n in enumerate(reranked, 1)}
        for i, n in enumerate(reranked[:10], 1):
            mark = "  <<< ALVO" if aid(n) == TARGET else ""
            print(f"  #{i:<2d} {n.score:+.3f}  {aid(n):11s} {name(n)}{mark}")

        # 3) Onde o T1055 parou e quem passou na frente
        tgt_e5 = e5_rank.get(TARGET)
        tgt_ce = ce_rank.get(TARGET)
        tgt_ce_score = next((n.score for n in reranked if aid(n) == TARGET), None)
        print(f"\n--- 3) TRAJETÓRIA DO {TARGET} ---")
        print(f"  e5:    rank #{tgt_e5}  (sim={e5_score.get(TARGET):.3f})")
        print(f"  rerank rank #{tgt_ce}  (ce_score={tgt_ce_score:+.3f})")
        promoted = [n for n in reranked if ce_rank[aid(n)] < (tgt_ce or 99)]
        print(f"\n  Promovidos ACIMA do {TARGET} pelo cross-encoder:")
        for n in promoted:
            a = aid(n)
            print(f"    ce#{ce_rank[a]:<2d} ce={n.score:+.3f}  (era e5#{e5_rank.get(a,'?')})  {a:11s} {name(n)}")

        # 4) Texto embeddado: alvo vs competidor nº1
        top = reranked[0]
        print(f"\n--- 4) TEXTO EMBEDDADO (nome + descrição) ---")
        print(f"  ALVO {TARGET} — {name_by_id(text_by_id, TARGET)}")
        print(f"    {short(text_by_id.get(TARGET, '<não veio no pool>'))}")
        print(f"\n  COMPETIDOR ce#1 {aid(top)} — {name(top)}")
        print(f"    {short(top.get_content())}")


def name_by_id(text_by_id, tid):
    return "T1055" if tid in text_by_id else tid


if __name__ == "__main__":
    main()
