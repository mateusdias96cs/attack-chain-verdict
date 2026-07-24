"""
Consulta semântica no índice MITRE ATT&CK (ChromaDB + embeddings locais).

Uso:
  ./.venv/bin/python query.py "roubo de credenciais na memoria do lsass"
  ./.venv/bin/python query.py "phishing com anexo" --k 5
  ./.venv/bin/python query.py "phishing com anexo" --no-rerank   # só busca vetorial

Pipeline de 2 estágios (padrão):
  1) busca vetorial e5 traz um POOL de candidatos (rápido, aproximado)
  2) cross-encoder REORDENA o pool e devolve os top-k (preciso)
Não usa LLM: é retrieval puro. Retorna as técnicas mais relevantes com metadados.
"""

import sys

import chromadb
from llama_index.core import VectorStoreIndex, Settings
from llama_index.vector_stores.chroma import ChromaVectorStore

from config import CHROMA_DIR, COLLECTION, get_embed_model, get_reranker

POOL = 20   # candidatos trazidos pela busca vetorial antes do rerank


def main() -> None:
    args = list(sys.argv[1:])
    k = 5
    rerank = True
    if "--no-rerank" in args:
        rerank = False
        args.remove("--no-rerank")
    if "--k" in args:
        i = args.index("--k")
        k = int(args[i + 1])
        del args[i:i + 2]
    query = " ".join(args).strip()
    if not query:
        print('Uso: python query.py "sua pergunta" [--k N] [--no-rerank]')
        sys.exit(1)

    # MESMO modelo/prefixos da ingestão (vem do config compartilhado)
    Settings.embed_model = get_embed_model()

    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    collection = client.get_collection(COLLECTION)
    vector_store = ChromaVectorStore(chroma_collection=collection)
    index = VectorStoreIndex.from_vector_store(vector_store)

    if rerank:
        # 1º estágio: pool amplo; 2º estágio: cross-encoder reordena para top-k
        nodes = index.as_retriever(similarity_top_k=POOL).retrieve(query)
        results = get_reranker(top_n=k).postprocess_nodes(nodes, query_str=query)
        modo = f"vetorial(top {POOL}) + rerank → top {k}"
    else:
        results = index.as_retriever(similarity_top_k=k).retrieve(query)
        modo = f"só vetorial → top {k}"

    print(f"\n🔎 Consulta: {query!r}   [{modo}]   ({collection.count()} técnicas)\n")
    for rank, node in enumerate(results, 1):
        m = node.metadata
        sub = " (subtécnica)" if m.get("is_subtechnique") else ""
        print(f"{rank}. [{node.score:.3f}] {m['attack_id']} — {m['name']}{sub}")
        print(f"     Táticas: {m.get('tactics') or 'N/A'} | Plataformas: {m.get('platforms') or 'N/A'}")
        print(f"     {m.get('url','')}")
        print()


if __name__ == "__main__":
    main()
