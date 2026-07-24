"""
RAG completo sobre MITRE ATT&CK — retrieval local + geração via LLM (Groq).

Pipeline de 3 estágios:
  1) RECUPERAR : e5 (bi-encoder) traz um pool de candidatos do ChromaDB
  2) REORDENAR : cross-encoder reranqueia o pool → top-k mais relevantes
  3) GERAR     : o LLM (Llama 3.3 70B) sintetiza a resposta ANCORADA nesse
                 contexto, citando os IDs ATT&CK. Sem contexto suficiente → diz.

Embedding e rerank são LOCAIS; só a geração usa nuvem (Groq).

Uso:
  ./.venv/bin/python ask.py "como um atacante rouba credenciais no windows?"
  ./.venv/bin/python ask.py "how to persist via scheduled tasks?" --k 6
"""

import sys

import chromadb
from llama_index.core import VectorStoreIndex, Settings
from llama_index.core.llms import ChatMessage
from llama_index.core.schema import MetadataMode
from llama_index.vector_stores.chroma import ChromaVectorStore

from config import CHROMA_DIR, COLLECTION, get_embed_model, get_reranker, get_llm

POOL = 20   # candidatos do 1º estágio

SYSTEM_PROMPT = (
    "You are a MITRE ATT&CK expert analyst answering a security question via RAG.\n"
    "STRICT RULES:\n"
    "1. Use ONLY the techniques provided in CONTEXT. Do NOT add outside knowledge, "
    "generic security advice, or recommendations that are not grounded in the CONTEXT.\n"
    "2. Whenever you reference a technique, cite its ATT&CK ID (e.g. T1003.001) and name.\n"
    "3. If the CONTEXT is insufficient to answer, say so explicitly and do not invent.\n"
    "4. LANGUAGE: write your ENTIRE answer in the SAME language as the user's QUESTION "
    "(question in English -> answer in English; pergunta em português -> responda em português). "
    "Ignore the language of the CONTEXT for this decision.\n"
    "Be technical and concise."
)


def build_context(nodes) -> str:
    """Monta o bloco de CONTEXTO que vai ao LLM, a partir dos nós recuperados."""
    blocks = []
    for i, n in enumerate(nodes, 1):
        m = n.metadata
        blocks.append(
            f"[FONTE {i}] {m.get('attack_id','?')} — {m.get('name','?')}\n"
            f"Táticas: {m.get('tactics') or 'N/A'} | Plataformas: {m.get('platforms') or 'N/A'}\n"
            f"URL: {m.get('url','')}\n"
            f"Descrição: {n.get_content(metadata_mode=MetadataMode.NONE)}"
        )
    return "\n\n".join(blocks)


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
    question = " ".join(args).strip()
    if not question:
        print('Uso: python ask.py "sua pergunta" [--k N] [--no-rerank]')
        sys.exit(1)

    Settings.embed_model = get_embed_model()
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    collection = client.get_collection(COLLECTION)
    index = VectorStoreIndex.from_vector_store(ChromaVectorStore(chroma_collection=collection))

    # 1) recuperar  2) reordenar
    if rerank:
        pool = index.as_retriever(similarity_top_k=POOL).retrieve(question)
        nodes = get_reranker(top_n=k).postprocess_nodes(pool, query_str=question)
    else:
        nodes = index.as_retriever(similarity_top_k=k).retrieve(question)

    # 3) gerar
    context = build_context(nodes)
    llm = get_llm()
    messages = [
        ChatMessage(role="system", content=SYSTEM_PROMPT),
        ChatMessage(role="user", content=f"CONTEXTO:\n{context}\n\nPERGUNTA: {question}"),
    ]
    print(f"\n🤖 Perguntando ao LLM com {len(nodes)} técnicas de contexto...\n")
    resp = llm.chat(messages)
    answer = resp.message.content

    print("═" * 70)
    print("RESPOSTA")
    print("═" * 70)
    print(answer.strip())
    print("\n" + "─" * 70)
    print("FONTES USADAS (contexto recuperado, ancoragem):")
    for i, n in enumerate(nodes, 1):
        m = n.metadata
        print(f"  {i}. {m.get('attack_id','?')} — {m.get('name','?')}  ({m.get('url','')})")


if __name__ == "__main__":
    main()
