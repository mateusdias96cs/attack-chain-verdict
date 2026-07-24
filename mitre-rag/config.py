"""
Configuração compartilhada do pipeline RAG MITRE ATT&CK.

Centraliza modelo de embedding, caminhos e a coleção para que INGESTÃO e
CONSULTA usem SEMPRE o mesmo modelo/prefixos. (Indexar com um modelo e
consultar com outro = resultados sem sentido — este módulo evita esse bug.)
"""

import os
from pathlib import Path

from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.core.postprocessor import SentenceTransformerRerank

# --- Caminhos e coleção ---------------------------------------------------
HERE = Path(__file__).parent
SRC = HERE.parent / "enterprise-attack-stix" / "enterprise-attack-clean.json"
CHROMA_DIR = HERE / "chroma_db"
COLLECTION = "mitre_attack_techniques"

# --- Modelo de embedding --------------------------------------------------
# multilingual-e5-small: 384-dim, otimizado para RETRIEVAL, forte em EN e PT.
# Exige prefixos: documentos -> "passage: ", perguntas -> "query: ".
EMBED_MODEL = "intfloat/multilingual-e5-small"
E5_QUERY_PREFIX = "query: "
E5_PASSAGE_PREFIX = "passage: "


def get_embed_model() -> HuggingFaceEmbedding:
    """Instancia o embedder com os prefixos e5 aplicados automaticamente.

    O HuggingFaceEmbedding prepende `text_instruction` a cada documento e
    `query_instruction` a cada consulta — então nunca esquecemos o prefixo.
    """
    return HuggingFaceEmbedding(
        model_name=EMBED_MODEL,
        text_instruction=E5_PASSAGE_PREFIX,
        query_instruction=E5_QUERY_PREFIX,
    )


# --- Reranker (cross-encoder, 2º estágio) ---------------------------------
# mmarco-mMiniLMv2: cross-encoder multilíngue (treinado no mMARCO, inclui PT),
# leve (~470 MB) e CPU-friendly. Upgrade de maior teto: "BAAI/bge-reranker-v2-m3"
# (mais forte, porém ~2.3 GB).
RERANK_MODEL = "cross-encoder/mmarco-mMiniLMv2-L12-H384-v1"


def get_reranker(top_n: int) -> SentenceTransformerRerank:
    """Cross-encoder que reordena os candidatos do 1º estágio, mantendo top_n.

    Diferente do embedder (bi-encoder, que vetoriza pergunta e documento
    separadamente), o cross-encoder recebe o PAR (pergunta, candidato) e pontua
    a relevância conjunta — mais preciso, por isso rodamos só sobre o pool.
    """
    return SentenceTransformerRerank(model=RERANK_MODEL, top_n=top_n)


# --- LLM gerador (3º estágio: síntese da resposta) ------------------------
# Groq serve Llama 3.3 70B com latência muito baixa. Único componente em nuvem
# do pipeline (embedding e rerank são locais). Chave via env GROQ_API_KEY.
LLM_MODEL = "llama-3.3-70b-versatile"


def load_env_file() -> None:
    """Carrega mitre-rag/../.env (KEY=VALUE) para o ambiente, se existir.

    Fallback simples sem dependência: só define chaves ainda não presentes.
    """
    env_path = HERE.parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def get_llm():
    """LLM Groq para síntese. Erro claro se faltar a chave."""
    from llama_index.llms.groq import Groq  # import tardio (dep opcional)

    load_env_file()
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise SystemExit(
            "❌ GROQ_API_KEY não encontrada. Defina no ambiente ou em mitre-rag/.env\n"
            "   (gere em https://console.groq.com/keys)"
        )
    # temperature baixa: resposta factual e ancorada no contexto, não criativa.
    return Groq(model=LLM_MODEL, api_key=api_key, temperature=0.1)
