"""
Ingestão do MITRE ATT&CK (dados limpos v19.1) para um índice vetorial local.

Fluxo:
  enterprise-attack-clean.json
      -> extrai técnicas ATIVAS (attack-pattern)  → 1 Document (nome + descrição)
      -> [padrão] extrai PROCEDURE EXAMPLES (relações 'uses' → técnica, com descrição)
         → 1 Document por exemplo, apontando para a técnica-pai via metadados
      -> embeddings LOCAIS e5-small
      -> grava no ChromaDB persistente (pasta ./chroma_db)

Por que procedure examples? A descrição da técnica é PROSA ABSTRATA; a consulta que
vem dos agentes costuma ser um COMANDO/observação concreta. Os procedure examples são
descrições concretas de "como um grupo/software usou a técnica" — aproximam o índice
da linguagem da consulta e fecham o gap de recall (net/rar/sdelete etc.). A busca
dedup por attack_id (no agente), então N chunks de uma técnica colapsam em 1 candidato.

Rode:  ./.venv/bin/python ingest.py            # técnicas + procedures (padrão)
       ./.venv/bin/python ingest.py --no-procedures   # só técnicas (índice antigo)
"""

import argparse
import json
import re

import chromadb
from llama_index.core import Document, Settings, StorageContext, VectorStoreIndex
from llama_index.vector_stores.chroma import ChromaVectorStore

from config import (CHROMA_DIR, COLLECTION, EMBED_MODEL, SRC, get_embed_model,
                    get_node_parser)

_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")   # [anchor](url) -> anchor
_CITE = re.compile(r"\(Citation:[^)]*\)")       # (Citation: ...) -> ''


def clean_procedure(text: str) -> str:
    """Remove markup de citação/links do procedure example (ruído p/ o embedding)."""
    text = _LINK.sub(r"\1", text)
    text = _CITE.sub("", text)
    return " ".join(text.split())


def _technique_meta(o: dict, tactic_name: dict) -> tuple[str, dict]:
    """Extrai (attack_id, metadados) de um attack-pattern."""
    attack_id, url = None, None
    for ref in o.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            attack_id, url = ref.get("external_id"), ref.get("url")
            break
    tactics = [tactic_name.get(p["phase_name"], p["phase_name"])
               for p in o.get("kill_chain_phases", [])
               if p.get("kill_chain_name") == "mitre-attack"]
    meta = {
        "attack_id": attack_id or "",
        "name": o["name"],
        "tactics": ", ".join(tactics),
        "platforms": ", ".join(o.get("x_mitre_platforms", [])),
        "is_subtechnique": bool(o.get("x_mitre_is_subtechnique")),
        "version": o.get("x_mitre_version", ""),
        "url": url or "",
    }
    return attack_id or o["id"], meta


def load_documents(with_procedures: bool = True) -> tuple[list[Document], int, int]:
    """Devolve (documents, n_técnicas, n_procedures)."""
    bundle = json.loads(SRC.read_text(encoding="utf-8"))
    objects = bundle["objects"]
    tactic_name = {o["x_mitre_shortname"]: o["name"]
                   for o in objects if o["type"] == "x-mitre-tactic"}

    # técnicas ativas: stix_id -> (attack_id, meta)
    active: dict[str, tuple[str, dict]] = {}
    for o in objects:
        if o["type"] != "attack-pattern":
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        active[o["id"]] = _technique_meta(o, tactic_name)

    docs: list[Document] = []
    # 1) 1 Document por técnica (nome + descrição) — o sinal ABSTRATO
    for o in objects:
        if o["type"] != "attack-pattern" or o["id"] not in active:
            continue
        doc_id, meta = active[o["id"]]
        meta = {**meta, "doc_type": "technique"}
        docs.append(Document(text=f"{o['name']}\n\n{o.get('description', '')}",
                             metadata=meta, doc_id=doc_id))
    n_tech = len(docs)

    # 2) procedure examples (relações 'uses' -> técnica ativa, com descrição) — CONCRETO
    n_proc = 0
    if with_procedures:
        for o in objects:
            if o.get("type") != "relationship" or o.get("relationship_type") != "uses":
                continue
            tgt = o.get("target_ref", "")
            desc = o.get("description")
            if not desc or tgt not in active:
                continue
            _, tmeta = active[tgt]
            text = clean_procedure(desc)
            if len(text) < 20:
                continue
            docs.append(Document(
                text=text,
                metadata={**tmeta, "doc_type": "procedure"},
                doc_id=f"proc::{o['id']}",   # id estável e único (não colide c/ técnica)
            ))
            n_proc += 1
    return docs, n_tech, n_proc


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-procedures", action="store_true",
                    help="indexa só as técnicas (nome+descrição), como o índice antigo")
    args = ap.parse_args()
    with_proc = not args.no_procedures

    print(f"[1/4] Lendo {SRC.name} (procedures={'sim' if with_proc else 'não'}) ...")
    docs, n_tech, n_proc = load_documents(with_procedures=with_proc)
    print(f"      {n_tech} técnicas + {n_proc} procedure examples = {len(docs)} documentos.")

    print(f"[2/4] Carregando modelo de embedding local: {EMBED_MODEL}")
    Settings.embed_model = get_embed_model()
    # O parser vai EXPLÍCITO em from_documents(transformations=...): Settings.transformations
    # é resolvido na primeira leitura e fica em cache, então mexer em Settings.node_parser
    # depois disso pode não propagar. Passar direto elimina a ambiguidade.
    node_parser = get_node_parser()

    print(f"[3/4] Abrindo ChromaDB persistente em {CHROMA_DIR}/")
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    try:
        client.delete_collection(COLLECTION)
        print(f"      coleção '{COLLECTION}' anterior removida (re-indexação limpa)")
    except Exception:
        pass
    client.create_collection(COLLECTION)
    vector_store = ChromaVectorStore(chroma_collection=client.get_collection(COLLECTION))
    storage = StorageContext.from_defaults(vector_store=vector_store)

    print(f"[4/4] Gerando embeddings de {len(docs)} docs e gravando (CPU, pode levar alguns min)...")
    VectorStoreIndex.from_documents(docs, storage_context=storage,
                                    transformations=[node_parser], show_progress=True)

    total = client.get_collection(COLLECTION).count()
    print(f"\n✅ Concluído. {total} vetores na coleção '{COLLECTION}' "
          f"({n_tech} técnicas + {n_proc} procedures, {total - len(docs)} chunks extras "
          f"de documentos longos).")


if __name__ == "__main__":
    main()
