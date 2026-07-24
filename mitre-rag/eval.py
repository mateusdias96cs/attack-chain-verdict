"""
Avaliação de qualidade do retrieval — MITRE ATT&CK RAG (ChromaDB + e5 + reranker).

Compara DOIS pipelines nas MESMAS perguntas do golden set:
  • BASELINE : só busca vetorial (bi-encoder e5), top-k por similaridade.
  • RERANKED : busca vetorial traz um POOL, e o cross-encoder reordena → top-k.

Métricas-padrão de IR (relevância binária), complementares:
  Hit Rate@k · MRR · Recall@k · Precision@k · NDCG@k
(Precision@k é pouco informativa aqui pois quase toda pergunta tem 1 alvo.)

Extras: consistência PT/EN, self-retrieval (sanity) e checagem de rótulos.

Rode:  ./.venv/bin/python eval.py
"""

from __future__ import annotations

import math
import random
from collections import defaultdict

from llama_index.core import VectorStoreIndex, Settings
from llama_index.vector_stores.chroma import ChromaVectorStore
import chromadb

from config import CHROMA_DIR, COLLECTION, get_embed_model, get_reranker

CANDIDATE_POOL = 20           # candidatos que a busca vetorial entrega ao reranker
K_EVAL = 10                   # medimos as métricas até este corte
KS = [1, 3, 5, 10]            # cortes reportados

# -------------------------------------------------------------------------
# GOLDEN SET: cada conceito em PT e EN, com o(s) ATT&CK ID(s) correto(s) (v19.1).
# -------------------------------------------------------------------------
GOLDEN = [
    ("LSASS dump",      "despejar credenciais da memória do processo LSASS",        "PT", ["T1003.001"]),
    ("LSASS dump",      "dump credentials from LSASS process memory",               "EN", ["T1003.001"]),
    ("Phishing anexo",  "email de phishing com anexo malicioso",                    "PT", ["T1566.001"]),
    ("Phishing anexo",  "phishing email with a malicious attachment",               "EN", ["T1566.001"]),
    ("PowerShell",      "execução de comandos maliciosos via PowerShell",           "PT", ["T1059.001"]),
    ("PowerShell",      "execute malicious commands using PowerShell",              "EN", ["T1059.001"]),
    ("Scheduled task",  "persistência criando uma tarefa agendada no windows",      "PT", ["T1053.005"]),
    ("Scheduled task",  "persistence by creating a scheduled task on windows",      "EN", ["T1053.005"]),
    ("Ransomware",      "ransomware que criptografa arquivos para extorsão",        "PT", ["T1486"]),
    ("Ransomware",      "ransomware encrypting files for extortion",                "EN", ["T1486"]),
    ("RDP lateral",     "movimento lateral usando área de trabalho remota RDP",     "PT", ["T1021.001"]),
    ("RDP lateral",     "lateral movement using remote desktop protocol",           "EN", ["T1021.001"]),
    ("Run keys",        "persistência via chaves Run do registro do windows",       "PT", ["T1547.001"]),
    ("Run keys",        "persistence via windows registry run keys",                "EN", ["T1547.001"]),
    ("Disable AV",      "desabilitar ou modificar ferramentas de segurança e antivírus", "PT", ["T1685"]),
    ("Disable AV",      "disable or modify security tools and antivirus",           "EN", ["T1685"]),
    ("DNS C2",          "comunicação de comando e controle usando protocolo DNS",   "PT", ["T1071.004"]),
    ("DNS C2",          "command and control communication over the DNS protocol",  "EN", ["T1071.004"]),
    ("Keylogging",      "capturar as teclas digitadas com um keylogger",           "PT", ["T1056.001"]),
    ("Keylogging",      "capture keystrokes with a keylogger",                      "EN", ["T1056.001"]),
    ("Brute force",     "ataque de força bruta para adivinhar senhas",             "PT", ["T1110"]),
    ("Brute force",     "brute force attack to guess passwords",                    "EN", ["T1110"]),
    ("Valid accounts",  "uso de contas válidas comprometidas para obter acesso",    "PT", ["T1078"]),
    ("Valid accounts",  "using compromised valid accounts to gain access",         "EN", ["T1078"]),
    ("Ingress tool",    "baixar ferramentas adicionais de um servidor externo",     "PT", ["T1105"]),
    ("Ingress tool",    "download additional tools from an external server",        "EN", ["T1105"]),
    # 'T1055.*' expande p/ o pai + todas as sub-técnicas (query de nível-pai):
    # devolver Ptrace/Proc Memory/APC injection etc. é resposta CORRETA de process injection.
    ("Process inject",  "injetar código malicioso em outro processo em execução",   "PT", ["T1055.*"]),
    ("Process inject",  "inject malicious code into another running process",       "EN", ["T1055.*"]),
    ("Obfuscation",     "ofuscar ou codificar arquivos para evitar detecção",       "PT", ["T1027"]),
    ("Obfuscation",     "obfuscate or encode files to evade detection",             "EN", ["T1027"]),
    ("Cred dumping OS", "extrair credenciais do sistema operacional",               "PT", ["T1003.001", "T1003.002", "T1003.004"]),
    ("Cred dumping OS", "dump operating system credentials",                        "EN", ["T1003.001", "T1003.002", "T1003.004"]),
]


# -------------------------------------------------------------------------
# Métricas (definições padrão de IR; relevância binária)
# -------------------------------------------------------------------------
def reciprocal_rank(ranked, relevant):
    for i, r in enumerate(ranked, 1):
        if r in relevant:
            return 1.0 / i
    return 0.0

def hit_at_k(ranked, relevant, k):
    return 1.0 if any(r in relevant for r in ranked[:k]) else 0.0

def recall_at_k(ranked, relevant, k):
    return len(set(ranked[:k]) & relevant) / len(relevant) if relevant else 0.0

def precision_at_k(ranked, relevant, k):
    return len(set(ranked[:k]) & relevant) / k

def ndcg_at_k(ranked, relevant, k):
    dcg = sum(1.0 / math.log2(i + 1) for i, r in enumerate(ranked[:k], 1) if r in relevant)
    ideal = min(len(relevant), k)
    idcg = sum(1.0 / math.log2(i + 1) for i in range(1, ideal + 1))
    return dcg / idcg if idcg else 0.0

def rank_of_first(ranked, relevant):
    for i, r in enumerate(ranked, 1):
        if r in relevant:
            return i
    return None

def row_metrics(ranked, relevant):
    out = {"mrr": reciprocal_rank(ranked, relevant)}
    for k in KS:
        out[f"hit@{k}"] = hit_at_k(ranked, relevant, k)
        out[f"recall@{k}"] = recall_at_k(ranked, relevant, k)
        out[f"prec@{k}"] = precision_at_k(ranked, relevant, k)
        out[f"ndcg@{k}"] = ndcg_at_k(ranked, relevant, k)
    return out


# -------------------------------------------------------------------------
# Setup e helpers de retrieval
# -------------------------------------------------------------------------
def nodes_to_ids(nodes):
    """attack_ids ranqueados, deduplicados (1 técnica pode ter 2 chunks)."""
    ids, seen = [], set()
    for n in nodes:
        aid = n.metadata.get("attack_id", "")
        if aid and aid not in seen:
            seen.add(aid)
            ids.append(aid)
    return ids


def expand_relevant(rels, all_ids):
    """Expande curingas 'TXXXX.*' → pai + todas as sub-técnicas presentes no índice."""
    out = set()
    for r in rels:
        if r.endswith(".*"):
            parent = r[:-2]
            out.add(parent)
            out.update(a for a in all_ids if a.startswith(parent + "."))
        else:
            out.add(r)
    return out


def all_attack_ids(collection):
    return {md["attack_id"] for md in collection.get(include=["metadatas"])["metadatas"]
            if md.get("attack_id")}


def check_label_integrity(collection, all_ids):
    missing = {aid for _, _, _, rels in GOLDEN
               for aid in expand_relevant(rels, all_ids) if aid not in all_ids}
    if missing:
        raise SystemExit(f"❌ IDs do gabarito ausentes no índice: {sorted(missing)}")
    print(f"✔ Integridade OK: todos os IDs do gabarito existem ({len(all_ids)} técnicas).\n")


def self_retrieval_test(retriever, collection, n=15):
    metas = collection.get(include=["metadatas"])["metadatas"]
    named = [(m["attack_id"], m["name"]) for m in metas if m.get("attack_id") and m.get("name")]
    random.seed(42)
    sample = random.sample(named, min(n, len(named)))
    top1 = sum(1 for aid, name in sample if nodes_to_ids(retriever.retrieve(name))[:1] == [aid])
    print("── SELF-RETRIEVAL (nome da técnica → ela mesma) ──")
    print(f"   acerto @1: {top1}/{len(sample)} ({top1/len(sample):.0%})\n")


def summarize(name, store):
    n = len(store["mrr"])
    print(f"\n── {name}  (n={n}) ──")
    print(f"   MRR: {sum(store['mrr'])/n:.3f}")
    for k in KS:
        hr = sum(store[f'hit@{k}']) / n
        rc = sum(store[f'recall@{k}']) / n
        nd = sum(store[f'ndcg@{k}']) / n
        print(f"   @{k:<2d}  Hit={hr:.2f}  Recall={rc:.2f}  NDCG={nd:.2f}")


def compare(label, base, rr, key):
    b = sum(base[key]) / len(base[key])
    r = sum(rr[key]) / len(rr[key])
    d = r - b
    arrow = "▲" if d > 0.001 else ("▼" if d < -0.001 else "=")
    print(f"   {label:16s} {b:.3f} → {r:.3f}   {arrow} {d:+.3f}")


def main():
    print("=" * 66)
    print("AVALIAÇÃO DE RETRIEVAL — baseline (vetorial) vs reranked (cross-encoder)")
    print("=" * 66 + "\n")

    Settings.embed_model = get_embed_model()
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    collection = client.get_collection(COLLECTION)
    index = VectorStoreIndex.from_vector_store(ChromaVectorStore(chroma_collection=collection))
    retriever = index.as_retriever(similarity_top_k=CANDIDATE_POOL)
    reranker = get_reranker(top_n=K_EVAL)

    all_ids = all_attack_ids(collection)
    check_label_integrity(collection, all_ids)
    self_retrieval_test(retriever, collection)

    agg_b, agg_r = defaultdict(list), defaultdict(list)
    lang_b = defaultdict(lambda: defaultdict(list))
    lang_r = defaultdict(lambda: defaultdict(list))

    print("── POR PERGUNTA: rank do 1º acerto (baseline → reranked) ──")
    for concept, query, lang, rels in GOLDEN:
        relevant = expand_relevant(rels, all_ids)
        pool = retriever.retrieve(query)                       # 1º estágio
        base_ids = nodes_to_ids(pool)
        rr_ids = nodes_to_ids(reranker.postprocess_nodes(pool, query_str=query))  # 2º estágio

        for m, v in row_metrics(base_ids, relevant).items():
            agg_b[m].append(v); lang_b[lang][m].append(v)
        for m, v in row_metrics(rr_ids, relevant).items():
            agg_r[m].append(v); lang_r[lang][m].append(v)

        rb, rr = rank_of_first(base_ids, relevant), rank_of_first(rr_ids, relevant)
        fb = f"#{rb}" if rb else f">{K_EVAL}"
        fr = f"#{rr}" if rr else f">{K_EVAL}"
        moved = "▲" if (rr and rb and rr < rb) else ("▼" if (rr and rb and rr > rb) else "·")
        print(f"  [{lang}] {concept:14s} alvo={','.join(rels):27s} {fb:>4s} → {fr:>4s}  {moved}")

    print("\n" + "=" * 66)
    print(f"AGREGADO  ({len(GOLDEN)} perguntas)")
    print("=" * 66)
    print("\n### BASELINE (só vetorial)")
    summarize("GLOBAL", agg_b); summarize("PT", lang_b["PT"]); summarize("EN", lang_b["EN"])
    print("\n### RERANKED (vetorial + cross-encoder)")
    summarize("GLOBAL", agg_r); summarize("PT", lang_r["PT"]); summarize("EN", lang_r["EN"])

    print("\n" + "=" * 66)
    print("GANHO (baseline → reranked)")
    print("=" * 66)
    print(" GLOBAL:")
    for key in ["mrr", "hit@1", "hit@3", "ndcg@5", "recall@5"]:
        compare(key, agg_b, agg_r, key)
    print(" PT:")
    for key in ["mrr", "hit@1", "hit@3", "ndcg@5"]:
        compare(key, lang_b["PT"], lang_r["PT"], key)
    print(" EN:")
    for key in ["mrr", "hit@1", "hit@3", "ndcg@5"]:
        compare(key, lang_b["EN"], lang_r["EN"], key)


if __name__ == "__main__":
    main()
