"""
Agente 3 — Classificador RAG de técnica MITRE ATT&CK.

Recebe uma DESCRIÇÃO textual de um evento (ou cadeia de eventos) — que pode vir do
agente de parsing (silver) ou do agente de correlação temporal — vetoriza com o
MESMO modelo que indexou o ChromaDB (e5-small, 384-dim) e devolve a(s) técnica(s)
ATT&CK mais parecidas semanticamente.

IMPORTANTE (constraint técnica): a vetorização da CONSULTA usa e5-small, não o Groq.
Retrieval só funciona se query e documentos forem embeddados pelo MESMO modelo — e o
índice foi construído com e5. O Groq (llama-3.3-70b) é usado nos agentes 1/2 para
inferência de linguagem, mas NÃO produz embeddings; aqui ele seria opcional só para
uma explicação/síntese em cima do resultado do retrieval (não implementado neste
agente, que é retrieval puro e determinístico).

Pipeline de 2 estágios (igual ao query.py, encapsulado como agente reutilizável):
  1) busca vetorial e5 → POOL de candidatos
  2) cross-encoder reordena → top-k
"""
from __future__ import annotations

from dataclasses import dataclass

import chromadb
from llama_index.core import Settings, VectorStoreIndex
from llama_index.vector_stores.chroma import ChromaVectorStore

from config import CHROMA_DIR, COLLECTION, get_embed_model, get_reranker

DEFAULT_POOL = 20      # candidatos do 1º estágio antes do rerank
DEFAULT_TOP_K = 3      # "as duas, três técnicas mais prováveis"


@dataclass
class TechniqueMatch:
    attack_id: str
    name: str
    score: float
    tactics: str
    platforms: str
    is_subtechnique: bool
    url: str

    def __str__(self) -> str:
        sub = " (subtécnica)" if self.is_subtechnique else ""
        return f"[{self.score:.3f}] {self.attack_id} — {self.name}{sub}"


class TechniqueClassifier:
    """Carrega e5 + reranker + índice UMA vez; reusa em cada classify()."""

    def __init__(self, pool: int = DEFAULT_POOL, use_reranker: bool = True):
        self.pool = pool
        self.use_reranker = use_reranker
        Settings.embed_model = get_embed_model()
        client = chromadb.PersistentClient(path=str(CHROMA_DIR))
        self._collection = client.get_collection(COLLECTION)
        self._index = VectorStoreIndex.from_vector_store(
            ChromaVectorStore(chroma_collection=self._collection))
        self._retriever = self._index.as_retriever(similarity_top_k=pool)
        # reranker é caro de instanciar; guarda por top_n mais usado
        self._reranker_cache: dict[int, object] = {}

    @property
    def technique_count(self) -> int:
        return self._collection.count()

    def _rerank(self, nodes, query: str, top_k: int):
        rr = self._reranker_cache.get(top_k)
        if rr is None:
            rr = get_reranker(top_n=top_k)
            self._reranker_cache[top_k] = rr
        return rr.postprocess_nodes(nodes, query_str=query)

    def classify(self, description: str, top_k: int = DEFAULT_TOP_K) -> list[TechniqueMatch]:
        """Descrição de evento/cadeia → top_k técnicas ATT&CK mais prováveis."""
        description = (description or "").strip()
        if not description:
            return []
        # classify() é o retrieval "puro" (query.py/ask.py/testes): filtra para docs de
        # TÉCNICA (nome+descrição) → comportamento estável, idêntico ao índice antigo.
        # Os procedure examples enriquecem só o candidates() (caminho do pipeline).
        k = self.pool if self.use_reranker else max(top_k, 1)
        nodes = self._retrieve(description, k, doc_type="technique")
        if not nodes:                                    # índice sem doc_type → fallback
            nodes = self._retrieve(description, k)
        if self.use_reranker:
            nodes = self._rerank(nodes, description, top_k)

        # dedup por attack_id (uma técnica pode ter >1 chunk), preserva a ordem
        out: list[TechniqueMatch] = []
        seen: set[str] = set()
        for n in nodes:
            m = n.metadata
            aid = m.get("attack_id", "")
            if not aid or aid in seen:
                continue
            seen.add(aid)
            out.append(TechniqueMatch(
                attack_id=aid, name=m.get("name", ""), score=float(n.score or 0.0),
                tactics=m.get("tactics", ""), platforms=m.get("platforms", ""),
                is_subtechnique=bool(m.get("is_subtechnique")), url=m.get("url", ""),
            ))
            if len(out) >= top_k:
                break
        return out

    def _retrieve(self, description: str, k: int, doc_type: str | None = None):
        """Recupera k nós; opcionalmente filtrando por doc_type (technique/procedure)."""
        if doc_type is None:
            return self._index.as_retriever(similarity_top_k=k).retrieve(description)
        from llama_index.core.vector_stores import (FilterOperator, MetadataFilter,
                                                    MetadataFilters)
        filters = MetadataFilters(filters=[
            MetadataFilter(key="doc_type", value=doc_type, operator=FilterOperator.EQ)])
        return self._index.as_retriever(similarity_top_k=k, filters=filters).retrieve(description)

    @staticmethod
    def _distinct(nodes):
        """dedup por attack_id preservando ordem; devolve (aid, meta, score) por técnica."""
        out, seen = [], set()
        for n in nodes:
            aid = n.metadata.get("attack_id", "")
            if aid and aid not in seen:
                seen.add(aid)
                out.append((aid, n.metadata, float(n.score or 0.0)))
        return out

    def candidates(self, description: str, top_k: int = DEFAULT_TOP_K,
                   e5_extra: int = 3, max_total: int = 10) -> list[TechniqueMatch]:
        """Candidatos para ARBITRAGEM (Agente 4) por RECUPERAÇÃO DUPLA + union.

        O índice tem dois tipos de doc: `technique` (nome+descrição, sinal ABSTRATO) e
        `procedure` (exemplos concretos "grupo/software usou a técnica assim"). Recuperar
        do pool misto deixava os 16,9k procedures INUNDAREM o pool e expulsarem o match
        abstrato forte (regressão medida em C2/rede). Então recuperamos SEPARADO e unimos:

          - técnica-filtrado  → preserva o recall abstrato (equivalente ao índice antigo)
          - procedure-filtrado → adiciona cobertura concreta (ex.: net→"enumerate domain accounts")
          - rerank sobre a união → precisão nos primeiros slots

        Assim procedure só SOMA recall, nunca subtrai. Dedup por attack_id (uma técnica
        tem N chunks). e5-score capturado ANTES do rerank (postprocess sobrescreve in-place).
        """
        description = (description or "").strip()
        if not description:
            return []

        tech_nodes = self._retrieve(description, self.pool, doc_type="technique")
        if not tech_nodes:   # índice antigo sem doc_type → fallback sem filtro
            tech_nodes = self._retrieve(description, self.pool)
        proc_nodes = self._retrieve(description, self.pool, doc_type="procedure")

        e5_tech = self._distinct(tech_nodes)
        e5_proc = self._distinct(proc_nodes)

        # rerank sobre a união dos nós (precisão conjunta técnica+procedure)
        pool = list(tech_nodes) + list(proc_nodes)
        if self.use_reranker and pool:
            reranked = self._rerank(pool, description, min(len(pool), max(top_k * 3, 12)))
        else:
            reranked = pool
        rr = self._distinct(reranked)

        out: list[TechniqueMatch] = []
        seen: set[str] = set()

        def _add(item):
            aid, meta, score = item
            if not aid or aid in seen or len(out) >= max_total:
                return
            seen.add(aid)
            out.append(TechniqueMatch(
                attack_id=aid, name=meta.get("name", ""), score=score,
                tactics=meta.get("tactics", ""), platforms=meta.get("platforms", ""),
                is_subtechnique=bool(meta.get("is_subtechnique")), url=meta.get("url", "")))

        # UNION: rerank (precisão) ∪ e5 técnica (recall abstrato) ∪ e5 procedure (concreto)
        for it in rr[:top_k]:
            _add(it)
        for it in e5_tech[:e5_extra]:
            _add(it)
        for it in e5_proc[:e5_extra]:
            _add(it)
        return out


# --------------------------------------------------------------------------
# Adaptadores: transformam a saída dos agentes 1/2 numa descrição em linguagem
# natural (o índice foi embeddado sobre nome+descrição das técnicas, então texto
# comportamental recupera melhor que campos crus de telemetria).
# --------------------------------------------------------------------------
_CATEGORY_PHRASE = {
    "process_create": "a new process was created",
    "network_connect": "a process made an outbound network connection",
    "network_bind": "a process bound to a local network port",
    "dns_query": "a process performed a DNS query",
    "image_load": "a module/DLL was loaded into a process",
    "create_remote_thread": "a process created a remote thread in another process",
    "process_access": "a process opened/accessed another process's memory",
    "file_create": "a file was created on disk",
    "file_delete": "a file was deleted from disk",
    "registry_set_value": "a registry value was set",
    "registry_create_delete": "a registry key was created or deleted",
    "powershell_pipeline": "PowerShell executed a command pipeline",
    "powershell_module": "PowerShell module logging recorded execution",
    "powershell_script_block": "PowerShell executed a script block",
    "logon": "an account successfully logged on",
    "logon_failure": "an account failed to log on",
    "object_access": "an object (file/registry/process) was accessed",
}


# fallback event_id → categoria (o silver do Agente 1 não carrega event_category;
# essa é uma coluna da Gold do Agente 2 — então derivamos aqui quando ausente)
_EVENT_ID_CATEGORY = {
    1: "process_create", 3: "network_connect", 7: "image_load", 8: "create_remote_thread",
    10: "process_access", 11: "file_create", 12: "registry_create_delete",
    13: "registry_set_value", 22: "dns_query", 23: "file_delete",
    4688: "process_create", 4624: "logon", 4625: "logon_failure",
    4663: "object_access", 4656: "object_access", 5156: "network_connect",
    800: "powershell_pipeline", 4103: "powershell_module", 4104: "powershell_script_block",
}


# Tools conhecidos (interpretadores/LOLBins/utilitários) → prosa COMPORTAMENTAL. Sem isto o
# adaptador emite só "Executable: cmd.exe" e o e5 (indexado sobre descrições de técnica)
# NÃO recupera a técnica canônica — é a ponte binário→comportamento (surface-form gap).
# Chave = nome-base do binário; famílias mapeiam ao MESMO comportamento (generalizável,
# não é hardcode de técnica). Ver eval em [[agent-eval-golden]].
_INTERPRETERS = {
    # interpretadores de comando/script → Command and Scripting Interpreter
    "cmd.exe": "the native Windows command-line shell interpreter (cmd.exe), used to "
               "execute commands, batch scripts and spawn other programs",
    "powershell.exe": "the PowerShell command and scripting interpreter, used to execute "
                      "commands and scripts on the host",
    "pwsh.exe": "the PowerShell (Core) command and scripting interpreter",
    "wscript.exe": "the Windows Script Host (wscript) used to execute VBScript/JScript scripts",
    "cscript.exe": "the Windows Script Host (cscript) used to execute scripts from the console",
    # system binary proxy execution (LOLBins)
    "mshta.exe": "mshta.exe, a signed Windows binary abused to proxy execution of HTA/script content",
    "rundll32.exe": "rundll32.exe, a signed Windows binary abused to proxy execution of DLL code",
    "regsvr32.exe": "regsvr32.exe, a signed Windows binary abused to proxy execution of code",
    "certutil.exe": "certutil.exe, a living-off-the-land binary abused to download or decode files",
    # arquivadores → Archive Collected Data (compress/encrypt files for exfiltration)
    "rar.exe": "the RAR archiving utility, used to compress and encrypt collected files "
               "into an archive to stage data for exfiltration",
    "winrar.exe": "the WinRAR archiving utility, used to compress and encrypt collected "
                  "files into an archive to stage data for exfiltration",
    "7z.exe": "the 7-Zip archiving utility, used to compress and encrypt collected data "
              "into an archive to stage it for exfiltration",
    "7za.exe": "the 7-Zip archiving utility, used to compress and encrypt collected data "
               "into an archive to stage it for exfiltration",
    # secure deletion / indicator removal → File Deletion
    "sdelete.exe": "the Sysinternals SDelete utility, used to securely delete and wipe "
                   "files from disk to remove evidence and indicators of compromise",
    "sdelete64.exe": "the Sysinternals SDelete utility, used to securely delete and wipe "
                     "files from disk to remove evidence and indicators of compromise",
    # network utilities → Account/Network discovery (o verbo específico refina no rerank)
    "net.exe": "the Windows net utility, used to enumerate accounts, groups, shares and "
               "network resources on the host or domain",
    "net1.exe": "the Windows net1 utility, used to enumerate accounts, groups and network "
                "resources on the host or domain",
}


def _masquerade_notes(image: str | None, cmdline: str | None) -> list[str]:
    """Verbaliza sinais de MASCARAMENTO presentes no nome/linha de comando."""
    text = f"{image or ''} {cmdline or ''}"
    low = (image or "").lower()
    notes: list[str] = []
    if "\u202e" in text:   # right-to-left override (U+202E)
        notes.append(
            "The filename contains a right-to-left override (RTLO) control character "
            "that disguises the file's true name and extension to masquerade a malicious "
            "executable as a benign file.")
    if low.endswith(".scr") or ".scr " in f"{low} " or ".scr\"" in low:
        notes.append(
            "The program uses a Windows screensaver (.scr) extension, an executable file "
            "type used to disguise a malicious binary and evade defenses through masquerading.")
    return notes


def describe_silver_event(ev: dict) -> str:
    """Descrição NL a partir de um registro silver (saída do agente de parsing)."""
    cat = (ev.get("event_category")
           or _EVENT_ID_CATEGORY.get(ev.get("event_id"))
           or ev.get("log_source") or "an event")
    phrase = _CATEGORY_PHRASE.get(cat, f"a {cat} event occurred")
    bits = [phrase + "."]
    # Enriquecimento comportamental (interpretador/mascaramento) só vale quando o SUJEITO
    # do evento é o processo/arquivo. Num network_connect o sujeito é a CONEXÃO; injetar
    # prosa de mascaramento ali polui o retrieval e derruba as técnicas de C2 do pool.
    exec_subject = cat in {"process_create", "powershell_pipeline", "powershell_module",
                           "powershell_script_block", "file_create", "image_load"}
    img = ev.get("image_name") or ev.get("image_path")
    if img:
        bits.append(f"Executable: {img}.")
        base = (ev.get("image_name") or img).replace("/", "\\").split("\\")[-1].strip().lower()
        # remove o char RTL só para casar o nome-base no dicionário de interpretadores
        interp = _INTERPRETERS.get(base.replace("\u202e", ""))
        if interp and exec_subject:
            bits.append(f"This process is {interp}.")
    if ev.get("command_line"):
        bits.append(f"Command line: {ev['command_line']}.")
    if exec_subject:
        for note in _masquerade_notes(ev.get("image_name") or img, ev.get("command_line")):
            bits.append(note)
    if ev.get("script_block_text"):
        bits.append(f"PowerShell executed script block content: {str(ev['script_block_text'])[:300]}.")
    if ev.get("registry_target_object"):
        bits.append(f"Registry key: {ev['registry_target_object']}.")
    if ev.get("target_filename"):
        bits.append(f"Target file: {ev['target_filename']}.")
    if ev.get("destination_ip"):
        port = ev.get("destination_port")
        # Enriquecimento de recall (query-side): o e5 sozinho NÃO traz as técnicas
        # canônicas de C2 (T1071/T1571/T1572) para o pool a partir de "outbound
        # connection to IP:port" — elas ficam fora do top-20. Ancorar a descrição no
        # VOCABULÁRIO comportamental do ATT&CK de command-and-control coloca-as no pool.
        # (A decisão benigno×malicioso é dos agentes 2/4; aqui só perguntamos "a que
        # técnica esse comportamento se PARECE" — conexão de saída se parece com C2.)
        bits.append(
            f"The process opened an outbound network connection to remote host "
            f"{ev['destination_ip']}" + (f" on port {port}" if port else "") + ". "
            "This behavior resembles command-and-control (C2) communication: a process "
            "beaconing to a remote adversary-controlled server, establishing a command "
            "and control channel over an application layer protocol, possibly on a "
            "non-standard network port.")
    if ev.get("dns_query_name"):
        bits.append(f"DNS query for {ev['dns_query_name']}.")
    if ev.get("logon_type") is not None:
        bits.append(
            f"An existing, legitimate account authenticated and successfully logged on "
            f"using valid credentials (logon type {ev['logon_type']}) — not a brute-force, "
            f"password spray, or newly created account, but reuse of a valid account.")
    if ev.get("subject_account_name") or ev.get("subject_account"):
        bits.append(f"Account: {ev.get('subject_account_name') or ev.get('subject_account')}.")
    return " ".join(bits)


def describe_chain(steps: list) -> str:
    """Descrição NL a partir de uma cadeia do agente de correlação (lista de Step
    ou lista de strings já renderizadas)."""
    lines = []
    for s in steps:
        lines.append(s if isinstance(s, str) else getattr(s, "line", lambda: str(s))())
    return "A sequence of related host events: " + " -> ".join(lines)
