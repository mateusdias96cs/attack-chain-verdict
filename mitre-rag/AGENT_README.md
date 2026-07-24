# Agente 3 — Classificador RAG de técnica MITRE ATT&CK

Recebe uma **descrição textual de um evento** (ou cadeia de eventos) — que pode vir do
agente de parsing (`silver_agent`) ou do agente de correlação (`temporal_agent`) — e
retorna a(s) técnica(s) ATT&CK mais parecida(s) semanticamente, buscando nas **697
técnicas** já indexadas no ChromaDB.

## Ponto técnico: qual modelo vetoriza a consulta

A vetorização da consulta usa **`intfloat/multilingual-e5-small`** (384-dim) — o
**mesmo modelo que indexou** o ChromaDB. Retrieval só funciona se query e documentos
forem embeddados pelo mesmo modelo; o índice foi construído com e5, então a query
também tem que ser e5.

O **Groq (llama-3.3-70b)** que os agentes 1 e 2 usam faz **inferência de linguagem**,
não **embeddings** — ele nem expõe endpoint de embedding. No pipeline RAG o Groq só
entra, opcionalmente, para *sintetizar* uma resposta em cima do que o retrieval trouxe
(ver `ask.py`); este agente é **retrieval puro e determinístico** (e5 + cross-encoder),
sem chamada de nuvem, exatamente o que o teste isolado exige.

## Pipeline (2 estágios, encapsulado)

```
descrição do evento/cadeia
      │  embedding e5-small (query: …)
      ▼
1) busca vetorial no ChromaDB → POOL de ~20 candidatos (rápido, aproximado)
      ▼
2) cross-encoder (mmarco-mMiniLMv2) reordena o pool → top-k (preciso)
      ▼
top-1/2/3 técnicas ATT&CK (attack_id, nome, táticas, plataformas, score, url)
```

## Uso

```python
from agent import TechniqueClassifier, describe_silver_event, describe_chain

clf = TechniqueClassifier()                       # carrega e5 + reranker 1x

# descrição livre
clf.classify("an account logged on with valid domain credentials", top_k=3)

# a partir de um registro silver (saída do Agente 1)
clf.classify(describe_silver_event(silver_dict), top_k=3)

# a partir de uma cadeia (saída do Agente 2)
clf.classify(describe_chain(chain.steps), top_k=3)
```

`TechniqueClassifier.classify(desc, top_k)` → `list[TechniqueMatch]`
(`attack_id, name, score, tactics, platforms, is_subtechnique, url`).

CLI de retrieval já existente e equivalente: `python query.py "…" --k 3`.

## Teste isolado

```bash
./.venv/bin/python test_technique_agent.py
```

Pega eventos cuja técnica correta é conhecida de antemão, passa **só a descrição** para
o agente (sem o resto do pipeline) e confere o top-k. Determinístico (não usa a API).

**Resultado:** o caso pedido — *logon com credencial válida → **T1078*** — acerta no
rank **#1**. Agregado: **hit@1 = 70%, hit@3 = 90%** em 10 casos (acertos exatos em
Run key→T1547.001, LSASS→T1003.001, Scheduled task→T1053.005, Masquerading
RTL→T1036.002 etc.). Único miss: "C2 sobre protocolo web" retorna T1090 (Proxy) em vez
de T1071 — caso ambíguo (Proxy também é técnica da tática Command and Control).

## Arquivos (novos)

| Arquivo | Papel |
|---|---|
| `agent.py` | `TechniqueClassifier` + adaptadores `describe_silver_event` / `describe_chain` |
| `test_technique_agent.py` | Teste isolado (evento conhecido → técnica esperada) |
| `demo_integration.py` | Mostra a entrada vindo dos agentes 1 e 2 |

Reusa a infra já existente: `config.py` (e5 + reranker + coleção), `ingest.py`
(indexação), `query.py`/`eval.py` (retrieval e métricas IR).

## Limitações

- Retrieval puramente semântico: descrições genéricas (ex.: "conexão a um servidor de
  C2") podem cair numa técnica vizinha da mesma tática. Um estágio de verificação por
  LLM (Groq) sobre os top-k candidatos elevaria a precisão em casos ambíguos — mas isso
  já sairia do "retrieval isolado".
- Os adaptadores `describe_*` produzem NL comportamental a partir dos campos; quanto
  mais rico o evento silver/cadeia, melhor a recuperação. (Ex.: o adaptador de logon
  descreve explicitamente "conta legítima existente, não brute-force/spray" para o
  T1078 subir sobre técnicas de ataque a credencial — sem isso, ele cai para ~#3.)
- Uma **cadeia** do Agente 2 costuma abranger VÁRIAS técnicas (execução + C2 +
  masquerading…). O top-1 único traz só uma técnica plausível daquela cadeia; para
  cadeias, classifique **por passo** (cada evento → sua técnica) ou consuma o top-k
  como conjunto, não como resposta única.
