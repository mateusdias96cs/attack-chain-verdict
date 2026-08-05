# graph_app — Orquestração LangGraph (visualização dos 4 agentes)

Envelope LangGraph do pipeline para **ver e rodar a disposição dos agentes** no
LangGraph Studio. Não substitui os agentes — apenas os fia como nós de um `StateGraph`.

```
START → agent1_silver → agent2_temporal → agent3_rag → agent4_verdict → END
        (Agente 1)       (Agente 2)        (Agente 3)    (Agente 4)
        parse silver      linha do tempo    RAG técnica   veredito Gemini
```

## Subir

```bash
graph_app/.venv/bin/langgraph dev --no-browser --port 2024
```

- **API**: http://127.0.0.1:2024
- **Studio UI**: https://smith.langchain.com/studio/?baseUrl=http://127.0.0.1:2024
- **API docs**: http://127.0.0.1:2024/docs

Abra a Studio UI no navegador do Windows (o WSL2 encaminha `localhost:2024`).

## Rodar o grafo

Na Studio, invoque o grafo `attack_chain_verdict`. Entrada mínima: `{}` — o nó
`agent1_silver` carrega a fixture APT29 (`verdict_agent/fixtures/apt29_chain.json`)
quando não recebe cadeia. Para uma cadeia própria, passe `{"chain": {...}}` no formato
do handoff-de-veredito.

> **1ª invocação demora ~1–2 min**: o nó `agent3_rag` carrega e5 + cross-encoder (torch)
> no venv do `mitre-rag` via subprocess. `agent4_verdict` chama o Gemini (precisa de
> `GEMINI_API_KEY` no `.env` da raiz).

## Detalhes de arquitetura preservados

- **Split de venvs**: este app roda em `graph_app/.venv` (Python 3.12, langgraph +
  google-genai). O Agente 3 continua em `mitre-rag/.venv` e é chamado por **subprocess**
  (o nó reusa `verdict_agent.cli.rag_candidates`). Ver a memória `pipeline-venv-split`.
- **Grounding**: `agent4_verdict` só atribui técnicas que o RAG recuperou (trava no
  Agente 4).
- **Narrativa no estado**: o Studio exibe o estado como JSON, então o nó do Agente 4
  também grava `report_text`, a cadeia de ataque já narrada passo a passo. É esse
  campo que se lê na interface; `verdict` continua com o objeto estruturado completo.
- **Modo dos nós 1 e 2**: leve/demo sobre a fixture já correlacionada (representam
  parsing e correlação sem reprocessar os 1,6 GB de NDJSON). Os nós 3 e 4 executam
  os agentes reais.

## Arquivos

- `graph.py` — `StateGraph` + os 4 nós + `graph` compilado (o que o Studio carrega).
- `langgraph.json` — aponta `attack_chain_verdict → ./graph.py:graph`, env em `../.env`.
- `pyproject.toml` — torna `.` instalável (exigência do langgraph.json).
