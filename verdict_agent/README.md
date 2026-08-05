# Agente 4 — Veredito Final (Gemini)

Fecha o pipeline: recebe tudo dos agentes anteriores e produz o **veredito final
estruturado** (Pydantic). Para **cada evento da cadeia** decide qual técnica ATT&CK
realmente se aplica, com **nível de confiança** e **explicação**, e apresenta o
conjunto como uma **cadeia de ataque numerada e narrada**.

## O que entra e o que sai

**Entrada** (handoff-de-veredito): a cadeia temporal do **Agente 2** + os candidatos
ATT&CK que o **Agente 3 (RAG)** recuperou para cada evento.

**Saída** (`schema.py`, validada via `response_schema` do Gemini):

```python
EventVerdict(event, step_title, attack_id, technique_name, tactic,
             confidence, confidence_level, rationale)
ChainVerdictReport(entity, overall_verdict, overall_confidence, events[], attack_summary)
```

Por passo da cadeia: um **título** que nomeia a ação do atacante e o artefato envolvido,
a **técnica** atribuída, a **fase** da cadeia, o **nível de confiança** e uma
**explicação em prosa** de 2 a 3 frases.

O `tactic` não vem do modelo. Ele é preenchido deterministicamente a partir do
metadado do candidato que o Agente 3 recuperou, pelo mesmo motivo da trava de
grounding: a fase da cadeia é fato do ATT&CK, não opinião do modelo.

## Formato do relatório

A saída legível é uma **cadeia de ataque numerada**, escrita para quem não conhece o
ATT&CK. Cada passo abre com o que o atacante fez, explica em texto corrido e só então
mostra os dados técnicos:

```
  1º  Execução do arquivo mascarado cod.3aka3.scr
      O arquivo usa um caractere que inverte a leitura do nome, fazendo um
      executável parecer um documento comum. Ele foi aberto pela conta do
      usuário, e logo em seguida o processo abriu conexão de rede.

      Técnica MITRE ATT&CK : T1036.002 Right-to-Left Override
      Fase da cadeia       : Furtividade
      Confiança            : alta (95%)
```

O relatório vai para **stdout** e a diagnose de execução (tokens, trace) vai para
**stderr**, então a saída que uma pessoa lê nunca se mistura com telemetria. O JSON
completo, com todos os campos, continua disponível via `--out`.

> As fases são traduzidas a partir das táticas da base v19.1, que tem 15 táticas.
> Nessa versão não existe mais "Defense Evasion": ela deu lugar a "Stealth"
> (Furtividade) e "Defense Impairment" (Degradação de defesas).

## Princípios

- **Gemini** (`gemini-flash-latest`, `google-genai`) — único componente Gemini do
  pipeline (agentes 1/2 usam Groq; agente 3 é retrieval local e5).
- **Saída estruturada Pydantic** — o `ChainVerdictReport` é o próprio `response_schema`;
  nada de parsing frágil de texto.
- **Grounding travado** (`agent.py:_ground`): a técnica atribuída a um evento tem de
  estar entre os candidatos do RAG daquele evento, senão vira `NONE`. O veredito
  **nunca cita um T-ID que o RAG não recuperou** — o Gemini *decide entre candidatos*
  usando o contexto temporal da cadeia, não inventa.
- **Uma chamada** para a cadeia inteira → o modelo enxerga a narrativa completa
  (ex.: binário mascarado → C2 desambigua "network_connect" como Command & Control).
- `temperature=0` → determinístico. `rationale`/resumo em PT; prompt de sistema em EN
  (evita vazamento de idioma).

## Uso

Requer `GEMINI_API_KEY` no `.env` da raiz (ver `.env.example`).

```bash
# Pipeline completo a partir de uma cadeia (agente 2): este CLI invoca o estágio de
# candidatos RAG no venv do mitre-rag (subprocess) e depois o Gemini.
.venv/bin/python -m verdict_agent.cli --chain verdict_agent/fixtures/apt29_chain.json \
    --top-k 4 --out verdict.json

# Se você já tem o handoff (cadeia + candidatos por evento):
.venv/bin/python -m verdict_agent.cli --handoff handoff.json --out verdict.json
```

## Split de venvs (importante)

O Agente 4 (Gemini, cloud) roda no **`.venv` raiz** (Python 3.14), junto dos agentes
1/2. O estágio de candidatos (e5/cross-encoder, torch) roda em **`mitre-rag/.venv`**
(Python 3.12) e é invocado via `subprocess` com `check=True` — falha não é engolida.
O contrato de handoff entre os venvs é JSON.

## Arquivos

- `schema.py` — modelos Pydantic (o contrato de saída).
- `gemini_client.py` — cliente Gemini com `response_schema` + loader de `.env`.
- `agent.py` — monta o prompt (cadeia + candidatos), chama o Gemini, aplica grounding.
- `cli.py` — dois modos (`--chain` orquestrado / `--handoff` direto).
- `mitre-rag/rag_candidates.py` — estágio de candidatos (roda no venv do RAG).
- `fixtures/apt29_chain.json` — cadeia canônica APT29 para demo/teste.
