# Agente 4: veredito final (Gemini)

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

- **Gemini** (`gemini-flash-latest`, `google-genai`): único componente Gemini do
  pipeline (agentes 1/2 usam Groq; agente 3 é retrieval local e5).
- **Saída estruturada Pydantic**: o `ChainVerdictReport` é o próprio `response_schema`;
  nada de parsing frágil de texto.
- **Grounding travado** (`agent.py:_ground`): a técnica atribuída a um evento tem de
  estar entre os candidatos do RAG daquele evento, senão vira `NONE`. O veredito
  **nunca cita um T-ID que o RAG não recuperou**, porque o Gemini *decide entre candidatos*
  usando o contexto temporal da cadeia, não inventa.
- **Uma chamada** para a cadeia inteira → o modelo enxerga a narrativa completa
  (ex.: binário mascarado → C2 desambigua "network_connect" como Command & Control).
- `temperature=0` → determinístico. `rationale`/resumo em PT; prompt de sistema em EN
  (evita vazamento de idioma).
- **Teto de saída** (`MAX_OUTPUT_TOKENS = 8192`, como nos agentes 1 e 2): sem ele uma
  geração degenerada corre até o limite do modelo. Já foi observada uma resposta de cerca
  de 333 mil caracteres que voltou truncada e quebrou a validação do schema com "Invalid
  JSON: EOF while parsing a string", mensagem que não aponta a causa. Quando a geração
  bate no teto, `_raise_if_truncated()` falha dizendo exatamente isso. Uma cadeia de
  quatro passos consome cerca de 600 tokens de saída, então a folga é larga.
- **Retry com backoff** para 429/500/503 transitório (6 tentativas, de 4 a 64 segundos).
  O `gemini-flash-latest` devolve 503 por sobrecarga de vez em quando, e sem o retry um
  único 503 abortava a rodada inteira de avaliação. Se persistir, o erro é relançado, não
  engolido.

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
1/2. O estágio de candidatos (e5, torch) roda em **`mitre-rag/.venv`**
(Python 3.12) e é invocado via `subprocess` com `check=True`, então falha não é engolida.
O contrato de handoff entre os venvs é JSON.

## Arquivos

- `schema.py`: modelos Pydantic (o contrato de saída).
- `gemini_client.py`: cliente Gemini com `response_schema` + loader de `.env`.
- `agent.py`: monta o prompt (cadeia + candidatos), chama o Gemini, aplica grounding.
- `ttp_graph.py`: evidência extra por travessia de grafo no ATT&CK (ver abaixo).
- `cli.py`: dois modos (`--chain` orquestrado / `--handoff` direto).
- `mitre-rag/rag_candidates.py`: estágio de candidatos (roda no venv do RAG).
- `fixtures/apt29_chain.json`: cadeia canônica APT29 para demo/teste.

## Evidência de grafo (`ttp_graph.py`)

O Agente 3 responde uma pergunta de um salto ("esta observação se parece com qual
técnica?"), e é aí que a busca vetorial ganha. O Agente 4 responde outra ("esta cadeia
inteira é coerente com o repertório de um ator conhecido?"), que é travessia de vários
saltos: grupo para software, software para técnica. Essa relação não está no texto de
nenhum documento indexado, então nenhuma busca densa a alcança. O módulo monta esse grafo
a partir do mesmo `enterprise-attack-clean.json` que alimenta o índice vetorial, sem
serviço novo nem cópia de dados, e injeta um bloco curto no prompt.

A escolha do mecanismo é estática, decidida em tempo de projeto (`USE_TTP_GRAPH` em
`agent.py`), e não por um seletor em tempo de execução: a natureza da pergunta de cada
agente já é conhecida, e um seletor probabilístico só acrescentaria latência e um modo de
falha silencioso.

O risco real da feature é viés de confirmação, e ela tem quatro travas contra isso:

1. **Não amplia o conjunto de candidatos.** A trava de grounding continua mandando:
   técnica fora dos candidatos do RAG vira `NONE` do mesmo jeito.
2. **Ponderação por raridade.** Uma técnica usada por quase todo grupo não discrimina
   nada (T1071.001 aparece em 139 dos 174 repertórios), então a cobertura é pesada pelo
   inverso do uso e só técnicas distintivas são listadas.
3. **Normalização por especificidade.** Sem ela o grupo de repertório grande venceria por
   tamanho, e o maior repertório da base é justamente o do APT29, o ator do dataset deste
   projeto: a feature viraria uma máquina de confirmar a resposta esperada.
4. **Portão de discriminação.** Se o melhor grupo não superar o pelotão por uma margem
   relativa, o bloco inteiro é suprimido. Calibrado em 200 cadeias sintetizadas a partir
   de candidatos reais do Agente 3, o limiar adotado (1.15) dispara em 43% delas.

O bloco entra no prompt enquadrado como sinal fraco e corroborativo, com instrução
explícita de nunca justificar sozinho uma atribuição e de não nomear o ator na saída.

Medido na cadeia APT29 de quatro passos, julgando a mesma cadeia com e sem o bloco: ele
dispara, não muda nenhuma das quatro atribuições e custa 38% a mais de prompt (2.207 para
2.852 tokens de entrada). Isso não confirma nem refuta a feature, porque naquela cadeia
não havia empate para desempatar: as quatro atribuições saem com confiança entre 0,85 e
0,95 nos dois cenários. O efeito esperado continua sendo margem em caso de empate, não
ganho de acurácia média.

O golden set não serve para medir isto: lá cada caso é julgado como cadeia de um evento
só, e a cobertura mínima de dois eventos faz o bloco ser sempre suprimido. Medir a feature
exige cadeias de verdade, com vários eventos.

Os testes em `tests/test_ttp_graph.py` cobrem as travas, não o caminho feliz.
