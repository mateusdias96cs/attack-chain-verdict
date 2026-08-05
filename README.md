# agentecve

Pipeline de quatro agentes que transforma telemetria bruta do Windows em um veredito de
segurança estruturado, com a técnica MITRE ATT&CK atribuída a cada evento, um nível de
confiança e uma justificativa.

A entrada são logs brutos do Windows (Sysmon, Security, PowerShell e Windows Filtering
Platform). A saída é um relatório validado por schema que responde, para uma sequência
de eventos correlacionados: o que aconteceu, qual técnica ATT&CK corresponde a cada
passo, com que confiança e por quê.

## O que o sistema faz

```
logs brutos NDJSON
      |
      v
Agente 1  parsing Bronze para Silver ......... 1 linha estruturada por evento
      |
      v
Agente 2  correlação temporal ................ cadeias de eventos relacionados
      |
      v
Agente 3  recuperação de técnicas ATT&CK ..... candidatos por evento
      |
      v
Agente 4  veredito final ..................... técnica + confiança + justificativa
```

| Agente | Diretório | O que faz | Motor |
|---|---|---|---|
| 1 | `silver_agent/` | Converte um log bruto em uma linha da camada Silver (cerca de 90 colunas), com normalização de PID, timestamp e hashes, e validação de qualidade | Parser determinístico por expressão regular. O modelo `llama-3.3-70b-versatile` (Groq) preenche apenas lacunas |
| 2 | `temporal_agent/` | Materializa a camada Gold em DuckDB e monta cadeias de eventos relacionados por linha do tempo e por artefato compartilhado | Correlação determinística em SQL. O Groq apenas pontua a plausibilidade das cadeias do topo |
| 3 | `mitre-rag/` | Recupera as técnicas ATT&CK mais próximas da descrição de cada evento | Busca vetorial local com `multilingual-e5-small` e reordenação por cross-encoder. Nenhuma chamada externa |
| 4 | `verdict_agent/` | Decide, entre os candidatos recuperados, qual técnica se aplica a cada evento e emite o relatório final | `gemini-flash-latest` com saída estruturada validada por Pydantic |

Duas garantias importantes do desenho:

1. **Sem separação artificial por arquivo.** Os dois arquivos de origem cobrem fases
   sequenciais do mesmo ataque, com um intervalo de cerca de 4,5 horas entre elas. Toda
   ordenação usa `event_utc_time`, e o nome do arquivo de origem nunca funciona como
   fronteira de correlação. Essa invariante é coberta por teste.
2. **Trava de grounding no Agente 4.** A técnica atribuída a um evento precisa estar
   entre os candidatos recuperados pelo Agente 3 para aquele mesmo evento. Se o modelo
   escapar disso, o agente rebaixa a atribuição para `NONE` e registra a correção. O
   relatório final nunca cita um identificador de técnica que a busca não recuperou.

## Dados de entrada

O pipeline foi construído sobre o conjunto de avaliação APT29 do MITRE (dmevals), em
formato NDJSON, com um objeto JSON por linha:

| Arquivo | Registros | Janela |
|---|---|---|
| `dadosdia1.json` | 196.081 | 02:55 às 03:28 UTC, domínio SCRANTON |
| `dadosdia2.json` | 587.286 | 07:54 às 08:29 UTC, domínio UTICA |

Os dois arquivos ficam na raiz do projeto e não são versionados, por causa do tamanho
(cerca de 2 GB somados). O perfil completo dos dados está em `docs/data_profile.md`.

## Requisitos

O projeto usa **três ambientes virtuais separados**, e isso é obrigatório, não
preferência. A pilha de embeddings (torch, transformers, chromadb) fica isolada em
`mitre-rag/`, e o LangGraph exige Python 3.12. Por isso os agentes não compartilham
interpretador e a integração entre eles acontece por subprocesso, com JSON como
contrato.

| Ambiente | Python | Usado por | Dependências principais |
|---|---|---|---|
| `.venv` (raiz) | 3.14 | Agentes 1, 2 e 4 | `groq`, `duckdb`, `google-genai`, `pydantic`, `pytest` |
| `mitre-rag/.venv` | 3.12 | Agente 3 | `chromadb`, `llama-index`, `sentence-transformers` |
| `graph_app/.venv` | 3.12 | Orquestração visual | `langgraph`, `langgraph-cli`, `google-genai` |

## Instalação

```bash
# 1. Ambiente raiz (agentes 1, 2 e 4)
python3.14 -m venv .venv
.venv/bin/pip install -r silver_agent/requirements.txt \
                      -r temporal_agent/requirements.txt \
                      -r verdict_agent/requirements.txt \
                      -r tests/requirements.txt

# 2. Ambiente do Agente 3 (busca vetorial)
python3.12 -m venv mitre-rag/.venv
mitre-rag/.venv/bin/pip install -r mitre-rag/requirements.txt

# 3. Ambiente da orquestração visual (opcional)
python3.12 -m venv graph_app/.venv
graph_app/.venv/bin/pip install langgraph langgraph-cli google-genai pydantic
```

### Índice vetorial do ATT&CK

O Agente 3 depende de um índice ChromaDB local, construído a partir de
`enterprise-attack-stix/enterprise-attack-clean.json` (base ATT&CK v19.1). O índice não
é versionado, mas é reproduzível:

```bash
cd mitre-rag && ./.venv/bin/python ingest.py
```

O índice padrão contém as 697 técnicas ativas mais os exemplos de procedimento. Os
exemplos de procedimento são importantes: a descrição de uma técnica é prosa abstrata,
enquanto a consulta que chega dos agentes é um comando concreto. Indexar os dois
aproxima o índice da linguagem da consulta. Para gerar apenas as técnicas, use
`ingest.py --no-procedures`.

### Chaves de API

Copie o template e preencha as duas chaves:

```bash
cp .env.example .env
```

| Variável | Usada por | Onde gerar |
|---|---|---|
| `GROQ_API_KEY` | Agentes 1 e 2 | https://console.groq.com/keys |
| `GEMINI_API_KEY` | Agente 4 | https://aistudio.google.com/app/apikey |

O Agente 3 não precisa de chave, porque roda inteiramente local.

## Como usar

### Pipeline completo, de uma cadeia até o veredito

Este é o caminho principal. O comando invoca a recuperação de candidatos no ambiente do
`mitre-rag` (por subprocesso) e depois o veredito final:

```bash
.venv/bin/python -m verdict_agent.cli \
    --chain verdict_agent/fixtures/apt29_chain.json \
    --top-k 4 \
    --out verdict.json
```

Se você já tem o handoff pronto (cadeia mais candidatos por evento), pule a etapa de
recuperação:

```bash
.venv/bin/python -m verdict_agent.cli --handoff handoff.json --out verdict.json
```

### Agentes individuais

```bash
# Agente 1: converte um log aleatório do arquivo bruto em uma linha Silver
.venv/bin/python -m silver_agent.cli --random dadosdia1.json --compact

# Agente 1 sem gastar tokens (apenas o caminho determinístico)
.venv/bin/python -m silver_agent.cli --random dadosdia1.json --no-llm

# Agente 2: monta a camada Gold sobre uma amostra e correlaciona
.venv/bin/python -m temporal_agent.cli --sample 40000

# Agente 2 sobre o conjunto completo de 783 mil eventos
.venv/bin/python -m temporal_agent.cli --rebuild

# Agente 3: consulta direta ao índice de técnicas
cd mitre-rag && ./.venv/bin/python query.py "logon com credenciais válidas de domínio" --k 3
```

Os Agentes 1 e 2 aceitam `--dry-run`, que estima o consumo de tokens sem fazer a
chamada, e `--no-llm`, que executa apenas a parte determinística. O Agente 4 sempre
chama o Gemini, porque a decisão final é a função dele.

### Orquestração visual

O diretório `graph_app/` monta os quatro agentes como nós de um grafo, para visualizar e
executar o pipeline em uma interface:

```bash
graph_app/.venv/bin/langgraph dev --no-browser --port 2024
```

A API sobe em `http://127.0.0.1:2024`. A primeira execução leva de um a dois minutos,
porque o nó do Agente 3 carrega os modelos de embedding e reordenação. Detalhes em
`graph_app/README.md`.

## Testes

```bash
.venv/bin/python -m pytest tests/ -q
```

São 33 testes e nenhum deles chama serviço externo. A execução leva cerca de dois
minutos e meio, porque `tests/test_gold_search.py` reconstrói a camada Gold inteira em
DuckDB a partir dos 783 mil eventos reais e valida integridade referencial, unicidade de
grão, reconciliação de contagem, a cadeia de validade SCD tipo 2 e as consultas que um
analista realmente executa.

Testes de retrieval do Agente 3 rodam no ambiente próprio:

```bash
cd mitre-rag && ./.venv/bin/python test_technique_agent.py
./.venv/bin/python test_describe_adapter.py
```

## Avaliação

O pipeline é medido contra um conjunto rotulado de 15 casos, com dificuldade crescente,
em `verdict_agent/golden_set.json`. Os rótulos foram conferidos um a um na base oficial
do MITRE ATT&CK.

```bash
.venv/bin/python -m verdict_agent.eval_golden --out resultados.json
```

Resultado da última medição:

| Métrica | Valor |
|---|---|
| Recall do Agente 3 (técnica correta entre os candidatos) | 14/15 (93%) |
| Acurácia estrita do Agente 4 (técnica exata) | 13/15 (87%) |
| Acurácia por família (aceita pai e subtécnica, não aceita irmãs) | 14/15 (93%) |
| Atribuições fora dos candidatos (violações de grounding) | 0/15 |

Por faixa de dificuldade: fácil 5/5, média 5/5, difícil 4/5. Dos 14 casos em que a
técnica correta foi recuperada, o Agente 4 acertou os 14. O gargalo do sistema é a
recuperação, não a decisão final.

## Estrutura do projeto

```
docs/            Modelagem: perfil dos dados, star schema, arquitetura medalhão e auditoria
silver_agent/    Agente 1: parsing Bronze para Silver
temporal_agent/  Agente 2: camada Gold e correlação temporal
mitre-rag/       Agente 3: índice vetorial e recuperação de técnicas ATT&CK
verdict_agent/   Agente 4: veredito final e harness de avaliação
graph_app/       Orquestração visual dos quatro agentes
tests/           Testes determinísticos do pipeline e da camada Gold
```

Cada diretório de agente tem um README próprio com o detalhamento, o orçamento de tokens
e as limitações específicas daquele agente. A camada de modelagem em `docs/` passou por
uma auditoria formal que encontrou 15 defeitos capazes de corromper resultados de
consulta, todos corrigidos e registrados em `docs/audit/lakehouse_audit.md`.

## Limitações conhecidas

- O único caso do conjunto de avaliação em que a recuperação falha envolve tráfego de
  comando e controle sobre protocolo web, e é ambíguo por construção do próprio caso.
- A recuperação depende de enriquecimento do lado da consulta para ferramentas cujo
  sinal está apenas na linha de comando. Binários fora do mapa de enriquecimento em
  `mitre-rag/agent.py` tendem a não recuperar a técnica correta.
- A linha do tempo por entidade foca contas humanas. Atividade posterior a escalonamento
  de privilégio, executada sob `SYSTEM`, é capturada pelas arestas de artefato, não pela
  linha do tempo do usuário.
- O conjunto de avaliação não tem casos rotulados com os hosts e as contas do segundo
  dia. A cobertura do domínio UTICA ainda está em aberto.
- O deslocamento de fuso usado como alternativa quando falta `UtcTime` foi descoberto
  neste conjunto de dados específico e precisa ser recalibrado por lote em outro
  ambiente.
