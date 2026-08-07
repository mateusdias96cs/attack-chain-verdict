# ATT&CK Chain Verdict

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
Portão    triagem determinística ............. tem característica de ataque?
      |
      +--- não ---> uso legítimo, com prova auditável (não gasta cota)
      |
      +--- sim --->
      |
      v
Agente 3  recuperação de técnicas ATT&CK ..... candidatos por evento
      |
      v
Agente 4  veredito final ..................... cadeia narrada passo a passo
```

| Agente | Diretório | O que faz | Motor |
|---|---|---|---|
| 1 | `silver_agent/` | Converte um log bruto em uma linha da camada Silver (cerca de 90 colunas), com normalização de PID, timestamp e hashes, e validação de qualidade. Cobre Sysmon, Security, PowerShell, WFP, WMI, BITS, RDP, Firewall, Defender e serviços do sistema, e nunca descarta um evento | Parser determinístico por expressão regular. O modelo `llama-3.3-70b-versatile` (Groq) preenche apenas lacunas |
| 2 | `temporal_agent/` | Materializa a camada Gold em DuckDB, monta cadeias de eventos relacionados por linha do tempo e por artefato compartilhado, e aplica um portão de triagem determinístico que decide se a cadeia segue para o veredito | Correlação e triagem determinísticas, por SQL e por regras. O Groq é opcional e desligado por padrão |
| 3 | `mitre-rag/` | Recupera as técnicas ATT&CK mais próximas da descrição de cada evento | Busca vetorial local com `multilingual-e5-small`, com chunking medido no tokenizer do próprio modelo. Nenhuma chamada externa |
| 4 | `verdict_agent/` | Decide, entre os candidatos recuperados, qual técnica se aplica a cada evento e emite o relatório final | `gemini-flash-latest` com saída estruturada validada por Pydantic, apoiado por travessia de grafo no ATT&CK |

Três garantias importantes do desenho:

1. **Sem separação artificial por arquivo.** Os dois arquivos de origem cobrem fases
   sequenciais do mesmo ataque, com um intervalo de cerca de 4,5 horas entre elas. Toda
   ordenação usa `event_utc_time`, e o nome do arquivo de origem nunca funciona como
   fronteira de correlação. Essa invariante é coberta por teste.
2. **Trava de grounding no Agente 4.** A técnica atribuída a um evento precisa estar
   entre os candidatos recuperados pelo Agente 3 para aquele mesmo evento. Se o modelo
   escapar disso, o agente rebaixa a atribuição para `NONE` e registra a correção. O
   relatório final nunca cita um identificador de técnica que a busca não recuperou.
3. **Teto de saída no Agente 4.** A geração é limitada a 8.192 tokens. Sem esse teto uma
   geração degenerada corre até o limite do modelo, e o sintoma chega como um erro de JSON
   inválido que não aponta a causa real. Quando a resposta bate no teto, o agente falha
   com uma mensagem que diz exatamente isso. Uma cadeia de quatro passos consome cerca de
   600 tokens de saída, então a folga é larga.
4. **Nenhum evento é descartado.** O parser cobre as famílias de log relevantes do
   Windows por identificador e por canal, e todo evento vira uma linha da camada Silver,
   inclusive tipos desconhecidos. O que não tem coluna própria é preservado inteiro na
   coluna `unmapped_json`, e o registro recebe `dq_status = partial` para deixar
   explícito onde o parse ficou incompleto. A cobertura semântica de cada tipo é
   incremental, mas a preservação do dado bruto é total.

## Triagem determinística antes do veredito

Nem todo log é ataque, e o modelo do Agente 4 tem cota diária. Para não gastar essa cota
com atividade legítima, e para não empurrar um evento benigno para dentro de uma técnica
só porque a busca sempre devolve a mais parecida, o Agente 2 tem um portão de triagem que
roda em código puro, sem chamar modelo nenhum e sem custo de token.

O portão consulta um conjunto de regras em `temporal_agent/triage_rules.yaml`, no estilo
das regras Sigma: cada regra descreve um padrão de ataque, aponta a técnica ATT&CK
correspondente e tem um nível de força. A decisão é simples e explicável:

- Uma regra **forte** que dispara já escala a cadeia para o veredito. Exemplos: acesso à
  memória do LSASS, deleção de cópias de sombra, download por utilitário do sistema,
  PowerShell codificado, nome de arquivo mascarado.
- **Dois sinais fracos** que se corroboram na mesma cadeia também escalam. Um sinal fraco
  isolado, como a simples criação de uma tarefa agendada, não escala, porque é comum em
  uso legítimo.
- Se nada dispara, a cadeia é declarada **uso legítimo**, com uma prova auditável: a lista
  do que foi verificado e não apareceu (sem mascaramento, sem conexão a porta atípica, sem
  acesso ao LSASS, sem download suspeito). O humano lê essa prova e confere se a conclusão
  faz sentido.

O portão tem recall limitado ao conjunto de regras: um ataque novo, fora do repertório,
passaria como legítimo. Para reduzir esse risco sem estourar a cota, uma pequena amostra
das cadeias declaradas legítimas é sorteada de forma determinística e enviada mesmo assim
ao veredito, como auditoria de segurança.

Uma regra ampla demais custa caro. A primeira versão da regra de comando e controle
marcava qualquer processo que abrisse conexão externa, e isso fez quase tudo escalar,
porque tráfego normal do Windows, como o cliente de e-mail e tarefas de segundo plano,
conecta o tempo todo a servidores de nuvem na porta 443. A regra foi rebaixada para sinal
fraco e passou a considerar a porta: conexões nas portas de serviço comuns não contam, e
uma conexão a porta atípica logo após a criação de um processo conta. Medido na amostra de
40 mil eventos do conjunto APT29, das cadeias montadas apenas a cadeia de ataque real
escala, o tráfego legítimo é declarado legítimo com prova, e o portão não faz nenhuma
chamada de modelo.

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

A saída é a cadeia de ataque numerada, escrita para ser lida por quem não conhece o
ATT&CK, com os dados técnicos ao lado de cada passo:

```
PASSO A PASSO (4 passos)

  1º  Execução do executável malicioso mascarado cod.3aka3.scr
      O atacante executou o arquivo malicioso cod.3aka3.scr localizado em
      ProgramData utilizando caracteres especiais de inversão de texto para
      ocultar sua extensão real. Após essa execução inicial, o processo passou
      a estabelecer comunicações de rede de saída.

      Técnica MITRE ATT&CK : T1036.002 Right-to-Left Override
      Fase da cadeia       : Furtividade
      Confiança            : alta (95%)

  2º  Conexão de rede externa do arquivo cod.3aka3.scr para o IP 192.168.0.5
      ...
```

O relatório legível vai para a saída padrão e a diagnose de execução vai para a saída
de erro, então é possível redirecionar só o relatório. O JSON completo sai em `--out`.

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

# Agente 2: monta a camada Gold, correlaciona e aplica o portão de triagem
.venv/bin/python -m temporal_agent.cli --sample 40000

# Agente 2 sobre o conjunto completo de 783 mil eventos
.venv/bin/python -m temporal_agent.cli --rebuild

# Agente 2 escalando também para o Groq nas cadeias que passam pelo portão
.venv/bin/python -m temporal_agent.cli --sample 40000 --groq

# Agente 3: consulta direta ao índice de técnicas
cd mitre-rag && ./.venv/bin/python query.py "logon com credenciais válidas de domínio" --k 3
```

O Agente 1 aceita `--dry-run`, que estima o consumo de tokens sem fazer a chamada, e
`--no-llm`, que executa apenas a parte determinística. O Agente 2 já roda determinístico
por padrão, com o portão de triagem no lugar do modelo, e só chama o Groq com `--groq`.
Ainda no Agente 2, `--no-triage` desliga o portão e escala tudo, como comparação, e
`--sample-budget N` controla quantas cadeias legítimas são sorteadas para auditoria. O
Agente 4 sempre chama o Gemini, porque a decisão final é a função dele.

### Orquestração visual

O diretório `graph_app/` monta os quatro agentes como nós de um grafo, para visualizar e
executar o pipeline em uma interface:

```bash
graph_app/.venv/bin/langgraph dev --no-browser --port 2024
```

A API sobe em `http://127.0.0.1:2024`. A primeira execução leva de um a dois minutos,
porque o nó do Agente 3 carrega o modelo de embedding. Detalhes em
`graph_app/README.md`.

## Testes

```bash
.venv/bin/python -m pytest tests/ -q
```

São 62 testes e nenhum deles chama serviço externo. A execução leva cerca de quatro
minutos, porque `tests/test_gold_search.py` reconstrói a camada Gold inteira em
DuckDB a partir dos 783 mil eventos reais e valida integridade referencial, unicidade de
grão, reconciliação de contagem, a cadeia de validade SCD tipo 2 e as consultas que um
analista realmente executa. O portão de triagem tem cobertura própria em
`tests/test_triage.py`, com um caso positivo e um caso benigno por regra.

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

Resultado da última medição, no índice atual:

| Métrica | Valor |
|---|---|
| Recall do Agente 3 (técnica correta entre os candidatos) | 14/15 (93%) |
| Acurácia estrita do Agente 4 (técnica exata) | 12/15 (80%) |
| Acurácia por família (aceita pai e subtécnica, não aceita irmãs) | 13/15 (87%) |
| Atribuições fora dos candidatos (violações de grounding) | 0/15 |

Por faixa de dificuldade: fácil 5/5, média 4/5, difícil 4/5. O gargalo do sistema é a
recuperação, não a decisão final: dos 14 casos em que a técnica correta foi recuperada,
o Agente 4 acertou 13.

Dois casos ficam de fora, e nenhum dos dois é erro de julgamento do modelo:

- **C14** é o único não recuperado pelo Agente 3. É uma conexão de C2 por HTTPS cujo
  evento traz `rundll32.exe` como imagem do processo, o que torna a descrição ambígua de
  propósito.
- **C09** é um empate genuíno de rotulação. O comando é `net group "Domain Admins"
  /domain`, o gabarito diz T1087.002 e o Agente 4 respondeu T1069.002. A base ATT&CK cita
  esse mesmo comando nas duas técnicas, e o texto do T1069.002 descreve literalmente o
  caso ("which users belong to a particular group, such as domain administrators"). O
  harness conta como erro porque só aceita a relação pai e subtécnica, nunca técnicas
  distintas. O rótulo foi mantido como está: mudar gabarito depois de ver a resposta do
  modelo estraga a medição.

A contagem oscila em torno de um caso entre execuções, porque o modelo não é
determinístico e o C09 é decidido no fio da navalha. Com 15 casos, diferenças de um caso
não sustentam conclusão.

Duas decisões de recuperação sustentam esse resultado:

- **Chunking medido no tokenizer certo.** O e5 tem janela de 512 tokens e corta o
  excedente em silêncio. O divisor de texto contava tokens pelo tokenizer padrão do
  LlamaIndex, que não é o do e5, então 30% das descrições de técnica perdiam texto na
  indexação, em média 146 tokens cada. Contando na moeda do próprio modelo, nada é
  cortado.
- **Cross-encoder desligado.** O `mmarco-mMiniLMv2` foi treinado para ranquear passagens
  de busca web a partir de perguntas curtas, e aqui a consulta é um parágrafo
  comportamental longo. Esse descasamento de domínio não muda o recall (14/15 com e sem
  reordenação), mas afunda a ordem, que é o que o Agente 4 lê primeiro: o e5 puro entrega
  MRR 0.730 e a técnica certa em primeiro lugar em 10 dos 15 casos, contra MRR 0.381 e
  3 de 15 com o cross-encoder. A reordenação segue disponível em `use_reranker=True`,
  para quando um reranker melhor for avaliado.

## Dois mecanismos de consulta à base ATT&CK

Os Agentes 3 e 4 consultam a mesma base, mas fazem perguntas de natureza diferente, e
cada um usa o mecanismo que responde melhor à sua pergunta.

- **Busca vetorial no Agente 3.** A pergunta é de um salto: com qual técnica esta
  observação se parece? Isso é similaridade semântica entre a descrição do evento e a
  prosa da técnica, que é exatamente o que a busca densa resolve.
- **Travessia de grafo no Agente 4.** A pergunta é de vários saltos: esta cadeia inteira
  é coerente com o repertório de um ator conhecido? Responder exige percorrer as relações
  de grupo para software e de software para técnica, que não estão no texto de nenhum
  documento indexado, então nenhuma busca densa as alcança. O módulo
  `verdict_agent/ttp_graph.py` monta esse grafo a partir do mesmo
  `enterprise-attack-clean.json` que alimenta o índice vetorial, sem serviço novo nem
  cópia de dados, e injeta um bloco curto no prompt do veredito.

A escolha do mecanismo é estática, tomada em tempo de projeto (`USE_TTP_GRAPH` em
`verdict_agent/agent.py`), e não por um seletor em tempo de execução: a natureza da
pergunta de cada agente já é conhecida, e um seletor probabilístico só acrescentaria
latência e um modo de falha silencioso.

O risco real dessa evidência é viés de confirmação, e ela tem quatro travas contra isso:

1. Não amplia o conjunto de candidatos, então a trava de grounding continua valendo.
2. Pondera a cobertura pela raridade da técnica, porque uma técnica que quase todo grupo
   usa não discrimina nada.
3. Normaliza pelo tamanho do repertório do grupo. Sem isso venceria sempre o maior
   repertório da base, que é justamente o do APT29, o ator deste conjunto de dados.
4. Suprime o bloco inteiro quando o melhor grupo não se destaca do pelotão.

Medido na cadeia APT29 de quatro passos, julgando a mesma cadeia com e sem o bloco: ele
dispara, não muda nenhuma das quatro atribuições e custa 38% a mais de prompt. Isso não
confirma nem refuta a evidência, porque naquela cadeia não havia empate a desempatar, que
é o cenário em que ela deveria agir. O conjunto de avaliação também não serve para
medi-la, porque lá cada caso é julgado como cadeia de um evento só e o bloco exige
cobertura mínima de dois eventos.

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
- A evidência de grafo do Agente 4 ainda não tem ganho comprovado. Ela se comporta como
  projetado, mas medir o efeito exige cadeias longas com candidatos empatados, e o
  conjunto de avaliação atual não tem esse tipo de caso.
- A avaliação usa 15 casos, o que é pouco para separar variação real de ruído. Diferenças
  de um caso entre execuções não sustentam conclusão, ainda mais porque o modelo do
  Agente 4 não é determinístico.
- O portão de triagem reconhece apenas os padrões descritos no seu conjunto de regras. Um
  ataque fora desse repertório passa como legítimo, e a amostragem das cadeias legítimas
  reduz esse risco, mas é amostra, não cobertura total. A prova de legitimidade atesta que
  os padrões de ataque conhecidos não apareceram, não que a atividade seja segura em
  termos absolutos.
- A prova de legitimidade se apoia no que o evento carrega e na ausência de padrões
  conhecidos, não na verificação de assinatura digital nem na conferência do caminho de
  instalação do binário. Persistência apontando para um binário assinado no caminho
  esperado e persistência apontando para um binário em pasta gravável pelo usuário ainda
  são tratadas pelo mesmo sinal fraco.
