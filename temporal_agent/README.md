# temporal_agent — Agente 2: Correlação temporal (Gold + Groq)

Identifica **sequências plausíveis de eventos relacionados** (trilhas de ataque) na
camada Gold, tratando dia1 e dia2 como **uma linha do tempo única**.

## Princípio central (requisito): sem separação dia1/dia2

Os dois arquivos são sequenciais com um gap de ~4,5h (dia1: 02:55–03:28 UTC; dia2:
07:54–08:29 UTC), em hosts/usuários **diferentes** (pbeesly@SCRANTON vs
dschrute/mscott@UTICA). Portanto:

- Toda ordenação é por **`event_utc_time`**; `source_file` **nunca** é fronteira de
  correlação (só rótulo de linhagem). Invariante testada.
- O elo "mesmo traço de ataque" através do gap vem de **artefato compartilhado**
  (hash de binário / IP de C2 / arquivo dropado→executado), já que processo e usuário
  não persistem entre os dias. Confirmado nos dados: **1.450 hashes SHA256 e ~50 IPs
  de C2 reaparecem nos dois dias**.

## Como funciona (híbrido)

```
NDJSON reais ──► Gold (DuckDB, fact_security_event denormalizada)
                    │
                    ▼
   1. Correlação DETERMINÍSTICA (0 tokens)
      • entity_timelines: eventos de (host, conta de ator) ordenados por event_utc_time
      • artifact_edges: arestas por hash / IP de C2 / drop→exec (cruzam host e dia)
      • pré-ranking por sinais fortes (exec+rede, powershell/cmd/.scr/certutil/psexec…)
                    │  top-N cadeias
                    ▼
   2. Groq (llama-3.3-70b) pontua PLAUSIBILIDADE (token-limitado)
      • input compacto (1 linha/passo, nº de passos limitado), max_tokens travado
      • saída JSON: verdict (attack|suspicious|benign), plausibility 0-1,
        likely_tactics (MITRE), rationale
```

O determinístico monta e rankeia; o LLM só julga as poucas candidatas do topo.

## Resultado validado

Na amostra, o agente coloca no topo a cadeia real do APT29 —
`SCRANTON/pbeesly`: `cod.3aka3.scr` (binário mascarado com RTL-override) →
`network_connect 192.168.0.5:1234` (C2) → `cmd.exe` → `powershell` —
com **verdict=attack, plausibility=0.90**, táticas *Execution / Command and Control /
Defense Evasion*; ruído benigno (Cortana/background) cai para p=0.20.

Continuidade dia1↔dia2: **53–103 arestas cross-dia**, incluindo o hash do
`cod.3aka3.scr` reaparecendo no dia2 com gap ~17.700s (**~4,9h — atravessa o gap**).

## Uso

```bash
pip install -r temporal_agent/requirements.txt   # duckdb + groq

# amostra rápida (gold 40k/arquivo) + correlação + plausibilidade via Groq
python -m temporal_agent.cli --sample 40000

# dataset completo (783k)
python -m temporal_agent.cli --rebuild

# só determinístico (0 tokens)
python -m temporal_agent.cli --sample 40000 --no-llm

# estimar tokens sem chamar a API
python -m temporal_agent.cli --sample 40000 --dry-run

# saída estruturada
python -m temporal_agent.cli --sample 40000 --json
```

Gold materializada em `.duckdb_tmp/temporal.duckdb` (on-disk, memory-safe p/ WSL;
gitignored). `GROQ_API_KEY` lido do `.env`.

## Orçamento de tokens

| Item | Tokens |
|---|---|
| Correlação determinística (qualquer volume) | **0** |
| Input por cadeia ao LLM | ~670–1.060 |
| Pontuação real por cadeia (in+out) | ~900–1.700 |
| Execução típica (top-5 cadeias) | ~5.000–8.000 total |

Controles: `--top-n` (nº de cadeias pontuadas), `--no-llm`, `--dry-run`,
`MAX_STEPS_PER_CHAIN` (teto de passos enviados), `max_output_tokens` (padrão 500).

## Testes

```bash
pip install duckdb pytest    # groq NÃO é necessário (testes são determinísticos)
pytest tests/test_temporal_correlation.py -v
```

9 testes: **sanidade** (linha do tempo única/sequencial, monotonicidade, isolamento
por host, ProcessCreate→NetworkConnect, source_file não é fronteira) + **reconstrução
cross-dia** (aresta atravessa o gap, hash de ferramenta compartilhado, cadeia APT29
reconstruída). Nenhum chama a API.

## Estrutura

| Arquivo | Responsabilidade |
|---|---|
| `gold.py` | Materializa a Gold (DuckDB) dos NDJSON com as colunas de correlação |
| `correlate.py` | Correlação determinística: timelines por entidade + arestas de artefato |
| `plausibility.py` | Pontuação de plausibilidade via Groq (token-limitada) |
| `agent.py` | Orquestrador híbrido (gold → correlação → LLM → ranking) |
| `cli.py` | Interface de linha de comando |

## Limitações conhecidas

- A timeline por entidade foca contas de ator humanas (`is_actor`); atividade
  pós-escalonamento sob `SYSTEM` é capturada pelas arestas de artefato, não pela
  timeline de usuário. Um próximo passo seria costurar a linhagem de processo
  (parent/child) para puxar a atividade SYSTEM de volta ao ator que a iniciou.
- A pontuação de plausibilidade é do LLM (best-effort); o ranking determinístico é a
  âncora estável. Mapear cada passo para técnicas ATT&CK específicas (via o RAG
  MITRE já instalado) seria o Agente 3.
- Amostra (`--sample`) pega as primeiras N linhas por arquivo; para cobertura total da
  cadeia use `--rebuild`.
