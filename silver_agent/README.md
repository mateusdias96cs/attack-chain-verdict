# silver_agent — Agente de parsing Bronze → Silver (Windows telemetry / Groq)

Transforma um log bruto do Windows (Sysmon / Security / PowerShell / WFP) em **uma
linha estruturada da camada Silver**, seguindo o contrato já definido em
[`docs/medallion/ddl_bronze_silver.sql`](../docs/medallion/ddl_bronze_silver.sql)
e as regras de [`docs/medallion/medallion_architecture.md`](../docs/medallion/medallion_architecture.md).

## Como funciona (híbrido — economia máxima de tokens)

```
log bruto (linha NDJSON  OU  bloco Message cru)
        │
        ▼
1. Parser determinístico  ─────────────────────────►  0 tokens
   (regex no Message + mapa de campos + normalizações:
    hex→decimal do PID, split de Hashes, reconciliação de
    timestamp, snake_case, derivação de log_source)
        │
        │  só se: EventID desconhecido, Message não-parseável,
        │         campo crítico faltando, ou chave não mapeada
        ▼
2. Groq (llama-3.3-70b-versatile) preenche SÓ as lacunas
   - input mínimo (envelope + Message + chaves não resolvidas)
   - JSON mode, max_tokens travado
   - loop de auto-correção: máx. 3 chamadas por log
        │
        ▼
3. Validação DQ (regras §4.1) → dq_status: passed | passed_with_warnings | quarantined
```

O determinístico **sempre vence** sobre o LLM nos campos que já resolveu — o Groq
nunca reescreve o que já está correto, preservando a apresentação original
(caminhos com `\`, GUIDs com `{}`, hex `0x…`).

Numa amostra de 17 EventIDs distintos, **14 são 100 % determinísticos (0 tokens)**;
só Security/WFP com campos de enriquecimento (ex.: `TokenElevationType`,
`ElevatedToken`) acionam o Groq.

## Cache de mapeamento (LLM-como-inferência-de-schema)

Logs do Windows são altamente repetitivos: numa amostra de 240k registros, os que
acionam o LLM se resumem a **~68 "shapes"** distintos (EventID + conjunto de campos
não-mapeados). O agente **não cacheia valores** (mudam a cada log: SID, PID,
timestamp) — cacheia o **plano de mapeamento** por shape:

```
log aciona LLM → calcula shape (event_id | log_source | chaves não-mapeadas)
   ├─ cache HIT  → aplica o plano aos valores DESTE log     → 0 tokens
   └─ cache MISS → chama o Groq 1x, aprende o plano, grava em disco
```

Segurança embutida: o plano só é reaproveitado quando se **prova** que a saída do
LLM foi uma renomeação pura de chaves (todo valor devolvido rastreia até um campo
bruto). Shapes cujo dado útil vem de um `Message` verboso (ex.: eventos Security
4656/4688) são marcados `llm_always` e **nunca** reaproveitam valor — o cache
troca tokens por economia só quando é seguro, nunca por correção.

Efeito prático: a **1ª** ocorrência de um shape custa uma chamada; da **2ª em
diante** é 0 tokens (`cache_hit`). Persistido em `silver_agent/.mapping_cache.json`
(cresce como uma biblioteca de templates; ignorado no git). Desative com `--no-cache`.

## Orçamento de tokens (medido nos dados reais)

| Cenário | Tokens |
|---|---|
| Evento Sysmon (1/3/10/11/12/13/22/23) | **0** (determinístico) |
| System prompt (fixo, reaproveitado) | ~600 |
| Input mínimo por log ao LLM | 690–1.150 (méd. ~830) |
| **Chamada real medida (EventID 4688)** | **1.432** (1 chamada, total in+out) |
| Mínimo realista (evento pequeno, 1 passada) | **~900** |
| Pior caso com o loop de 3 chamadas | ~4.000–6.000 |

Controles de limite embutidos:
- `--max-output-tokens` (padrão **900**) — teto de saída por chamada.
- `--max-llm-calls` (padrão **3**) — teto do loop de busca.
- Input truncado a um orçamento de caracteres (campos gigantes como `CallTrace` /
  `ScriptBlockText` são cortados **só no envio ao LLM**; o valor completo fica no
  registro Silver).

## Instalação

```bash
pip install -r silver_agent/requirements.txt   # groq
# GROQ_API_KEY é lido de .env automaticamente
```

## Uso

```bash
# log aleatório do bronze (só determinístico se der conta → 0 tokens)
python -m silver_agent.cli --random dadosdia1.json --compact

# força o caminho Groq (demonstra o agente); loop máx. 3
python -m silver_agent.cli --random dadosdia1.json --force-llm --compact

# estima tokens SEM gastar API
python -m silver_agent.cli --random dadosdia1.json --force-llm --dry-run

# só determinístico, nunca chama a API
python -m silver_agent.cli --random dadosdia2.json --no-llm

# log via stdin — linha JSON OU bloco Message cru
echo '{"EventID":13, ...}' | python -m silver_agent.cli -
```

O registro Silver sai em **stdout** (JSON); o trace do agente (passos, chamadas,
tokens, dq_status) sai em **stderr**.

## Estrutura

| Arquivo | Responsabilidade |
|---|---|
| `schema.py` | Colunas Silver, mapa de coalesce, derivação de `log_source`, sets de DQ |
| `parser.py` | Parser determinístico + normalizadores (0 tokens) |
| `groq_client.py` | Cliente Groq: prompt compacto, JSON mode, guarda de tokens |
| `validate.py` | Validação DQ (regras críticas §4.1) para o loop de auto-correção |
| `cache.py` | Cache de mapeamento por shape (aprende plano 1x, reaproveita a 0 tokens) |
| `agent.py` | Orquestrador híbrido (determinístico → cache → LLM → validação, loop ≤ 3) |
| `cli.py` | Interface de linha de comando |

## Limitações conhecidas

- O `tz_offset` de fallback (UTC-4) é o valor **descoberto neste dataset**; um
  pipeline de produção deve recalibrá-lo por batch (ver arquitetura §5.2). Quando
  `UtcTime` ou `@timestamp` estão presentes, o offset não é usado.
- Códigos `%%NNNN` do Windows (`network_direction`, `elevated_token`) dependem da
  tabela `ref_windows_message_code`, ainda não semeada (ver arquitetura §8).
- O caminho LLM é best-effort: pode ocasionalmente rotular um campo de forma
  imperfeita. Colunas inteiras são coagidas; o determinístico é a fonte exata.
- O cache aprende o plano a partir da **1ª** ocorrência de cada shape (learn-once);
  se aquela chamada do LLM produzir um plano imperfeito, os próximos herdam. Para os
  shapes Sysmon (renomeação pura) isso é estável; os shapes Security de `Message`
  verboso ficam `llm_always` (sem economia, mas sem risco). O próximo passo de
  economia seria um parser determinístico do formato de Message verboso do Windows
  Security — aí esses shapes também iriam a 0 tokens.
