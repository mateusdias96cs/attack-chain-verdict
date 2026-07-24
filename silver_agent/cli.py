"""
CLI do agente de parsing Bronze -> Silver.

Exemplos:
  # parseia um log aleatório de dadosdia1.json (só determinístico se der conta)
  python -m silver_agent.cli --random dadosdia1.json

  # força o caminho Groq para demonstrar o agente (loop máx. 3)
  python -m silver_agent.cli --random dadosdia1.json --force-llm

  # estima tokens sem gastar API
  python -m silver_agent.cli --random dadosdia1.json --force-llm --dry-run

  # parseia um log vindo do stdin (linha JSON OU bloco Message cru)
  echo '{"EventID":13,...}' | python -m silver_agent.cli -
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

from .agent import MAX_LLM_CALLS, parse_log
from .cache import DEFAULT_CACHE_PATH, MappingCache
from .groq_client import DEFAULT_MODEL, DEFAULT_MAX_OUTPUT_TOKENS, GroqParser


def _load_dotenv():
    """Carrega GROQ_API_KEY do .env sem dependência externa."""
    import os
    env = Path(".env")
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


def _random_line(path: str) -> str:
    """Amostra uma linha aleatória via reservoir sampling (não carrega o arquivo)."""
    chosen = None
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            if line.strip() and random.randint(1, i) == 1:
                chosen = line
    if chosen is None:
        sys.exit(f"Arquivo vazio: {path}")
    return chosen


def main(argv=None):
    p = argparse.ArgumentParser(description="Agente de parsing Bronze->Silver (Groq)")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("input", nargs="?", help="arquivo com 1 log, ou '-' p/ stdin")
    src.add_argument("--random", metavar="NDJSON", help="amostra 1 linha aleatória do arquivo")
    p.add_argument("--force-llm", action="store_true", help="sempre aciona o Groq")
    p.add_argument("--no-llm", action="store_true", help="só determinístico (0 tokens)")
    p.add_argument("--dry-run", action="store_true", help="estima tokens sem chamar a API")
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--max-output-tokens", type=int, default=DEFAULT_MAX_OUTPUT_TOKENS)
    p.add_argument("--max-llm-calls", type=int, default=MAX_LLM_CALLS)
    p.add_argument("--no-cache", action="store_true", help="desativa o cache de mapeamento")
    p.add_argument("--cache-path", default=str(DEFAULT_CACHE_PATH))
    p.add_argument("--compact", action="store_true", help="omite colunas nulas no output")
    args = p.parse_args(argv)

    _load_dotenv()

    if args.random:
        raw = _random_line(args.random)
        source_file = Path(args.random).stem
    elif args.input == "-":
        raw = sys.stdin.read()
        source_file = None
    else:
        raw = Path(args.input).read_text(encoding="utf-8", errors="replace")
        source_file = Path(args.input).stem

    groq = GroqParser(model=args.model, max_output_tokens=args.max_output_tokens)
    cache = None if args.no_cache else MappingCache(args.cache_path)
    res = parse_log(
        raw, source_file=source_file,
        use_llm=not args.no_llm, force_llm=args.force_llm,
        groq=groq, max_llm_calls=args.max_llm_calls, dry_run=args.dry_run,
        cache=cache,
    )

    silver = {k: v for k, v in res.silver.items() if v is not None} \
        if args.compact else res.silver

    print("=" * 72, file=sys.stderr)
    for t in res.trace:
        print("· " + t, file=sys.stderr)
    print(f"· LLM usado: {res.used_llm} | chamadas: {res.llm_calls}/"
          f"{args.max_llm_calls} | cache_hit: {res.cache_hit} | "
          f"tokens: {res.total_tokens} | dq_status: {res.silver['dq_status']}",
          file=sys.stderr)
    if cache is not None:
        print(f"· cache: {cache.stats()}", file=sys.stderr)
    print("=" * 72, file=sys.stderr)

    print(json.dumps(silver, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
