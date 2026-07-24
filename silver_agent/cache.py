"""
Cache de mapeamento (LLM-como-inferência-de-schema + execução determinística).

Logs do Windows são altamente repetitivos: numa amostra de 240k registros, os
que acionam o LLM se resumem a ~68 "shapes" distintos (EventID + conjunto de
campos não-mapeados). Cachear a DECISÃO de mapeamento por shape reduz as
chamadas ao Groq em ~99,7%.

NÃO cacheamos valores parseados (mudam a cada log: SID, PID, timestamp). Cacheamos
o *plano*: para este shape, o campo bruto `X` vai na coluna Silver `Y`. Na próxima
vez que aparece o mesmo shape, aplicamos o plano aos valores DAQUELE log — 0 tokens,
valores corretos.

Segurança: só marcamos um shape como cacheável quando provamos que a saída do LLM
é uma renomeação pura (todo valor devolvido rastreia até um campo bruto do log).
Shapes "sujos" (ex.: valores extraídos de um Message verboso) viram `llm_always` e
nunca reaproveitam valor — correção nunca é trocada por economia.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_CACHE_PATH = Path(__file__).with_name(".mapping_cache.json")


def _norm(v) -> str:
    """Normaliza um valor para comparação (tolerante a int hex/decimal e caixa)."""
    if v is None:
        return ""
    s = str(v).strip()
    m = re.fullmatch(r"0x[0-9a-fA-F]+|\d+", s)
    if m:
        try:
            return str(int(s, 16) if s.lower().startswith("0x") else int(s))
        except ValueError:
            pass
    return s.casefold()


def derive_mapping(unmapped_values: dict, llm_data: dict) -> dict | None:
    """Rastreia cada coluna que o LLM preencheu até um campo bruto não-mapeado.

    Retorna {source_key: silver_col} se TODA a contribuição do LLM for uma
    renomeação pura de chaves; retorna None se algum valor não rastrear (shape
    'sujo' → não cacheável). Um dict vazio (LLM não extraiu nada) é um plano
    válido: memoriza "nada a extrair aqui", pulando o LLM nas próximas vezes.
    """
    idx: dict[str, str] = {}
    for k, v in unmapped_values.items():
        nv = _norm(v)
        if nv:
            idx.setdefault(nv, k)
    mapping: dict[str, str] = {}
    used: set[str] = set()
    for col, val in llm_data.items():
        nv = _norm(val)
        src = idx.get(nv)
        if src is None or src in used:
            return None  # valor não rastreável a um campo bruto → shape sujo
        mapping[src] = col
        used.add(src)
    return mapping


class MappingCache:
    def __init__(self, path: str | Path = DEFAULT_CACHE_PATH):
        self.path = Path(path)
        self._data: dict[str, dict] = {}
        self._dirty = False
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._data = {}

    @staticmethod
    def shape_key(event_id, log_source: str, unmapped_keys) -> str:
        keys = ",".join(sorted(unmapped_keys))
        return f"{event_id}|{log_source}|{keys}"

    def get(self, shape: str) -> dict | None:
        return self._data.get(shape)

    def put_map(self, shape: str, mapping: dict):
        self._data[shape] = {
            "kind": "map", "map": mapping,
            "learned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "hits": 0,
        }
        self._dirty = True

    def put_llm_always(self, shape: str):
        self._data[shape] = {
            "kind": "llm_always",
            "learned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "hits": 0,
        }
        self._dirty = True

    def bump(self, shape: str):
        if shape in self._data:
            self._data[shape]["hits"] = self._data[shape].get("hits", 0) + 1
            self._dirty = True

    def save(self):
        if not self._dirty:
            return
        try:
            self.path.write_text(
                json.dumps(self._data, ensure_ascii=False, indent=2),
                encoding="utf-8")
            self._dirty = False
        except OSError:
            pass

    def stats(self) -> dict:
        maps = sum(1 for e in self._data.values() if e["kind"] == "map")
        always = sum(1 for e in self._data.values() if e["kind"] == "llm_always")
        hits = sum(e.get("hits", 0) for e in self._data.values())
        return {"shapes": len(self._data), "map": maps,
                "llm_always": always, "total_hits": hits}
