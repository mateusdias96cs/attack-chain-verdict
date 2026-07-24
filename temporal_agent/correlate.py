"""
Correlação temporal determinística sobre a Gold (0 tokens).

Duas bases de ligação (escolha do usuário):
  1. Timeline por entidade — eventos de um mesmo (host, conta de ator) ordenados por
     `event_utc_time`. Captura a sequência dentro de um cenário e ATRAVÉS do gap de
     4,5h se a mesma entidade agir nos dois momentos.
  2. Artefato compartilhado — arestas entre eventos que dividem hash/IP de C2/arquivo
     dropado→executado/chave de registro. Ligam dia1↔dia2 mesmo com host/usuário
     diferentes (é assim que "o mesmo traço de ataque" cruza o gap neste dataset).

INVARIANTE: `source_file` nunca entra em nenhum PARTITION/ORDER — a ordenação é sempre
por `event_utc_time` numa linha do tempo única. `source_file` só é lido para ROTULAR
se uma aresta é cross-dia.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import duckdb

# categorias que interessam numa trilha de ataque (reduz ruído de telemetria)
NOTABLE_CATEGORIES = (
    "process_create", "network_connect", "network_bind", "dns_query",
    "create_remote_thread", "process_access", "file_create", "file_delete",
    "registry_set_value", "registry_create_delete",
    "powershell_pipeline", "powershell_module", "powershell_script_block",
)


@dataclass
class Step:
    time: str
    event_utc_time: object
    source_file: str
    host: str
    actor: str | None
    event_id: int
    category: str
    image_name: str | None
    artifact: str | None       # o artefato mais informativo do evento
    record_number: int

    def line(self) -> str:
        """Uma linha compacta para o LLM (economia de token)."""
        who = f"{self.host}/{self.actor or '-'}"
        art = f" | {self.artifact}" if self.artifact else ""
        img = f" {self.image_name}" if self.image_name else ""
        return f"{self.time} {who} {self.category}{img}{art}"


@dataclass
class Chain:
    kind: str                      # 'entity_timeline' | 'artifact_bridge'
    entity: str                    # rótulo (host/actor ou artefato)
    steps: list[Step] = field(default_factory=list)
    source_files: set = field(default_factory=set)
    hosts: set = field(default_factory=set)
    actors: set = field(default_factory=set)

    @property
    def cross_day(self) -> bool:
        return len(self.source_files) > 1

    @property
    def span_seconds(self) -> float:
        if len(self.steps) < 2:
            return 0.0
        return (self.steps[-1].event_utc_time - self.steps[0].event_utc_time).total_seconds()

    def summary(self) -> dict:
        return {
            "kind": self.kind, "entity": self.entity, "n_steps": len(self.steps),
            "cross_day": self.cross_day, "source_files": sorted(self.source_files),
            "hosts": sorted(self.hosts), "actors": sorted(a for a in self.actors if a),
            "start": str(self.steps[0].event_utc_time) if self.steps else None,
            "end": str(self.steps[-1].event_utc_time) if self.steps else None,
            "span_seconds": round(self.span_seconds, 1),
        }


# artefato mais informativo por categoria de evento
_ARTIFACT_EXPR = """
    CASE
        WHEN event_category LIKE 'network%' THEN destination_ip ||
             CASE WHEN destination_port IS NOT NULL THEN ':' || destination_port ELSE '' END
        WHEN event_category = 'dns_query' THEN dns_query_name
        WHEN event_category = 'file_create' OR event_category='file_delete' THEN target_filename
        WHEN event_category LIKE 'registry%' THEN registry_target_object
        WHEN event_category LIKE 'powershell%' THEN command_line
        WHEN event_category = 'process_access' THEN target_image
        ELSE coalesce(command_line, image_path)
    END
"""


def _rows(con: duckdb.DuckDBPyConnection, sql: str) -> list[dict]:
    """Executa e retorna list[dict] sem depender de pandas/numpy."""
    cur = con.execute(sql)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def _row_to_step(r: dict) -> Step:
    t = r["event_utc_time"]
    return Step(
        time=t.strftime("%H:%M:%S"), event_utc_time=t,
        source_file=r["source_file"], host=r["hostname_nk"], actor=r["subject_account"],
        event_id=r["event_id"], category=r["event_category"],
        image_name=r["image_name"], artifact=(r["artifact"] or None),
        record_number=r["record_number"],
    )


def entity_timelines(con: duckdb.DuckDBPyConnection,
                     min_steps: int = 4,
                     notable_only: bool = True,
                     limit_entities: int = 20) -> list[Chain]:
    """Cadeias por (host, conta de ator), ordenadas por event_utc_time (sem source_file)."""
    cat_filter = ("AND event_category IN " +
                  "(" + ",".join(f"'{c}'" for c in NOTABLE_CATEGORIES) + ")") if notable_only else ""
    rows = _rows(con, f"""
        SELECT hostname_nk, subject_account, source_file, event_utc_time, event_id,
               event_category, image_name, record_number,
               {_ARTIFACT_EXPR} AS artifact
        FROM fact_security_event
        WHERE is_actor {cat_filter}
        ORDER BY hostname_nk, subject_account, event_utc_time, record_number
    """)

    chains: dict[tuple, Chain] = {}
    for r in rows:
        key = (r["hostname_nk"], r["subject_account"])
        ch = chains.get(key)
        if ch is None:
            ch = Chain(kind="entity_timeline", entity=f"{key[0]}/{key[1]}")
            chains[key] = ch
        step = _row_to_step(r)
        # colapsa repetições consecutivas idênticas (mesma categoria+artefato)
        if ch.steps and ch.steps[-1].category == step.category \
                and ch.steps[-1].artifact == step.artifact:
            continue
        ch.steps.append(step)
        ch.source_files.add(step.source_file)
        ch.hosts.add(step.host)
        ch.actors.add(step.actor)

    out = [c for c in chains.values() if len(c.steps) >= min_steps]
    out.sort(key=lambda c: len(c.steps), reverse=True)
    return out[:limit_entities]


def artifact_edges(con: duckdb.DuckDBPyConnection,
                   cross_day_only: bool = False,
                   limit: int = 200) -> list[dict]:
    """Arestas entre eventos que compartilham um artefato forte (hash / IP de C2 /
    drop→exec / chave de registro). Podem cruzar host, usuário e source_file."""
    cross = "WHERE a.source_file <> b.source_file" if cross_day_only else "WHERE TRUE"

    # 1) mesmo binário (hash SHA256)
    hash_edges = _rows(con, f"""
        SELECT 'hash' AS kind, a.hash_sha256 AS key,
               a.source_file AS a_file, b.source_file AS b_file,
               a.hostname_nk AS a_host, b.hostname_nk AS b_host,
               a.image_name AS a_img, b.image_name AS b_img,
               a.event_utc_time AS a_time, b.event_utc_time AS b_time,
               a.record_number AS a_rn, b.record_number AS b_rn
        FROM fact_security_event a
        JOIN fact_security_event b
          ON a.hash_sha256 = b.hash_sha256
         AND a.hash_sha256 <> ''
         AND a.event_utc_time < b.event_utc_time
        {cross.replace('a.source_file','a.source_file')}
        QUALIFY row_number() OVER (PARTITION BY a.hash_sha256 ORDER BY a.event_utc_time, b.event_utc_time) = 1
        LIMIT {limit}
    """)

    # 2) mesmo destino de rede (C2)
    ip_edges = _rows(con, f"""
        SELECT 'dest_ip' AS kind, a.destination_ip AS key,
               a.source_file AS a_file, b.source_file AS b_file,
               a.hostname_nk AS a_host, b.hostname_nk AS b_host,
               a.image_name AS a_img, b.image_name AS b_img,
               a.event_utc_time AS a_time, b.event_utc_time AS b_time,
               a.record_number AS a_rn, b.record_number AS b_rn
        FROM fact_security_event a
        JOIN fact_security_event b
          ON a.destination_ip = b.destination_ip
         AND a.destination_ip IS NOT NULL AND a.destination_ip <> ''
         AND a.event_utc_time < b.event_utc_time
        {cross}
          AND a.destination_ip NOT LIKE '10.%' AND a.destination_ip NOT LIKE '224.%'
          AND a.destination_ip NOT LIKE 'ff02%' AND a.destination_ip NOT LIKE '169.254%'
        QUALIFY row_number() OVER (PARTITION BY a.destination_ip ORDER BY a.event_utc_time, b.event_utc_time) = 1
        LIMIT {limit}
    """)

    # 3) arquivo dropado (file_create) depois EXECUTADO (process_create com mesma imagem)
    drop_exec = _rows(con, f"""
        SELECT 'drop_exec' AS kind, a.target_filename AS key,
               a.source_file AS a_file, b.source_file AS b_file,
               a.hostname_nk AS a_host, b.hostname_nk AS b_host,
               a.image_name AS a_img, b.image_name AS b_img,
               a.event_utc_time AS a_time, b.event_utc_time AS b_time,
               a.record_number AS a_rn, b.record_number AS b_rn
        FROM fact_security_event a
        JOIN fact_security_event b
          ON lower(a.target_filename) = lower(b.image_path)
         AND a.target_filename IS NOT NULL AND a.target_filename <> ''
         AND a.event_category = 'file_create' AND b.event_category = 'process_create'
         AND a.event_utc_time < b.event_utc_time
        {cross}
        QUALIFY row_number() OVER (PARTITION BY lower(a.target_filename) ORDER BY a.event_utc_time, b.event_utc_time) = 1
        LIMIT {limit}
    """)

    edges = hash_edges + ip_edges + drop_exec
    for e in edges:
        e["cross_day"] = e["a_file"] != e["b_file"]
        e["gap_seconds"] = round((e["b_time"] - e["a_time"]).total_seconds(), 1)
    return edges
