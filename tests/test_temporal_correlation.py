"""
Testes do Agente 2 — correlação temporal, isoladamente contra a Gold.

Dois blocos (escolha do usuário):
  * Sanidade   — ordenação temporal correta, isolamento por entidade, causalidade
                 ProcessCreate→NetworkConnect, e a INVARIANTE central: source_file
                 NÃO é fronteira (a correlação atravessa dia1↔dia2).
  * Reconstrução cross-dia — o elo de continuidade dia1↔dia2 existe e atravessa o gap
                 de ~4,5h via artefato compartilhado (hash), e a cadeia de ataque
                 APT29 (pbeesly@SCRANTON) é reconstruída deterministicamente.

Determinísticos: NÃO chamam a API do Groq (sem custo/segredo). Constroem a Gold numa
amostra dos NDJSON reais.

Run:  pytest tests/test_temporal_correlation.py -v
Deps: pip install duckdb        (groq NÃO é necessário para estes testes)
Env:  AGENTECVE_TEMPORAL_SAMPLE=40000   # linhas por arquivo (default 40000)
"""
from __future__ import annotations

import os
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(ROOT))

duckdb = pytest.importorskip("duckdb")

from temporal_agent.correlate import artifact_edges, entity_timelines  # noqa: E402
from temporal_agent.gold import DATA_FILES, build_gold                 # noqa: E402

SAMPLE = int(os.environ.get("AGENTECVE_TEMPORAL_SAMPLE", "40000"))


@pytest.fixture(scope="session")
def gold(tmp_path_factory):
    missing = [str(f) for f in DATA_FILES if not f.exists()]
    if missing:
        pytest.skip(f"dados de origem não encontrados: {missing}")
    tmp = tmp_path_factory.mktemp("temporal_gold")
    con = duckdb.connect(str(tmp / "t.duckdb"))
    con.execute(f"PRAGMA temp_directory='{(tmp / 'spill').as_posix()}'")
    con.execute("PRAGMA memory_limit='4GB'")
    con.execute("PRAGMA threads=2")
    con.execute("PRAGMA preserve_insertion_order=false")
    build_gold(con, sample=SAMPLE)
    yield con
    con.close()


def scalar(con, sql):
    return con.execute(sql).fetchone()[0]


# ======================================================================================
# SANIDADE
# ======================================================================================
class TestSanidade:
    def test_gold_populada_dois_arquivos(self, gold):
        assert scalar(gold, "SELECT count(*) FROM fact_security_event") > 0
        files = {r[0] for r in gold.execute(
            "SELECT DISTINCT source_file FROM fact_security_event").fetchall()}
        assert files == {"dadosdia1", "dadosdia2"}, files

    def test_linha_do_tempo_unica_e_sequencial(self, gold):
        """dia1 inteiro precede dia2 → há UMA linha do tempo ordenável por event_utc_time,
        com um gap real no meio (o 'atacante espera e retoma')."""
        max1 = scalar(gold, "SELECT max(event_utc_time) FROM fact_security_event WHERE source_file='dadosdia1'")
        min2 = scalar(gold, "SELECT min(event_utc_time) FROM fact_security_event WHERE source_file='dadosdia2'")
        assert min2 > max1, "esperado dia2 inteiramente após dia1 (linha do tempo sequencial)"
        gap_h = (min2 - max1).total_seconds() / 3600
        assert gap_h > 1.0, f"esperado gap > 1h entre os arquivos, obtido {gap_h:.2f}h"

    def test_timeline_monotonica_no_tempo(self, gold):
        """Cada cadeia por entidade é não-decrescente em event_utc_time."""
        for c in entity_timelines(gold, min_steps=4):
            times = [s.event_utc_time for s in c.steps]
            assert times == sorted(times), f"cadeia {c.entity} fora de ordem temporal"

    def test_entity_timeline_nao_mistura_hosts(self, gold):
        """Isolamento: uma timeline de entidade é de um único host (chave = host+ator)."""
        for c in entity_timelines(gold, min_steps=4):
            assert len(c.hosts) == 1, f"cadeia {c.entity} mistura hosts: {c.hosts}"

    def test_processcreate_antes_de_networkconnect(self, gold):
        """Causalidade: para um mesmo process_guid, o ProcessCreate (EID 1) não ocorre
        DEPOIS da primeira conexão de rede (EID 3) daquele processo."""
        violacoes = scalar(gold, """
            WITH pc AS (
                SELECT process_guid, min(event_utc_time) AS t_create
                FROM fact_security_event WHERE event_id = 1 AND process_guid IS NOT NULL
                GROUP BY process_guid
            ),
            nc AS (
                SELECT process_guid, min(event_utc_time) AS t_net
                FROM fact_security_event WHERE event_id = 3 AND process_guid IS NOT NULL
                GROUP BY process_guid
            )
            SELECT count(*) FROM pc JOIN nc USING (process_guid)
            WHERE nc.t_net < pc.t_create
        """)
        assert violacoes == 0, f"{violacoes} processos com NetworkConnect antes do ProcessCreate"

    def test_source_file_nao_e_fronteira(self, gold):
        """A correlação DEVE poder atravessar source_file (senão dia1/dia2 ficariam
        artificialmente separados). Prova: existem arestas de artefato cross-dia."""
        edges = artifact_edges(gold, cross_day_only=True, limit=50)
        assert len(edges) > 0, "nenhuma aresta cross-dia — source_file estaria separando indevidamente"
        assert all(e["a_file"] != e["b_file"] for e in edges)


# ======================================================================================
# RECONSTRUÇÃO CROSS-DIA (continuidade do traço de ataque)
# ======================================================================================
class TestReconstrucaoCrossDia:
    def test_aresta_cross_dia_atravessa_o_gap(self, gold):
        """Pelo menos uma aresta de artefato liga dia1→dia2 atravessando o gap (> 1h)."""
        edges = artifact_edges(gold, cross_day_only=True, limit=100)
        long_bridges = [e for e in edges if e["gap_seconds"] > 3600]
        assert long_bridges, "nenhuma aresta cross-dia atravessa o gap de >1h"
        # e o gap deve bater com a distância real entre os arquivos (~4-5h)
        assert max(e["gap_seconds"] for e in long_bridges) > 4000

    def test_hash_de_ferramenta_compartilhado_entre_dias(self, gold):
        """O elo de continuidade concreto: existe um binário (hash SHA256) usado nos
        DOIS dias — 'mesmo traço de ataque' reutilizando ferramenta através do gap."""
        compartilhados = scalar(gold, """
            SELECT count(*) FROM (
                SELECT hash_sha256 FROM fact_security_event
                WHERE hash_sha256 <> ''
                GROUP BY hash_sha256 HAVING count(DISTINCT source_file) = 2
            )
        """)
        assert compartilhados > 0, "esperado ao menos um hash de ferramenta em ambos os dias"

    def test_cadeia_de_ataque_apt29_reconstruida(self, gold):
        """Reconstrução determinística: a timeline de pbeesly@SCRANTON (dia1) contém a
        sequência de ataque — binário mascarado seguido de conexão a C2 externo."""
        chains = {c.entity: c for c in entity_timelines(gold, min_steps=4)}
        alvo = next((c for e, c in chains.items()
                     if e.startswith("SCRANTON/") and "pbeesly" in e), None)
        assert alvo is not None, "cadeia SCRANTON/pbeesly não reconstruída"

        cats = [s.category for s in alvo.steps]
        assert "process_create" in cats and "network_connect" in cats

        # binário mascarado (cod.3aka3.scr) presente em algum passo
        blob = " ".join((s.artifact or "") + " " + (s.image_name or "") for s in alvo.steps)
        assert "cod.3aka3.scr" in blob, "artefato de ataque mascarado ausente na cadeia"

        # o process_create do binário mascarado precede a conexão de rede (ordem causal)
        t_exec = next(s.event_utc_time for s in alvo.steps
                      if s.category == "process_create" and "cod.3aka3.scr" in (s.artifact or ""))
        t_net = next(s.event_utc_time for s in alvo.steps if s.category == "network_connect")
        assert t_exec <= t_net, "conexão de rede antes da execução do binário (ordem incorreta)"
