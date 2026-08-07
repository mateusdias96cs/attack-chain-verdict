"""Testes do módulo de consistência de TTP por grafo.

O foco é nas TRAVAS, não no caminho feliz: a feature só se justifica se ela calar
quando não tem o que dizer e se ela não virar uma máquina de confirmar o ator do
dataset. Rode:  python -m pytest tests/test_ttp_graph.py -q
"""
from __future__ import annotations

import math

import pytest

from verdict_agent import ttp_graph as tg


def chain(*rows: list[str]) -> dict:
    return {"entity": "t", "events": [
        {"index": i, "candidates": [{"attack_id": a} for a in r]}
        for i, r in enumerate(rows)]}


# Listas REAIS de candidatos do Agente 3 (do eval do golden set), numa combinação que
# PASSA no portão de discriminação. Precisa disparar, senão as asserções antiviés
# passariam vacuamente sobre uma lista vazia e o teste não testaria nada.
REAL_CHAIN = chain(
    ["T1078.004", "T1078", "T1558.004", "T1586", "T1110.003", "T1552.001",
     "T1555.002", "T1556.001", "T1555.003"],
    ["T1059.001", "T1546.013", "T1202", "T1059", "T1690", "T1677", "T1059.005",
     "T1059.003"],
    ["T1134.002", "T1543", "T1543.002", "T1055.012", "T1053.005", "T1574.011",
     "T1053.002", "T1543.003", "T1202"],
    ["T1127.002", "T1055.001", "T1547.001", "T1218.003", "T1218.011", "T1218",
     "T1218.013", "T1218.008", "T1218.010"])

# Combinação que NÃO discrimina (topo empatado com o pelotão): usada para provar que a
# supressão dispara em cadeia real, não só na degenerada.
FLAT_CHAIN = chain(
    ["T1078.004", "T1078", "T1558.004", "T1586", "T1110.003", "T1552.001"],
    ["T1546.002", "T1218.011", "T1574.004", "T1574.013", "T1036.002", "T1036.008"],
    ["T1547.001", "T1134.002", "T1543", "T1564.010", "T1560.001", "T1560.002"],
    ["T1569.002", "T1055.012", "T1055.004", "T1127.002", "T1572", "T1071.001"])


def test_fixture_realmente_dispara():
    """Guarda-chuva: se REAL_CHAIN parar de disparar, os testes abaixo viram vacuosos."""
    ev = tg.analyze(REAL_CHAIN)
    assert not ev.empty, f"fixture não dispara mais ({ev.suppressed}); recalibre-o"
    assert len(ev.groups) >= 2


def test_grafo_carrega_com_dois_saltos():
    """Repertório inclui grupo->técnica E grupo->software->técnica."""
    rep, usage = tg._load()
    assert len(rep) > 150, "esperado ~174 intrusion-sets ativos"
    # APT29 usa muito mais técnicas via software do que diretamente
    assert len(rep["APT29"]) > 150, "travessia de 2 saltos não aconteceu"
    assert usage["T1071.001"] > 100, "técnica comum deveria ter uso alto"


def test_repertorio_grande_nao_vence_por_tamanho():
    """Anti-viés nº1: o ator do dataset (APT29) tem o MAIOR repertório (230).

    Sem a normalização por especificidade ele venceria toda cadeia, e a feature
    viraria uma profecia autorrealizável no dataset do projeto.
    """
    rep, _ = tg._load()
    assert len(rep["APT29"]) == max(len(v) for v in rep.values())
    ev = tg.analyze(REAL_CHAIN)
    nomes = [g.name for g in ev.groups]
    assert "APT29" not in nomes, "APT29 apareceu no topo apesar da normalização"


def test_repertorio_minusculo_e_filtrado():
    """Anti-viés nº2: grupo subdocumentado não pode liderar por artefato."""
    rep, _ = tg._load()
    for g in tg.analyze(REAL_CHAIN).groups:
        assert g.repertoire_size >= tg.MIN_REPERTOIRE


def test_suprime_quando_nao_discrimina():
    """Anti-viés nº3: cadeia degenerada (1 candidato/evento) não discrimina nada,
    porque todo grupo que cobre tudo recebe o mesmo score."""
    degenerada = chain(["T1059.001"], ["T1105"], ["T1071.001"], ["T1547.001"])
    ev = tg.analyze(degenerada)
    assert ev.empty and ev.suppressed, "deveria suprimir por falta de poder discriminante"
    assert tg.render(ev) == ""


def test_suprime_tambem_em_cadeia_real_sem_sinal():
    """A supressão não pode depender de input degenerado: cadeia real e plausível
    em que o topo empata com o pelotão também tem de calar."""
    ev = tg.analyze(FLAT_CHAIN)
    assert ev.empty and "discriminante" in ev.suppressed
    assert tg.render(ev) == ""


def test_so_lista_tecnica_distintiva():
    """Técnica usada por 80% dos grupos não entra no prompt: não informa e gasta token."""
    ev = tg.analyze(REAL_CHAIN)
    rep, usage = tg._load()
    limite = tg.DISTINCTIVE_MAX_SHARE * len(rep)
    for aid in ev.in_repertoire:
        assert usage.get(aid, usage.get(aid.split(".")[0], 0)) <= limite


def test_render_enquadra_como_sinal_fraco():
    """O bloco tem de conter o aviso; sem ele o LLM trata atribuição como prova."""
    ev = tg.analyze(REAL_CHAIN)
    if ev.empty:
        pytest.skip("cadeia suprimida nesta calibração")
    txt = tg.render(ev)
    assert "CAVEAT" in txt and "NEVER" in txt
    assert "Do not name or attribute the actor" in txt


def test_cadeia_vazia_nao_quebra():
    ev = tg.analyze({"entity": "x", "events": []})
    assert ev.empty and tg.render(ev) == ""


def test_idf_penaliza_tecnica_comum():
    """A ponderação tem de dar peso ~0 para o que todo mundo usa."""
    rep, usage = tg._load()
    n = len(rep)
    comum = math.log(n / (1 + usage["T1071.001"]))     # ~139 grupos
    rara = math.log(n / (1 + usage["T1036.002"]))      # ~5 grupos
    assert rara > comum * 3, "raridade não está dominando a ponderação"
