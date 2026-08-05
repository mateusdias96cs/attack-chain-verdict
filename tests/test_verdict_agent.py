"""
Testes determinísticos do Agente 4 — veredito final (SEM chamar o Gemini).

Cobrem o que é responsabilidade do agente (não do LLM): montagem do prompt, a trava
de GROUNDING (técnica atribuída tem de ser um candidato do RAG, senão vira NONE) e a
coerência confidence↔confidence_level.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from verdict_agent.agent import _ground, build_prompt
from verdict_agent.cli import print_report
from verdict_agent.schema import (ChainVerdictReport, ConfidenceLevel, EventVerdict,
                                   Verdict)


def _handoff():
    return {
        "entity": "SCRANTON/pbeesly",
        "prior_chain_verdict": {"verdict": "attack", "plausibility": 0.9,
                                "likely_tactics": ["Execution"]},
        "events": [
            {"index": 0, "time": "02:55:56", "raw": "proc scr",
             "description": "masqueraded screensaver executed",
             "candidates": [
                 {"attack_id": "T1036.002", "name": "Right-to-Left Override",
                  "score": 1.4, "tactics": "Defense Evasion", "is_subtechnique": True},
                 {"attack_id": "T1204.002", "name": "Malicious File",
                  "score": 0.5, "tactics": "Execution", "is_subtechnique": True}]},
            {"index": 1, "time": "02:55:59", "raw": "net 192.168.0.5",
             "description": "outbound connection to external ip",
             "candidates": [
                 {"attack_id": "T1133", "name": "External Remote Services",
                  "score": -3.4, "tactics": "Initial Access", "is_subtechnique": False}]},
        ],
    }


def test_build_prompt_lists_events_and_candidates():
    p = build_prompt(_handoff())
    assert "CHAIN ENTITY: SCRANTON/pbeesly" in p
    assert "[event 0]" in p and "[event 1]" in p
    assert "T1036.002" in p and "T1133" in p
    assert "PRIOR TEMPORAL SCREEN" in p  # contexto do agente 2 propagado


def test_grounding_forces_none_for_hallucinated_technique():
    """Se o LLM atribuir um T-ID FORA dos candidatos, o agente corrige p/ NONE."""
    report = ChainVerdictReport(
        entity="SCRANTON/pbeesly", overall_verdict=Verdict.attack,
        overall_confidence=0.9, attack_summary="x",
        events=[
            # evento 0: técnica inventada (não está nos candidatos) -> deve virar NONE
            EventVerdict(event="e0", step_title="t0", attack_id="T1071.001",
                         technique_name="Web Protocols", confidence=0.9,
                         confidence_level=ConfidenceLevel.high, rationale="r0"),
            # evento 1: candidato válido -> preservado
            EventVerdict(event="e1", step_title="t1", attack_id="T1133", technique_name="",
                         confidence=0.6, confidence_level=ConfidenceLevel.medium,
                         rationale="r1"),
        ])
    trace = []
    out = _ground(report, _handoff(), trace)
    assert out.events[0].attack_id == "NONE"
    assert out.events[0].confidence == 0.0
    assert out.events[0].confidence_level == ConfidenceLevel.none
    assert "correção" in out.events[0].rationale
    # candidato válido é mantido e o nome é preenchido a partir do candidato
    assert out.events[1].attack_id == "T1133"
    assert out.events[1].technique_name == "External Remote Services"
    assert any("fora dos candidatos" in t for t in trace)


def test_grounding_fixes_confidence_level_coherence():
    """confidence e confidence_level têm de concordar após a trava."""
    report = ChainVerdictReport(
        entity="e", overall_verdict=Verdict.attack, overall_confidence=0.9,
        attack_summary="x",
        events=[
            EventVerdict(event="e0", step_title="t0", attack_id="T1036.002",
                         technique_name="RTLO", confidence=0.95,
                         confidence_level=ConfidenceLevel.low,  # incoerente
                         rationale="r"),
            EventVerdict(event="e1", step_title="t1", attack_id="T1133", technique_name="ERS",
                         confidence=0.6, confidence_level=ConfidenceLevel.high,  # incoerente
                         rationale="r"),
        ])
    out = _ground(report, _handoff(), [])
    assert out.events[0].confidence_level == ConfidenceLevel.high    # 0.95 -> high
    assert out.events[1].confidence_level == ConfidenceLevel.medium  # 0.60 -> medium


def test_grounding_pads_missing_event_verdicts():
    """Se o LLM devolver menos vereditos que eventos, o faltante vira NONE explícito."""
    report = ChainVerdictReport(
        entity="e", overall_verdict=Verdict.attack, overall_confidence=0.9,
        attack_summary="x",
        events=[EventVerdict(event="e0", step_title="t0", attack_id="T1036.002",
                             technique_name="RTLO", confidence=0.9,
                             confidence_level=ConfidenceLevel.high,
                             rationale="r")])
    out = _ground(report, _handoff(), [])
    assert len(out.events) == 2
    assert out.events[1].attack_id == "NONE"


def test_tactic_comes_from_rag_candidate_not_from_model():
    """A fase da cadeia é metadado do candidato do RAG, nunca texto do LLM."""
    report = ChainVerdictReport(
        entity="e", overall_verdict=Verdict.attack, overall_confidence=0.9,
        attack_summary="x",
        events=[
            EventVerdict(event="e0", step_title="t0", attack_id="T1036.002",
                         technique_name="RTLO", tactic="tática inventada pelo modelo",
                         confidence=0.9, confidence_level=ConfidenceLevel.high,
                         rationale="r"),
            EventVerdict(event="e1", step_title="t1", attack_id="NONE",
                         technique_name="", tactic="lixo", confidence=0.0,
                         confidence_level=ConfidenceLevel.none, rationale="r"),
        ])
    out = _ground(report, _handoff(), [])
    assert out.events[0].tactic == "Defense Evasion"  # veio do candidato
    assert out.events[1].tactic == ""                 # NONE não tem fase


def test_empty_step_title_falls_back_to_event_description():
    """Título vazio não pode virar passo anônimo no relatório."""
    report = ChainVerdictReport(
        entity="e", overall_verdict=Verdict.attack, overall_confidence=0.9,
        attack_summary="x",
        events=[
            EventVerdict(event="e0", step_title="   ", attack_id="T1036.002",
                         technique_name="RTLO", confidence=0.9,
                         confidence_level=ConfidenceLevel.high, rationale="r"),
            EventVerdict(event="e1", step_title="ok", attack_id="T1133",
                         technique_name="ERS", confidence=0.6,
                         confidence_level=ConfidenceLevel.medium, rationale="r"),
        ])
    trace = []
    out = _ground(report, _handoff(), trace)
    assert out.events[0].step_title == "masqueraded screensaver executed"
    assert any("step_title vazio" in t for t in trace)


def test_all_tactics_of_the_indexed_base_have_a_portuguese_phase():
    """Toda tática da base v19.1 precisa de tradução, senão a fase sai em inglês.

    A v19.1 não tem mais "Defense Evasion": ela virou "Stealth" e "Defense
    Impairment". Este teste trava a lista contra a base que o índice usa.
    """
    from verdict_agent.cli import _fase_pt

    taticas_v19 = [
        "Reconnaissance", "Resource Development", "Initial Access", "Execution",
        "Persistence", "Privilege Escalation", "Stealth", "Defense Impairment",
        "Credential Access", "Discovery", "Lateral Movement", "Collection",
        "Command and Control", "Exfiltration", "Impact",
    ]
    for t in taticas_v19:
        assert _fase_pt(t) != t, f"tática sem tradução: {t}"
    assert _fase_pt("Stealth") == "Furtividade"
    assert _fase_pt("Defense Impairment") == "Degradação de defesas"
    # técnica com mais de uma tática mantém as duas fases
    assert _fase_pt("Execution, Persistence") == "Execução, Persistência"
    # tática desconhecida passa pelo fallback sem quebrar
    assert _fase_pt("Tática Nova") == "Tática Nova"
    assert _fase_pt("") == ""


def test_report_renders_as_numbered_narrative(capsys):
    """A saída legível é uma cadeia numerada em prosa, não a linha crua do log."""
    report = ChainVerdictReport(
        entity="SCRANTON/pbeesly", overall_verdict=Verdict.attack,
        overall_confidence=0.92,
        attack_summary="O atacante executou um arquivo mascarado e abriu um canal externo.",
        events=[
            EventVerdict(event="proc scr", step_title="Execução do arquivo mascarado cod.3aka3.scr",
                         attack_id="T1036.002", technique_name="Right-to-Left Override",
                         tactic="Defense Evasion", confidence=0.95,
                         confidence_level=ConfidenceLevel.high,
                         rationale="O arquivo usa um caractere de inversão de escrita para "
                                   "parecer inofensivo e foi executado pela conta do usuário."),
            EventVerdict(event="net 192.168.0.5", step_title="Conexão de saída para 192.168.0.5",
                         attack_id="NONE", technique_name="", confidence=0.0,
                         confidence_level=ConfidenceLevel.none,
                         rationale="A conexão foi observada, mas nenhum candidato se aplica."),
        ])
    print_report(report, {"total_tokens": 10})
    saida = capsys.readouterr().out

    assert "1º" in saida and "2º" in saida               # cadeia numerada
    assert "Execução do arquivo mascarado cod.3aka3.scr" in saida
    assert "Evasão de defesas" in saida                  # fase traduzida (nome legado)
    assert "alta (95%)" in saida                         # confiança em palavras
    assert "nenhuma técnica se aplica" in saida          # passo sem técnica é explicado
    assert "ATAQUE" in saida
    # o rótulo cru do evento não vira o título do passo
    assert "[0] proc scr" not in saida


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
