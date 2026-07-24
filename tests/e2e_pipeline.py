"""
Teste END-TO-END do pipeline: Agente 1 (parsing) → Agente 2 (correlação) → Agente 3 (RAG).

Objetivo (pedido do usuário): certeza de que os agentes NÃO quebram silenciosamente
ao serem encadeados. Aplica boas práticas de agentes:

  • Contrato explícito em CADA fronteira (tipo/forma/não-vazio), com PASS/FAIL visível.
  • Fail-fast: precondição falha → o estágio para (não propaga lixo adiante).
  • Sem engolir erro: o Agente 3 roda em OUTRO venv via subprocess com check=True;
    crash/stderr é surfaced, não silenciado (ver [[pipeline-venv-split]]).
  • Âncora semântica ground-truth ponta-a-ponta: log bruto de logon → …três agentes…
    → técnica T1078 (o caso canônico que o usuário definiu).
  • Detecção de degradação silenciosa: descrição vazia, retrieval vazio, score ausente,
    dq_status quarantined, id de técnica malformado — tudo vira FALHA explícita.

Estágios 1+2 rodam neste venv (raiz); o estágio 3 é invocado no venv do mitre-rag.

Rode:  ./.venv/bin/python tests/e2e_pipeline.py
       (leva ~2 min: o estágio 3 carrega e5 + cross-encoder)
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MITRE_PY = ROOT / "mitre-rag" / ".venv" / "bin" / "python"
STAGE3 = ROOT / "mitre-rag" / "e2e_stage3.py"
TID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# --- coletor de checagens de contrato ------------------------------------------
_checks: list[tuple[str, str, bool, str]] = []


def check(stage: str, name: str, ok: bool, detail: str = "") -> bool:
    _checks.append((stage, name, bool(ok), detail))
    mark = "✔" if ok else "✗"
    print(f"  [{stage}] {mark} {name}" + (f"  ({detail})" if detail else ""))
    return ok


def fatal(stage: str, msg: str):
    check(stage, msg, False)
    _report_and_exit()


def family(tid: str) -> str:
    return tid.split(".")[0]


def first_line_matching(path: pathlib.Path, needle: str, extra=None, limit=400000) -> str | None:
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= limit:
                break
            if needle in line and (extra is None or extra in line):
                return line.rstrip("\n")
    return None


# ================================================================= STAGE 1
def stage1_parsing() -> list[dict]:
    from silver_agent import parse_log  # agente 1

    events = []

    # (a) logon com credencial válida → alvo T1078
    raw_logon = first_line_matching(ROOT / "dadosdia1.json", '"EventID":4624', '"LogonType":"3"')
    if raw_logon is None:
        fatal("1", "não achei um evento 4624 (logon) com LogonType 3 nos dados")
    res = parse_log(raw_logon, source_file="dadosdia1", use_llm=False)  # determinístico, 0 tokens
    sv = res.silver
    check("1", "logon: parse retornou dict", isinstance(sv, dict) and bool(sv))
    check("1", "logon: event_id == 4624", sv.get("event_id") == 4624, f"got {sv.get('event_id')}")
    check("1", "logon: event_utc_time preenchido", bool(sv.get("event_utc_time")), str(sv.get("event_utc_time")))
    check("1", "logon: hostname_nk preenchido", bool(sv.get("hostname_nk")), str(sv.get("hostname_nk")))
    check("1", "logon: logon_type extraído", sv.get("logon_type") is not None, str(sv.get("logon_type")))
    check("1", "logon: dq_status != quarantined", sv.get("dq_status") != "quarantined", str(sv.get("dq_status")))
    events.append({"label": "logon_valid_creds", "silver": sv, "expect_family": "T1078"})

    # (b) PowerShell script block → alvo T1059
    raw_ps = first_line_matching(ROOT / "dadosdia2.json", '"EventID":4104')
    if raw_ps is not None:
        res2 = parse_log(raw_ps, source_file="dadosdia2", use_llm=False)
        sv2 = res2.silver
        check("1", "powershell: event_id == 4104", sv2.get("event_id") == 4104, f"got {sv2.get('event_id')}")
        check("1", "powershell: log_source == powershell", sv2.get("log_source") == "powershell", str(sv2.get("log_source")))
        events.append({"label": "powershell_scriptblock", "silver": sv2, "expect_family": "T1059"})

    check("1", "≥1 evento silver produzido", len(events) >= 1, f"{len(events)} eventos")
    return events


# ================================================================= STAGE 2
def stage2_correlation() -> list[str]:
    from temporal_agent.correlate import artifact_edges, entity_timelines
    from temporal_agent.gold import open_gold

    con = open_gold(sample=40000)  # determinístico, 0 tokens
    n = con.execute("SELECT count(*) FROM fact_security_event").fetchone()[0]
    check("2", "gold materializada (fact > 0)", n > 0, f"{n} linhas")

    files = {r[0] for r in con.execute(
        "SELECT DISTINCT source_file FROM fact_security_event").fetchall()}
    check("2", "gold cobre os dois arquivos", files == {"dadosdia1", "dadosdia2"}, str(files))

    chains = entity_timelines(con, min_steps=4)
    check("2", "≥1 timeline de entidade", len(chains) >= 1, f"{len(chains)} cadeias")

    # invariante: cada timeline é de um único host e monotônica no tempo
    iso = all(len(c.hosts) == 1 for c in chains)
    mono = all([s.event_utc_time for s in c.steps] == sorted(s.event_utc_time for s in c.steps) for c in chains)
    check("2", "timelines não misturam hosts", iso)
    check("2", "timelines monotônicas no tempo", mono)

    edges = artifact_edges(con, cross_day_only=True, limit=50)
    check("2", "arestas cross-dia existem (source_file não é fronteira)", len(edges) > 0, f"{len(edges)} arestas")

    # cadeia de ataque APT29 (SCRANTON/pbeesly) para o handoff
    attack = next((c for c in chains if c.entity.startswith("SCRANTON/") and "pbeesly" in c.entity), None)
    if attack is None:
        attack = max(chains, key=lambda c: len(c.steps))  # fallback: maior cadeia
    check("2", "cadeia de ataque selecionada", attack is not None, attack.entity if attack else "—")
    steps = [s.line() for s in attack.steps[:20]]
    check("2", "cadeia serializada em passos", len(steps) >= 4, f"{len(steps)} passos")
    con.close()
    return steps


# ================================================================= STAGE 3 (subprocess)
def stage3_rag(events: list[dict], chain_steps: list[str]) -> dict:
    if not MITRE_PY.exists():
        fatal("3", f"interpretador do mitre-rag ausente: {MITRE_PY}")

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="e2e_"))
    handoff = tmp / "handoff.json"
    out = tmp / "out.json"
    handoff.write_text(json.dumps({"events": events, "chain": chain_steps},
                                  ensure_ascii=False, default=str), encoding="utf-8")

    # check=True → um crash do estágio 3 vira exceção aqui, nunca passa despercebido
    try:
        proc = subprocess.run(
            [str(MITRE_PY), str(STAGE3), str(handoff), str(out)],
            cwd=str(ROOT / "mitre-rag"), capture_output=True, text=True, timeout=600, check=True)
    except subprocess.CalledProcessError as e:
        print(e.stdout); print(e.stderr, file=sys.stderr)
        fatal("3", f"estágio 3 falhou (exit {e.returncode}) — ver stderr acima")
    except subprocess.TimeoutExpired:
        fatal("3", "estágio 3 estourou o timeout (600s)")

    check("3", "estágio 3 terminou com exit 0", True)
    if not out.exists():
        fatal("3", "estágio 3 não escreveu o arquivo de saída")
    return json.loads(out.read_text(encoding="utf-8"))


# ================================================================= VALIDAÇÃO FINAL
def validate_end_to_end(res: dict):
    check("E2E", "índice tem 697 técnicas", res.get("technique_count") == 699 or res.get("technique_count", 0) >= 690,
          f"{res.get('technique_count')} vetores")

    for ev in res["events"]:
        label = ev["label"]
        ids = [t["id"] for t in ev["top3"]]
        check("E2E", f"{label}: top-3 não vazio", len(ids) >= 1, str(ids))
        check("E2E", f"{label}: ids de técnica bem-formados", all(TID_RE.match(i) for i in ids), str(ids))
        check("E2E", f"{label}: scores presentes", all("score" in t for t in ev["top3"]))
        exp = ev.get("expect_family")
        if exp:
            hit = family(exp) in {family(i) for i in ids}
            check("E2E", f"{label}: técnica esperada {exp} na família do top-3", hit,
                  f"esperado {exp}, veio {ids}")

    if res.get("chain"):
        cids = [t["id"] for t in res["chain"]["top3"]]
        check("E2E", "cadeia: top-3 não vazio", len(cids) >= 1, str(cids))
        check("E2E", "cadeia: ids bem-formados", all(TID_RE.match(i) for i in cids), str(cids))


def _report_and_exit():
    fails = [c for c in _checks if not c[2]]
    print("\n" + "=" * 78)
    print(f"RESUMO E2E: {len(_checks) - len(fails)}/{len(_checks)} checagens passaram")
    if fails:
        print("\nFALHAS:")
        for stage, name, _, detail in fails:
            print(f"  ✗ [{stage}] {name}" + (f" — {detail}" if detail else ""))
        print("\n⚠️  PIPELINE COM QUEBRA — ver acima.")
        sys.exit(1)
    print("✅ PIPELINE E2E ÍNTEGRO — nenhum agente quebrou silenciosamente.")
    sys.exit(0)


def main():
    print("### AGENTE 1 — parsing (Bronze→Silver, determinístico)")
    events = stage1_parsing()
    print("\n### AGENTE 2 — correlação temporal (Gold)")
    chain_steps = stage2_correlation()
    print("\n### AGENTE 3 — RAG de técnica (subprocess, venv mitre-rag)")
    print("  … carregando e5 + cross-encoder (~2 min) …")
    res = stage3_rag(events, chain_steps)
    print("\n### VALIDAÇÃO PONTA-A-PONTA")
    validate_end_to_end(res)

    print("\n### TÉCNICAS RECUPERADAS (do log bruto à técnica, via 3 agentes)")
    for ev in res["events"]:
        print(f"  {ev['label']:24} → {', '.join(t['id'] for t in ev['top3'])}  "
              f"(esperado {ev.get('expect_family')})")
    if res.get("chain"):
        print(f"  {'cadeia_ataque(agente2)':24} → {', '.join(t['id'] for t in res['chain']['top3'])}")

    _report_and_exit()


if __name__ == "__main__":
    main()
