"""
CLI do Agente 4 — veredito final estruturado (Gemini).

Dois modos:

  # A) já tenho o handoff (cadeia + candidatos RAG por evento):
  .venv/bin/python -m verdict_agent.cli --handoff handoff.json [--out verdict.json]

  # B) tenho só a cadeia (agente 2) e quero o pipeline completo: este CLI invoca o
  #    estágio de candidatos no venv do mitre-rag (subprocess) e depois o Gemini:
  .venv/bin/python -m verdict_agent.cli --chain chain.json [--top-k 4] [--out verdict.json]

Respeita o SPLIT DE VENVS: o Agente 4 (Gemini, cloud) roda no .venv raiz; o estágio de
candidatos (e5/torch) roda em mitre-rag/.venv via subprocess com check=True (falha não
é engolida).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

from .agent import VerdictAgent, _level_for

ROOT = Path(__file__).resolve().parent.parent
RAG_DIR = ROOT / "mitre-rag"
RAG_PY = RAG_DIR / ".venv" / "bin" / "python"


def rag_candidates(chain_path: Path, top_k: int) -> dict:
    """Invoca o estágio de candidatos RAG no venv do mitre-rag (subprocess)."""
    if not RAG_PY.exists():
        raise SystemExit(f"❌ interpretador do RAG não encontrado: {RAG_PY}")
    with tempfile.NamedTemporaryFile("w", suffix=".handoff.json", delete=False) as tf:
        out_path = Path(tf.name)
    # o subprocess roda com cwd=mitre-rag/, então caminhos precisam ser absolutos
    chain_abs = chain_path.resolve()
    cmd = [str(RAG_PY), "rag_candidates.py", str(chain_abs), str(out_path), str(top_k)]
    print(f"→ candidatos RAG (venv mitre-rag): {' '.join(cmd)}")
    subprocess.run(cmd, cwd=str(RAG_DIR), check=True)
    return json.loads(out_path.read_text(encoding="utf-8"))


LARGURA = 78

# Glossário das táticas do ATT&CK Enterprise. A tática é a FASE da cadeia de ataque;
# o nome canônico é em inglês, então mostramos a fase em português para quem lê o
# relatório sem conhecer o framework.
#
# As 15 primeiras entradas são exatamente as táticas da base v19.1 que alimenta o
# índice (conferidas nos objetos x-mitre-tactic). Atenção: nessa versão NÃO existe
# mais "Defense Evasion"; ela deu lugar a "Stealth" e "Defense Impairment". A entrada
# legada continua no mapa porque um índice construído de uma versão anterior ainda
# emite o nome antigo.
FASES_PT = {
    "reconnaissance": "Reconhecimento",
    "resource development": "Preparação de recursos",
    "initial access": "Acesso inicial",
    "execution": "Execução",
    "persistence": "Persistência",
    "privilege escalation": "Escalonamento de privilégio",
    "stealth": "Furtividade",
    "defense impairment": "Degradação de defesas",
    "credential access": "Acesso a credenciais",
    "discovery": "Descoberta",
    "lateral movement": "Movimentação lateral",
    "collection": "Coleta",
    "command and control": "Comando e controle",
    "exfiltration": "Exfiltração",
    "impact": "Impacto",
    "defense evasion": "Evasão de defesas",  # legado (bases anteriores à v19)
}

VEREDITO_PT = {"attack": "ATAQUE", "suspicious": "SUSPEITO", "benign": "BENIGNO"}
CONFIANCA_PT = {"high": "alta", "medium": "média", "low": "baixa", "none": "nenhuma"}


def _fase_pt(tactics: str) -> str:
    """Traduz a(s) tática(s) do candidato para a fase em português."""
    if not tactics:
        return ""
    partes = [p.strip() for p in tactics.split(",") if p.strip()]
    return ", ".join(FASES_PT.get(p.lower(), p) for p in partes)


def _paragrafo(texto: str, recuo: str) -> str:
    """Quebra prosa em linhas legíveis, preservando o recuo do bloco."""
    return textwrap.fill(
        " ".join((texto or "").split()),
        width=LARGURA, initial_indent=recuo, subsequent_indent=recuo)


def render_report(report) -> str:
    """Monta a cadeia de ataque como narrativa numerada e devolve o texto.

    Separado de `print_report` porque o relatório legível também é consumido fora
    do terminal (o grafo do LangGraph expõe esse texto no estado, para que a
    narrativa apareça no Studio em vez do JSON cru).
    """
    linhas: list[str] = []

    def escreve(texto: str = "") -> None:
        linhas.append(texto)

    veredito = VEREDITO_PT.get(report.overall_verdict.value, report.overall_verdict.value)
    # os limiares de confiança vivem no agente; reusar evita que renderizador e
    # trava de coerência divirjam se um dia forem ajustados.
    nivel_geral = CONFIANCA_PT.get(_level_for(report.overall_confidence).value, "")

    escreve()
    escreve("=" * LARGURA)
    escreve(f"CADEIA DE ATAQUE: {report.entity}")
    escreve(f"Classificação geral: {veredito} "
            f"(confiança {nivel_geral}, {report.overall_confidence * 100:.0f}%)")
    escreve("=" * LARGURA)

    escreve()
    escreve("O QUE ACONTECEU")
    escreve()
    escreve(_paragrafo(report.attack_summary, "  "))

    total = len(report.events)
    escreve()
    escreve(f"PASSO A PASSO ({total} {'passo' if total == 1 else 'passos'})")

    for i, v in enumerate(report.events, start=1):
        escreve()
        # título com recuo pendente: o número ocupa coluna fixa, então o texto do
        # título e o parágrafo abaixo dele começam ambos na coluna 6.
        marcador = f"  {f'{i}º'.rjust(2)}  "
        escreve(textwrap.fill(
            " ".join(v.step_title.split()),
            width=LARGURA, initial_indent=marcador, subsequent_indent="      "))
        escreve(_paragrafo(v.rationale, "      "))
        escreve()
        if v.attack_id != "NONE":
            tecnica = f"{v.attack_id} {v.technique_name}".strip()
            escreve(f"      Técnica MITRE ATT&CK : {tecnica}")
            fase = _fase_pt(v.tactic)
            if fase:
                escreve(f"      Fase da cadeia       : {fase}")
            escreve(f"      Confiança            : "
                    f"{CONFIANCA_PT.get(v.confidence_level.value, '')} "
                    f"({v.confidence * 100:.0f}%)")
        else:
            escreve("      Técnica MITRE ATT&CK : nenhuma técnica se aplica a este passo")

    escreve()
    escreve("=" * LARGURA)
    return "\n".join(linhas)


def print_report(report, usage: dict) -> None:
    """Imprime a cadeia narrada em stdout; a diagnose de execução vai para stderr."""
    print(render_report(report))
    if usage:
        print(f"· tokens Gemini: {usage.get('total_tokens')} "
              f"(entrada={usage.get('prompt_tokens')}, saída={usage.get('output_tokens')})",
              file=sys.stderr)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Agente 4 — veredito final (Gemini)")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--handoff", help="handoff pronto (cadeia + candidatos por evento)")
    src.add_argument("--chain", help="só a cadeia; roda o estágio de candidatos RAG antes")
    ap.add_argument("--top-k", type=int, default=4, help="candidatos por evento (modo --chain)")
    ap.add_argument("--out", help="grava o veredito estruturado (JSON) neste caminho")
    ap.add_argument("--model", default=None, help="override do modelo Gemini")
    args = ap.parse_args(argv)

    if args.handoff:
        handoff = json.loads(Path(args.handoff).read_text(encoding="utf-8"))
    else:
        handoff = rag_candidates(Path(args.chain), args.top_k)

    from .gemini_client import GeminiVerdict
    gemini = GeminiVerdict(model=args.model) if args.model else GeminiVerdict()
    agent = VerdictAgent(gemini=gemini)
    res = agent.run(handoff)

    for t in res.trace:
        print("·", t, file=sys.stderr)
    print_report(res.report, res.usage)

    if args.out:
        Path(args.out).write_text(
            res.report.model_dump_json(indent=2), encoding="utf-8")
        print(f"\n💾 veredito estruturado salvo em {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
