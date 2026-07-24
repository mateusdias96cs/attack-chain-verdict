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
from pathlib import Path

from .agent import VerdictAgent

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


def print_report(report, usage: dict) -> None:
    print("\n" + "=" * 72)
    print(f"VEREDITO FINAL — {report.entity}")
    print(f"  geral: {report.overall_verdict.value}  "
          f"(confiança {report.overall_confidence:.2f})")
    print(f"  resumo: {report.attack_summary}")
    print("-" * 72)
    for i, v in enumerate(report.events):
        tech = f"{v.attack_id} {v.technique_name}".strip() if v.attack_id != "NONE" else "— (nenhuma)"
        print(f"[{i}] {v.event[:60]}")
        print(f"     técnica : {tech}")
        print(f"     conf.   : {v.confidence:.2f} ({v.confidence_level.value})")
        print(f"     porquê  : {v.rationale}")
    print("-" * 72)
    if usage:
        print(f"tokens Gemini: {usage.get('total_tokens')} "
              f"(in={usage.get('prompt_tokens')}, out={usage.get('output_tokens')})")
    print("=" * 72)


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
