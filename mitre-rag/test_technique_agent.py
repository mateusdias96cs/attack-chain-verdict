"""
Teste ISOLADO do Agente 3 (RAG de técnica ATT&CK).

Cada caso é uma DESCRIÇÃO de evento no estilo que sai dos agentes 1/2 (telemetria
Windows descrita em linguagem natural), com a(s) técnica(s) ATT&CK correta(s) já
conhecida(s) de antemão. Passamos SÓ a descrição para o agente (sem o resto do
pipeline) e conferimos se a técnica certa aparece no top-k.

O exemplo pedido — logon com credencial válida → T1078 — é o primeiro caso.

Retrieval é local e determinístico (e5 + cross-encoder); NÃO usa a API do Groq.

Rode:  ./.venv/bin/python test_technique_agent.py
"""
from __future__ import annotations

import sys

from agent import TechniqueClassifier

# (rótulo, descrição do evento, técnica(s) aceitável(is))
#   'T1078'    -> aceita o pai OU qualquer subtécnica T1078.x
#   'T1036.002'-> aceita a sub OU seu pai T1036
GOLDEN = [
    ("Logon credencial válida",
     "An account successfully logged on to the system using valid domain credentials. "
     "Logon type 3 network logon. The credentials were legitimate and belonged to an "
     "existing domain user account, not a newly created one.",
     ["T1078"]),
    ("PowerShell execução",
     "PowerShell executed an encoded command pipeline to run malicious script content "
     "on the host via powershell.exe.",
     ["T1059.001"]),
    ("Run key persistência",
     "A registry value was set under the Windows CurrentVersion Run key so that a program "
     "launches automatically every time the user logs on.",
     ["T1547.001"]),
    ("LSASS dump",
     "A process opened the memory of the lsass.exe process with read access to extract "
     "and dump credential material from LSASS.",
     ["T1003.001"]),
    ("Scheduled task",
     "A scheduled task was created on the Windows host through schtasks to execute a "
     "program persistently at a set time.",
     ["T1053.005"]),
    ("Ingress tool transfer",
     "certutil.exe was executed with a URL argument to download a file from an external "
     "server onto the local host.",
     ["T1105"]),
    ("Masquerading RTL",
     "An executable named with a right-to-left override character was run to disguise its "
     "real .scr extension and appear as a harmless document.",
     ["T1036.002", "T1036"]),
    ("Account discovery net.exe",
     "The net.exe and net1.exe utilities were run to enumerate domain user accounts and "
     "group memberships on the host.",
     ["T1087.002", "T1087"]),
    ("Process injection",
     "A process created a remote thread inside another running process to inject and "
     "execute its own code in that process.",
     ["T1055", "T1055.003"]),
    ("Command and control HTTP",
     "A process established an outbound network connection to an external command and "
     "control server over a standard web protocol.",
     ["T1071.001", "T1071"]),
]

MIN_HIT_AT_3 = 0.70   # limiar de aprovação agregado (top-3)


def parent(aid: str) -> str:
    return aid.split(".")[0]


def is_hit(returned_ids: list[str], expected: list[str]) -> bool:
    """Acerto se algum ID retornado casa com a FAMÍLIA de algum esperado
    (mesma técnica: id exato, seu pai, ou uma de suas subtécnicas)."""
    fams = {parent(e) for e in expected}
    return any(parent(r) in fams for r in returned_ids)


def main() -> int:
    clf = TechniqueClassifier()
    print(f"Índice: {clf.technique_count} técnicas | e5-small + cross-encoder\n")
    print(f"{'caso':26} {'alvo':14} {'top-3 retornado':34} hit@1 hit@3")
    print("-" * 92)

    hit1 = hit3 = 0
    t1078_ok = False
    failures = []
    for label, desc, expected in GOLDEN:
        matches = clf.classify(desc, top_k=3)
        ids = [m.attack_id for m in matches]
        h1 = is_hit(ids[:1], expected)
        h3 = is_hit(ids[:3], expected)
        hit1 += h1
        hit3 += h3
        if label.startswith("Logon"):
            t1078_ok = h3
        if not h3:
            failures.append((label, expected, ids))
        top3 = ", ".join(ids[:3])
        print(f"{label:26} {','.join(expected):14} {top3:34} "
              f"{'✔' if h1 else '·':^5} {'✔' if h3 else '✗':^5}")

    n = len(GOLDEN)
    print("-" * 92)
    print(f"\nhit@1 = {hit1}/{n} ({hit1/n:.0%})   hit@3 = {hit3}/{n} ({hit3/n:.0%})")
    print(f"caso pedido (logon → T1078) no top-3: {'✔ PASSOU' if t1078_ok else '✗ FALHOU'}")

    # asserts do teste isolado
    ok = True
    if not t1078_ok:
        print("\n❌ ASSERT: o evento de logon com credencial válida NÃO retornou T1078 no top-3")
        ok = False
    if hit3 / n < MIN_HIT_AT_3:
        print(f"\n❌ ASSERT: hit@3 {hit3/n:.0%} abaixo do limiar {MIN_HIT_AT_3:.0%}")
        ok = False
    if failures:
        print("\nCasos que falharam no top-3 (para inspeção):")
        for label, exp, ids in failures:
            print(f"  · {label}: esperado {exp}, retornou {ids[:3]}")

    print("\n" + ("✅ TESTE ISOLADO PASSOU" if ok else "⚠️  TESTE ISOLADO COM FALHAS"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
