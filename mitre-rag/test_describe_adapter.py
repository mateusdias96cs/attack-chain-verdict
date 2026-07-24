"""
Teste do adaptador describe_silver_event (script, sem pytest — roda no venv do mitre-rag).

Trava as correções de recall do Agente 3:
  - prosa de MASCARAMENTO (RTLO/.scr) só para eventos de processo/arquivo;
  - prosa de INTERPRETADOR (cmd/powershell) só para execução;
  - prosa de C2 para network_connect;
  - e o GATE: nada de mascaramento/interpretador vazando para o evento de rede
    (era o bug que derrubava as técnicas de C2 do pool).

Uso: ./.venv/bin/python test_describe_adapter.py
"""
from agent import describe_silver_event

RTLO = "‮"


def d(ev):
    return describe_silver_event(ev).lower()


def test_process_masquerade():
    s = d({"event_category": "process_create", "image_name": f"cod.{RTLO}3aka3.scr",
           "command_line": f'"cod.{RTLO}3aka3.scr" /S'})
    assert "right-to-left override" in s and "masquerad" in s, s
    assert "screensaver" in s, s


def test_interpreters():
    s_cmd = d({"event_category": "process_create", "image_name": "cmd.exe"})
    assert "command-line shell interpreter" in s_cmd, s_cmd
    s_ps = d({"event_category": "powershell_script_block", "image_name": "powershell.exe"})
    assert "powershell command and scripting interpreter" in s_ps, s_ps


def test_network_has_c2_and_no_masquerade_leak():
    # rede COM um image_name mascarado: a prosa de mascaramento NÃO pode vazar.
    s = d({"event_category": "network_connect", "image_name": f"cod.{RTLO}3aka3.scr",
           "destination_ip": "192.168.0.5", "destination_port": 1234})
    assert "command-and-control" in s and "non-standard" in s, s
    assert "masquerad" not in s, "vazou prosa de mascaramento no evento de rede!"
    assert "right-to-left" not in s, "vazou RTLO no evento de rede!"
    assert "interpreter" not in s, "vazou prosa de interpretador no evento de rede!"


def test_logon_still_works():
    s = d({"event_category": "logon", "subject_account_name": "pbeesly", "logon_type": 3})
    assert "valid credentials" in s, s


if __name__ == "__main__":
    fns = [test_process_masquerade, test_interpreters,
           test_network_has_c2_and_no_masquerade_leak, test_logon_still_works]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} testes do adaptador passaram.")
