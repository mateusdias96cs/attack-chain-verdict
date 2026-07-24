"""
Demo de integração: a entrada do Agente 3 vem dos agentes 1 e 2.

Mostra que um registro silver (saída do agente de parsing) e uma cadeia (saída do
agente de correlação) são convertidos em descrição NL pelos adaptadores e
classificados na técnica ATT&CK correta.

Rode:  ./.venv/bin/python demo_integration.py
"""
from agent import TechniqueClassifier, describe_chain, describe_silver_event

clf = TechniqueClassifier()

# ---- (A) evento silver vindo do AGENTE 1 (parsing): logon 4624 credencial válida
silver_logon = {
    "event_category": "logon", "log_source": "windows_security",
    "subject_account_name": "pbeesly", "logon_type": 3,
}
desc_a = describe_silver_event(silver_logon)
print("── (A) evento silver (agente 1) → descrição ──")
print("  ", desc_a)
for m in clf.classify(desc_a, top_k=3):
    print("   →", m)

# ---- (B) evento silver: PowerShell script block
silver_ps = {
    "event_category": "powershell_script_block", "log_source": "powershell",
    "image_name": "powershell.exe",
    "command_line": "powershell -enc SQBFAFgA... (base64 encoded command)",
}
desc_b = describe_silver_event(silver_ps)
print("\n── (B) evento silver PowerShell (agente 1) → descrição ──")
print("  ", desc_b)
for m in clf.classify(desc_b, top_k=3):
    print("   →", m)

# ---- (C) cadeia vinda do AGENTE 2 (correlação): execução mascarada → C2
chain_steps = [
    '02:55:56 SCRANTON/pbeesly process_create | "C:\\ProgramData\\victim\\cod.3aka3.scr" /S',
    "02:55:59 SCRANTON/pbeesly network_connect cod.3aka3.scr | 192.168.0.5:1234",
    '02:56:04 SCRANTON/pbeesly process_create | "C:\\windows\\system32\\cmd.exe"',
    "02:56:14 SCRANTON/pbeesly process_create | powershell",
]
desc_c = describe_chain(chain_steps)
print("\n── (C) cadeia de correlação (agente 2) → descrição ──")
print("  ", desc_c[:160], "...")
for m in clf.classify(desc_c, top_k=3):
    print("   →", m)
