"""
Portão de triagem determinístico (0 tokens, sem API) — Agente 2.

Decide, por regras pré-escritas (triage_rules.yaml, estilo Sigma), se um evento/cadeia
tem CARACTERÍSTICA de ataque:

  - qualquer regra `high` dispara  → ESCALA para o veredito LLM (Agente 4)
  - >=2 regras `medium` disparam    → ESCALA (corroboração mútua)
  - nada dispara (ou 1 medium solto) → LEGÍTIMO, com prova auditável; NÃO gasta cota

Dois pontos de entrada, normalizados numa "visão de evento" comum:
  - dict Silver do Agente 1 (evento isolado)         -> event_view_from_silver
  - Step/Chain do correlate.py do Agente 2 (cadeia)  -> event_view_from_step

A prova (RuleHit.evidence para o caminho de ataque, benign_evidence para o legítimo) é o
artefato que o humano audita: mostra o QUE casou ou o que foi checado e não casou.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

RULES_PATH = Path(__file__).with_name("triage_rules.yaml")

# event_id -> categoria (o Silver do Agente 1 não carrega event_category; é coluna da
# Gold do Agente 2). Espelha o mapa do adaptador do Agente 3 — mantido local para não
# cruzar venvs (triage roda no venv raiz).
_EVENT_ID_CATEGORY = {
    1: "process_create", 3: "network_connect", 7: "image_load", 8: "create_remote_thread",
    10: "process_access", 11: "file_create", 12: "registry_create_delete",
    13: "registry_set_value", 22: "dns_query", 23: "file_delete",
    4688: "process_create", 4624: "logon", 4625: "logon_failure",
    4663: "object_access", 4656: "object_access", 5156: "network_connect",
    800: "powershell_pipeline", 4103: "powershell_module", 4104: "powershell_script_block",
    7045: "service_install", 4697: "service_install",
}

_MATCH_OPS = ("_contains", "_regex", "_mask")


@dataclass
class RuleHit:
    rule_id: str
    attack_id: str
    tactic: str
    level: str                 # 'high' | 'medium'
    scope: str                 # 'event' | 'chain'
    title: str
    evidence: dict = field(default_factory=dict)   # o PORQUÊ auditável (campo -> valor)


@dataclass
class TriageDecision:
    entity: str
    decision: str = "clear"                  # 'escalate' | 'clear'
    fired: list = field(default_factory=list)          # list[RuleHit]
    benign_evidence: dict = field(default_factory=dict)
    sampled_for_audit: bool = False

    @property
    def attack_ids(self) -> list:
        return sorted({h.attack_id for h in self.fired})

    @property
    def tactics(self) -> list:
        return sorted({h.tactic for h in self.fired if h.tactic})

    def to_prior_verdict(self) -> dict:
        """Formato lido pelo Agente 4 (`prior_chain_verdict` do handoff): reaproveita as
        chaves verdict/plausibility/likely_tactics que o build_prompt já consome, e anexa
        a EVIDÊNCIA determinística (regras + T-IDs) para o Gemini ler o porquê do gate."""
        escalated = self.decision == "escalate"
        has_high = any(h.level == "high" for h in self.fired)
        return {
            "verdict": "attack" if escalated else "benign",
            "plausibility": 0.8 if has_high else (0.5 if escalated else 0.1),
            "likely_tactics": self.tactics,
            "source": "deterministic_triage",
            "sampled_for_audit": self.sampled_for_audit,
            "fired_rules": [{"rule_id": h.rule_id, "attack_id": h.attack_id,
                             "level": h.level, "evidence": h.evidence} for h in self.fired],
            "attack_ids": self.attack_ids,
        }


# ---------------------------------------------------------------------------
# Carregamento das regras
# ---------------------------------------------------------------------------
def load_rules(path: str | Path = RULES_PATH) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        rules = yaml.safe_load(f) or []
    for r in rules:                       # normaliza defaults
        r.setdefault("scope", "event")
        r.setdefault("level", "medium")
        r.setdefault("tactic", "")
    return rules


# ---------------------------------------------------------------------------
# Visões de evento normalizadas (dict com campos nomeados)
# ---------------------------------------------------------------------------
def _basename(p) -> str:
    return re.split(r"[\\/]", str(p or ""))[-1]


def event_view_from_silver(s: dict) -> dict:
    eid = s.get("event_id")
    return {
        "event_id": eid,
        "category": s.get("event_category") or _EVENT_ID_CATEGORY.get(eid) or s.get("log_source"),
        "image_name": s.get("image_name") or _basename(s.get("image_path")),
        "command_line": s.get("command_line"),
        "target_image": s.get("target_image"),
        "granted_access": s.get("granted_access"),
        "registry_target_object": s.get("registry_target_object"),
        "target_filename": s.get("target_filename"),
        "logon_type": s.get("logon_type"),
        "destination_ip": s.get("destination_ip"),
        "script_block_text": s.get("script_block_text"),
        "unmapped_json": s.get("unmapped_json"),
    }


def event_view_from_step(st) -> dict:
    """Reconstrói a visão a partir de um Step do correlate.py, onde o campo mais
    informativo do evento está condensado em `artifact` conforme a categoria."""
    cat = st.category or ""
    art = st.artifact
    v = {"event_id": st.event_id, "category": cat, "image_name": st.image_name,
         "command_line": None, "target_image": None, "granted_access": None,
         "registry_target_object": None, "target_filename": None, "logon_type": None,
         "destination_ip": None, "destination_port": None,
         "script_block_text": None, "unmapped_json": None}
    if cat.startswith("network"):
        parts = str(art).split(":") if art else []
        v["destination_ip"] = (parts[0] or None) if parts else None
        v["destination_port"] = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    elif cat == "process_access":
        v["target_image"] = art
    elif cat.startswith("registry"):
        v["registry_target_object"] = art
    elif cat in ("file_create", "file_delete"):
        v["target_filename"] = art
    elif cat.startswith("powershell"):
        v["command_line"] = art
        v["script_block_text"] = art
    else:                                  # process_create/service_install/genérico
        v["command_line"] = art
    return v


# ---------------------------------------------------------------------------
# Casamento de predicados (event scope)
# ---------------------------------------------------------------------------
def _split_op(key: str) -> tuple[str, str]:
    for suf in _MATCH_OPS:
        if key.endswith(suf):
            return key[: -len(suf)], suf[1:]
    return key, "eq"


def _match_predicate(view: dict, key: str, spec) -> tuple[bool, object]:
    field_name, op = _split_op(key)
    val = view.get(field_name)
    if val is None:
        return False, None
    sval = str(val)
    opts = spec if isinstance(spec, list) else [spec]

    if op == "eq":
        if field_name == "image_name":
            low = _basename(sval).lower()
            for o in opts:
                if _basename(str(o)).lower() == low:
                    return True, _basename(sval)
            return False, None
        # numérico (event_id, logon_type) ou string exata
        for o in opts:
            if str(o).lower() == sval.lower():
                return True, val
        try:
            if int(val) in [int(o) for o in opts]:
                return True, val
        except (TypeError, ValueError):
            pass
        return False, None

    if op == "contains":
        low = sval.lower()
        for o in opts:
            if str(o).lower() in low:
                return True, o
        return False, None

    if op == "regex":
        for o in opts:
            if re.search(str(o), sval, re.IGNORECASE):
                return True, str(o)
        return False, None

    if op == "mask":
        try:
            iv = int(sval, 0) if isinstance(val, str) else int(val)
            m = int(spec)
            return (iv & m) == m, hex(iv)
        except (TypeError, ValueError):
            return False, None

    return False, None


def evaluate_event(view: dict, rules: list[dict]) -> list[RuleHit]:
    """Regras de escopo evento cujo TODO o `match` casa contra a visão do evento."""
    hits: list[RuleHit] = []
    for r in rules:
        if r.get("scope") != "event":
            continue
        match = r.get("match") or {}
        evidence: dict = {}
        ok = True
        for key, spec in match.items():
            good, matched = _match_predicate(view, key, spec)
            if not good:
                ok = False
                break
            evidence[key] = matched
        if ok and match:
            hits.append(RuleHit(
                rule_id=r["id"], attack_id=r.get("attack_id", ""), tactic=r.get("tactic", ""),
                level=r.get("level", "medium"), scope="event", title=r.get("title", ""),
                evidence=evidence))
    return hits


# ---------------------------------------------------------------------------
# Casamento de sequência (chain scope)
# ---------------------------------------------------------------------------
def is_external_ip(ip: str | None) -> bool:
    """IP roteável/externo = globalmente alcançável (is_global). Exclui privado,
    loopback, link-local, multicast, reservado e faixas de documentação (RFC 5737)."""
    if not ip:
        return False
    try:
        return ipaddress.ip_address(str(ip).strip()).is_global
    except ValueError:
        return False


# Portas de serviço comuns/legítimas. Uma conexão nessas portas NÃO conta como sinal de
# porta não-padrão (evita falso positivo do tráfego web/AD/e-mail normal do Windows).
_STANDARD_PORTS = {80, 443, 53, 88, 389, 445, 135, 139, 25, 110, 143, 993, 995,
                   22, 3389, 123, 137, 138, 5985, 5986, 636, 3268, 3269, 21}


def _is_nonstandard_port(port) -> bool:
    return port is not None and int(port) not in _STANDARD_PORTS


def _cat_eq(cat: str, want: str) -> bool:
    # 'network_connect' casa 'network_connect'/'network_bind'; senão igualdade exata
    if want == "network_connect":
        return cat.startswith("network")
    return cat == want


def evaluate_chain(chain, rules: list[dict]) -> list[RuleHit]:
    hits: list[RuleHit] = []
    steps = chain.steps
    for r in rules:
        if r.get("scope") != "chain":
            continue
        cm = r.get("chain_match") or {}
        seq = cm.get("sequence") or []
        if len(seq) != 2:
            continue
        a_cat, b_cat = seq
        within = cm.get("within_seconds")
        need_ext = bool(cm.get("external_dest"))
        excl_ports = set(cm.get("exclude_ports") or [])
        need_nonstd = bool(cm.get("nonstandard_port"))
        found = None
        for i, si in enumerate(steps):
            if not _cat_eq(si.category or "", a_cat):
                continue
            for sj in steps[i + 1:]:
                if not _cat_eq(sj.category or "", b_cat):
                    continue
                gap = (sj.event_utc_time - si.event_utc_time).total_seconds()
                if gap < 0:
                    continue
                if within is not None and gap > within:
                    continue
                bview = event_view_from_step(sj)
                dest, port = bview.get("destination_ip"), bview.get("destination_port")
                if need_ext and not is_external_ip(dest):
                    continue
                if excl_ports and port in excl_ports:
                    continue
                if need_nonstd and not _is_nonstandard_port(port):
                    continue
                found = (si, sj, gap)
                break
            if found:
                break
        if found:
            si, sj, gap = found
            hits.append(RuleHit(
                rule_id=r["id"], attack_id=r.get("attack_id", ""), tactic=r.get("tactic", ""),
                level=r.get("level", "medium"), scope="chain", title=r.get("title", ""),
                evidence={"sequence": f"{si.category} -> {sj.category}",
                          "from": si.line(), "to": sj.line(), "gap_seconds": round(gap, 1)}))
    return hits


# ---------------------------------------------------------------------------
# Prova de legitimidade (quando nada de ataque dispara)
# ---------------------------------------------------------------------------
def _benign_signals(views: list[dict]) -> list[str]:
    """Atestações positivas derivadas da AUSÊNCIA de padrões de ataque conhecidos.
    Honesto: é evidência de que os indicadores checados não apareceram, não prova
    universal de segurança."""
    sig: list[str] = []
    cats = {v["category"] for v in views if v["category"]}
    net_dests = [v.get("destination_ip") for v in views if v.get("destination_ip")]
    ext = [d for d in net_dests if is_external_ip(d)]

    if not ext:
        sig.append("Nenhuma conexão a IP externo/roteável (sem indício de canal C2)."
                   if net_dests else "Nenhuma conexão de rede de saída na cadeia.")
    imgs = " ".join(str(v.get("image_name") or "") for v in views).lower()
    if "‮" not in imgs and ".scr" not in imgs:
        sig.append("Nenhum indicador de mascaramento de nome (sem RTLO/.scr).")
    if not any((v.get("target_image") or "").lower().endswith("lsass.exe") for v in views):
        sig.append("Nenhum acesso à memória de processo sensível (LSASS).")
    cmdl = " ".join(str(v.get("command_line") or "") for v in views).lower()
    if "certutil" not in imgs and "bitsadmin" not in imgs and "-enc" not in cmdl:
        sig.append("Nenhum download por LOLBin nem PowerShell codificado.")
    if {"process_create", "powershell_pipeline", "powershell_script_block"} & cats:
        sig.append("Execução de shell/processo sem ofuscação, codificação ou LOLBin de proxy.")
    return sig


# ---------------------------------------------------------------------------
# Decisão de triagem
# ---------------------------------------------------------------------------
def decide(entity: str, hits: list[RuleHit], views: list[dict],
           rules: list[dict]) -> TriageDecision:
    high = [h for h in hits if h.level == "high"]
    medium = [h for h in hits if h.level == "medium"]
    d = TriageDecision(entity=entity, fired=hits)
    if high or len(medium) >= 2:
        d.decision = "escalate"
    else:
        d.decision = "clear"
        d.benign_evidence = {
            "no_match": not hits,
            "rules_evaluated": len(rules),
            "medium_uncorroborated": [h.rule_id for h in medium],
            "positive_signals": _benign_signals(views),
        }
    return d


def triage_chain(chain, rules: list[dict]) -> TriageDecision:
    """Entrada do Agente 2: uma Chain do correlate.py."""
    views = [event_view_from_step(st) for st in chain.steps]
    hits: list[RuleHit] = []
    for v in views:
        hits.extend(evaluate_event(v, rules))
    hits.extend(evaluate_chain(chain, rules))
    return decide(chain.entity, hits, views, rules)


def triage_events(silver_events: list[dict], rules: list[dict],
                  entity: str = "adhoc") -> TriageDecision:
    """Entrada standalone: uma lista de dicts Silver do Agente 1 (sem correlação).
    Só avalia regras de escopo evento (não há cadeia/tempo aqui)."""
    views = [event_view_from_silver(s) for s in silver_events]
    hits: list[RuleHit] = []
    for v in views:
        hits.extend(evaluate_event(v, rules))
    return decide(entity, hits, views, rules)
