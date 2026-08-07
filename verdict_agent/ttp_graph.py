"""Consistência de TTP por travessia de grafo — fonte de evidência EXTRA do Agente 4.

Por que grafo AQUI e vetorial no Agente 3: a pergunta muda de natureza entre os dois.
O Agente 3 pergunta "esta observação se parece com qual técnica?", que é similaridade
de UM salto e é onde busca densa ganha. O Agente 4 pergunta "esta cadeia inteira é
coerente com o repertório de um ator conhecido?", que é travessia de VÁRIOS saltos
(grupo → software → técnica) e é onde relação explícita ganha. A escolha do mecanismo
é ESTÁTICA, decidida aqui em tempo de projeto, não por um seletor em tempo de execução:
a natureza da pergunta de cada agente já é conhecida e um seletor probabilístico só
acrescentaria latência e um modo de falha silencioso.

As arestas saem do MESMO `enterprise-attack-clean.json` que alimenta o índice vetorial,
então não há serviço novo nem cópia de dados. Se um dia a consulta exigir travessias
mais fundas ou caminhos entre grupos, este módulo é o ponto de troca para um Neo4j sem
mexer no resto do Agente 4.

TRÊS TRAVAS contra viés de confirmação (o risco real desta feature):
  1. Ponderação por raridade: técnica usada por 100 grupos não discrimina nada. O sinal
     reportado é a RARIDADE (quantos grupos usam), então o modelo desconta o óbvio.
  2. Tamanho do repertório vai junto: grupo com 200 técnicas casa com qualquer coisa.
  3. Isto NÃO amplia o conjunto de candidatos. A trava de grounding do Agente 4 segue
     mandando: técnica fora dos candidatos do RAG continua virando NONE.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

STIX = Path(__file__).resolve().parent.parent / "enterprise-attack-stix" / "enterprise-attack-clean.json"

# Um grupo precisa cobrir pelo menos isto para ser reportado. Evita despejar no prompt
# uma cauda de grupos que casam com 1 evento genérico por acaso.
MIN_EVENTS_COVERED = 2
TOP_GROUPS = 3

# Piso de repertório. A normalização por especificidade (ver analyze) corrige o viés do
# grupo grande, mas cria o oposto: grupo com 8 técnicas documentadas cobrindo 3 eventos
# parece "surpreendente" quando na verdade só está subdocumentado no ATT&CK. Exigir um
# repertório mínimo tira do páreo esse artefato de catalogação.
MIN_REPERTOIRE = 20

# Só entra no prompt a técnica DISTINTIVA: usada por no máximo esta fração dos grupos.
# Medido no ATT&CK: T1071.001 aparece em 139 dos 174 repertórios (80%) e T1105 em 142.
# Listar essas não informa nada e ainda gasta prompt.
DISTINCTIVE_MAX_SHARE = 0.25
MAX_DISTINCTIVE_LINES = 8

# Portão de discriminação: o melhor grupo precisa superar o 10º colocado por esta razão
# (1.15 = 15% acima). Se não superar, a evidência não separa ninguém e o bloco inteiro é
# suprimido. Sem isto o Agente 4 recebe "todo mundo casa com tudo", que é ruído com
# aparência de evidência. Margem RELATIVA porque a escala do score varia com a cadeia.
# Calibrado em 200 cadeias sintetizadas a partir de candidatos REAIS do Agente 3:
#   limiar 1.05 -> dispara em 100%   (sempre fala, logo não informa)
#   limiar 1.10 -> dispara em  78%
#   limiar 1.15 -> dispara em  43%   <- escolhido
#   limiar 1.25 -> dispara em  10%
#   limiar 1.40 -> dispara em   0%   (feature morta)
MIN_SCORE_MARGIN = 1.15


@dataclass
class GroupMatch:
    name: str
    events_covered: int
    total_events: int
    repertoire_size: int
    score: float = 0.0                       # cobertura ponderada por raridade (IDF)
    matched: list[str] = field(default_factory=list)   # técnicas distintivas que casaram


@dataclass
class TTPEvidence:
    groups: list[GroupMatch]
    usage: dict[str, int]          # attack_id -> quantos grupos usam (raridade)
    in_repertoire: dict[str, list[str]]   # attack_id -> grupos do top que usam
    suppressed: str = ""           # motivo, quando a evidência não discrimina

    @property
    def empty(self) -> bool:
        return bool(self.suppressed) or not self.groups


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


@lru_cache(maxsize=1)
def _load() -> tuple[dict[str, set[str]], dict[str, int]]:
    """Devolve (repertório por grupo, nº de grupos por técnica).

    Repertório = técnicas usadas DIRETAMENTE pelo grupo, mais as técnicas do software
    (malware/tool) que o grupo usa. É a travessia de 2 saltos que a busca vetorial não
    consegue fazer, porque essa relação não está no texto de nenhum documento.
    """
    objects = json.loads(STIX.read_text(encoding="utf-8"))["objects"]

    tech_id: dict[str, str] = {}      # stix_id -> T-ID (só técnicas ativas)
    group_name: dict[str, str] = {}   # stix_id -> nome do grupo
    for o in objects:
        t = o.get("type")
        if t == "attack-pattern":
            if o.get("revoked") or o.get("x_mitre_deprecated"):
                continue
            aid = _attack_id(o)
            if aid:
                tech_id[o["id"]] = aid
        elif t == "intrusion-set":
            if not (o.get("revoked") or o.get("x_mitre_deprecated")):
                group_name[o["id"]] = o.get("name", "")

    # 1º salto: software -> técnicas
    sw_tech: dict[str, set[str]] = {}
    # arestas grupo -> software (resolvidas depois de montar sw_tech)
    group_sw: dict[str, set[str]] = {}
    repertoire: dict[str, set[str]] = {g: set() for g in group_name}

    for o in objects:
        if o.get("type") != "relationship" or o.get("relationship_type") != "uses":
            continue
        src, tgt = o.get("source_ref", ""), o.get("target_ref", "")
        if tgt in tech_id:
            if src in repertoire:                      # grupo -> técnica (direto)
                repertoire[src].add(tech_id[tgt])
            elif src.startswith(("malware--", "tool--")):   # software -> técnica
                sw_tech.setdefault(src, set()).add(tech_id[tgt])
        elif src in repertoire and tgt.startswith(("malware--", "tool--")):
            group_sw.setdefault(src, set()).add(tgt)     # grupo -> software

    # 2º salto: grupo -> software -> técnicas
    for gid, sws in group_sw.items():
        for sw in sws:
            repertoire[gid] |= sw_tech.get(sw, set())

    by_name = {group_name[g]: techs for g, techs in repertoire.items() if techs}

    usage: dict[str, int] = {}
    for techs in by_name.values():
        for t in techs:
            usage[t] = usage.get(t, 0) + 1
    return by_name, usage


def _family(aid: str) -> str:
    return aid.split(".")[0]


def analyze(handoff: dict) -> TTPEvidence:
    """Cruza os candidatos do RAG da cadeia inteira com o repertório de cada grupo.

    Casamento por FAMÍLIA (T1059.003 casa com T1059): o repertório do ATT&CK registra
    ora o pai, ora a subtécnica, e exigir igualdade exata perderia coocorrência real.
    """
    repertoire, usage = _load()
    events = handoff.get("events") or []
    per_event: list[set[str]] = []
    for ev in events:
        per_event.append({c.get("attack_id", "") for c in (ev.get("candidates") or [])
                          if c.get("attack_id")})

    n_groups = len(repertoire) or 1
    all_cands = {c for s in per_event for c in s}
    n_using = {a: usage.get(a, usage.get(_family(a), 0)) for a in all_cands}

    def idf(aid: str) -> float:
        """Peso da técnica: ~0 se todo mundo usa, alto se poucos usam.

        Sem isto a cobertura satura: cadeias reais são feitas de técnicas comuns
        (T1105 está em 142 dos 174 repertórios) e QUALQUER grupo casa com tudo.
        """
        return math.log(n_groups / (1 + n_using.get(aid, 0)))

    scored: list[GroupMatch] = []
    for name, techs in repertoire.items():
        if len(techs) < MIN_REPERTOIRE:
            continue
        fams = {_family(t) for t in techs}
        covered, total, matched = 0, 0.0, []
        for cands in per_event:
            hit = [c for c in cands if _family(c) in fams]
            if not hit:
                continue
            covered += 1
            best = max(hit, key=idf)     # o evento contribui pela técnica MAIS distintiva
            total += max(idf(best), 0.0)
            if _is_distinctive(best, n_using, n_groups):
                matched.append(best)
        if covered >= MIN_EVENTS_COVERED:
            # Normaliza por ESPECIFICIDADE: com ~10 candidatos por evento, o grupo de
            # repertório grande cobre a técnica mais rara de todo evento e venceria por
            # tamanho, não por semelhança. Medido: o APT29 tem 230 técnicas, o maior de
            # todos, justamente o ator do dataset — sem esta divisão a feature viraria
            # uma máquina de confirmar APT29.
            scored.append(GroupMatch(name=name, events_covered=covered,
                                     total_events=len(per_event),
                                     repertoire_size=len(techs),
                                     score=total / math.log(1 + len(techs)),
                                     matched=sorted(set(matched))))

    # ordena pelo score ajustado; empate desfeito pelo repertório menor (mais específico)
    scored.sort(key=lambda g: (-g.score, g.repertoire_size))

    # Portão: o topo precisa se destacar do pelotão, senão isto não é evidência.
    # Margem RELATIVA, porque a escala do score muda com o tamanho da cadeia.
    suppressed = ""
    if len(scored) < 2:
        suppressed = "nenhum grupo com cobertura mínima"
    else:
        baseline = scored[min(9, len(scored) - 1)].score
        if baseline <= 0 or scored[0].score < baseline * MIN_SCORE_MARGIN:
            suppressed = (f"sem poder discriminante (topo {scored[0].score:.2f} vs "
                          f"pelotão {baseline:.2f})")

    top = [] if suppressed else scored[:TOP_GROUPS]
    in_rep = {
        aid: [g.name for g in top if _family(aid) in {_family(t) for t in repertoire[g.name]}]
        for aid in sorted(all_cands) if _is_distinctive(aid, n_using, n_groups)
    }
    return TTPEvidence(groups=top, usage={a: n_using[a] for a in sorted(all_cands)},
                       in_repertoire=in_rep, suppressed=suppressed)


def _is_distinctive(aid: str, n_using: dict[str, int], n_groups: int) -> bool:
    n = n_using.get(aid, 0)
    return 0 < n <= DISTINCTIVE_MAX_SHARE * n_groups


def render(ev: TTPEvidence) -> str:
    """Bloco de texto para o prompt. Deliberadamente enquadrado como sinal FRACO."""
    if ev.empty:
        return ""
    out = ["\nTTP GRAPH EVIDENCE (corroborating only — see caveat below):",
           "  Known-group repertoires overlapping this chain (from ATT&CK "
           "group->technique and group->software->technique relations), ranked by "
           "RARITY-WEIGHTED overlap so that techniques everyone uses count for little:"]
    for g in ev.groups:
        rare = f" via distinctive: {', '.join(g.matched)}" if g.matched else ""
        out.append(f"    - {g.name}: {g.events_covered}/{g.total_events} events, "
                   f"weighted overlap {g.score:.1f} "
                   f"(repertoire size {g.repertoire_size}){rare}")
    distinctive = [(a, n) for a, n in ev.usage.items() if a in ev.in_repertoire]
    if distinctive:
        out.append("  Distinctive candidates only (rare techniques carry attribution "
                   "signal; common ones are omitted because they carry none):")
        for aid, n in sorted(distinctive, key=lambda x: x[1])[:MAX_DISTINCTIVE_LINES]:
            groups = ev.in_repertoire.get(aid) or []
            tag = f" | in repertoire of: {', '.join(groups)}" if groups else ""
            out.append(f"    - {aid}: used by only {n} of {len(_load()[0])} groups{tag}")
    out.append(
        "  CAVEAT — how to use this block: it is WEAK corroborating evidence about "
        "attribution, not about which technique the observation shows. It must NEVER by "
        "itself justify assigning a technique, and must never override what the "
        "observation text actually says. Use it ONLY to break a tie between candidates "
        "the observation supports equally well, and prefer distinctive techniques (used "
        "by few groups) over common ones. A group matching many events may simply have a "
        "large repertoire. Do not name or attribute the actor in your output.")
    return "\n".join(out)
