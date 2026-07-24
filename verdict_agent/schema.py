"""
Contrato de saída do Agente 4 — o VEREDITO FINAL estruturado.

O usuário pediu, por evento da cadeia: (evento, técnica atribuída, nível de
confiança, justificativa curta). É exatamente `EventVerdict`. Os modelos são
Pydantic v2 e também servem de `response_schema` para o Gemini (saída estruturada
nativa), então tudo que o LLM devolve já sai validado e tipado.

A técnica atribuída é SEMPRE arbitrada entre os candidatos que o Agente 3 (RAG)
recuperou — o Gemini escolhe/decide, não inventa T-IDs. Quando nenhum candidato se
aplica, `attack_id == "NONE"` e `confidence_level == none`.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class ConfidenceLevel(str, Enum):
    """Nível de confiança da atribuição da técnica ao evento."""
    high = "high"        # evidência direta e inequívoca no evento
    medium = "medium"    # evidência plausível, apoiada pelo contexto da cadeia
    low = "low"          # atribuição fraca / ambígua
    none = "none"        # nenhuma técnica ATT&CK se aplica ao evento


class Verdict(str, Enum):
    attack = "attack"
    suspicious = "suspicious"
    benign = "benign"


class EventVerdict(BaseModel):
    """Veredito final para UM evento da cadeia (o formato que o usuário pediu)."""
    event: str = Field(..., description="Descrição/rótulo do evento julgado.")
    attack_id: str = Field(
        ..., description='Técnica ATT&CK atribuída (ex.: "T1036.005") ou "NONE".')
    technique_name: str = Field(
        ..., description="Nome da técnica atribuída (vazio se NONE).")
    confidence: float = Field(
        ..., ge=0.0, le=1.0,
        description="Confiança numérica 0.0–1.0 da atribuição.")
    confidence_level: ConfidenceLevel = Field(
        ..., description="Faixa qualitativa da confiança.")
    rationale: str = Field(
        ..., description="Justificativa curta (1 frase) em português.")


class ChainVerdictReport(BaseModel):
    """Veredito consolidado da cadeia inteira: um EventVerdict por evento."""
    entity: str = Field(..., description="Entidade da cadeia (host/ator ou artefato).")
    overall_verdict: Verdict = Field(
        ..., description="Classificação geral da cadeia.")
    overall_confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confiança geral 0.0–1.0.")
    events: list[EventVerdict] = Field(
        default_factory=list, description="Veredito por evento, na ordem da cadeia.")
    attack_summary: str = Field(
        ..., description="Resumo curto (1–2 frases) da narrativa de ataque em português.")
