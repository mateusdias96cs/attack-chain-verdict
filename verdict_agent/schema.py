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
    """Veredito final para UM passo da cadeia de ataque.

    `step_title` e `rationale` são o que um leitor sem familiaridade com ATT&CK
    consegue ler: o título nomeia a AÇÃO do atacante e o artefato envolvido, e a
    justificativa explica o passo em prosa. Os campos técnicos (`attack_id`,
    `confidence`) continuam ao lado, para quem quiser auditar a atribuição.
    """
    event: str = Field(..., description="Descrição/rótulo do evento julgado.")
    step_title: str = Field(
        ...,
        description=(
            "Título do passo em português: a AÇÃO do atacante mais o artefato "
            'concreto (arquivo, processo, IP, chave de registro). Ex.: "Execução do '
            'arquivo mascarado cod.3aka3.scr". Sem jargão e sem T-ID.'))
    attack_id: str = Field(
        ..., description='Técnica ATT&CK atribuída (ex.: "T1036.005") ou "NONE".')
    technique_name: str = Field(
        ..., description="Nome da técnica atribuída (vazio se NONE).")
    tactic: str = Field(
        default="",
        description=("Tática ATT&CK (fase da cadeia) da técnica atribuída. Preenchida "
                     "deterministicamente a partir do candidato do RAG, não pelo LLM."))
    confidence: float = Field(
        ..., ge=0.0, le=1.0,
        description="Confiança numérica 0.0–1.0 da atribuição.")
    confidence_level: ConfidenceLevel = Field(
        ..., description="Faixa qualitativa da confiança.")
    rationale: str = Field(
        ...,
        description=("Explicação do passo em português corrente, 2 a 3 frases: o que "
                     "aconteceu, por que isso caracteriza a técnica e como se liga ao "
                     "passo anterior ou seguinte."))


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
        ...,
        description=("Narrativa da cadeia em português corrente, 3 a 5 frases, contando "
                     "a história do ataque do início ao fim (quem, o quê, com qual "
                     "arquivo, para onde) sem listar T-IDs."))
