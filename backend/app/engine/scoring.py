from typing import List, Tuple
from app.core.schemas import (
    AuthStatus,
    IdentityAnalysis,
    DomainInfo,
    OriginIpInfo,
    ClientMetadata,
    SegVerdicts,
    AnalysisSummary,
    Finding,
    RiskLevel,
)


def calculate_risk_score(
    auth: AuthStatus,
    identity: IdentityAnalysis,
    domain: DomainInfo,
    origin_ip: OriginIpInfo,
    client: ClientMetadata,
    seg: SegVerdicts,
    total_hops: int,
    elapsed_ms: float,
) -> Tuple[AnalysisSummary, List[Finding]]:
    findings: List[Finding] = []
    total_score = 0

    # 1. Autenticação
    if auth.spf_verdict in ["fail", "permerror"]:
        findings.append(
            Finding(
                category="Autenticação",
                title="SPF Fail",
                description="O IP emissor não possui autorização no registro SPF",
                points=20,
                severity=RiskLevel.HIGH,
            )
        )
        total_score += 20
    elif auth.spf_verdict in ["softfail", "neutral"]:
        findings.append(
            Finding(
                category="Autenticação",
                title="SPF Softfail/Neutral",
                description="Registro SPF permissivo ou não rigoroso",
                points=10,
                severity=RiskLevel.INFO,
            )
        )
        total_score += 10
    elif auth.spf_verdict == "none":
        findings.append(
            Finding(
                category="Autenticação",
                title="Sem SPF",
                description="Domínio sem registro SPF detectado",
                points=5,
                severity=RiskLevel.INFO,
            )
        )
        total_score += 5

    if auth.dkim_verdict in ["fail", "invalid"]:
        findings.append(
            Finding(
                category="Autenticação",
                title="DKIM Inválido",
                description="Assinatura criptográfica DKIM corrompida ou inválida",
                points=20,
                severity=RiskLevel.HIGH,
            )
        )
        total_score += 20
    elif auth.dkim_verdict == "none":
        findings.append(
            Finding(
                category="Autenticação",
                title="Sem Assinatura DKIM",
                description="Mensagem não possui assinatura DKIM",
                points=10,
                severity=RiskLevel.INFO,
            )
        )
        total_score += 10

    if auth.dmarc_verdict == "fail":
        pts = 20 if auth.dmarc_policy in ["quarantine", "reject"] else 10
        findings.append(
            Finding(
                category="Autenticação",
                title="DMARC Fail",
                description=f"Falha de validação DMARC (política: {auth.dmarc_policy or 'none'})",
                points=pts,
                severity=RiskLevel.HIGH if pts == 20 else RiskLevel.INFO,
            )
        )
        total_score += pts

    # 2. Identidade & Spoofing
    if identity.display_name_spoofing:
        findings.append(
            Finding(
                category="Identidade & BEC",
                title="Display Name Spoofing (BEC)",
                description="Nome amigável corporativo/executivo enviado a partir de webmail público",
                points=30,
                severity=RiskLevel.CRITICAL,
            )
        )
        total_score += 30

    if identity.typosquatting_detected:
        findings.append(
            Finding(
                category="Identidade & BEC",
                title="Typosquatting no Reply-To",
                description=f"Reply-To ({identity.reply_to_domain}) possui semelhança gráfica enganosa com From ({identity.from_domain})",
                points=25,
                severity=RiskLevel.CRITICAL,
            )
        )
        total_score += 25
    elif identity.reply_to_mismatch:
        findings.append(
            Finding(
                category="Identidade & BEC",
                title="Reply-To Divergente",
                description="Respostas são desviadas para um domínio diferente do remetente",
                points=10,
                severity=RiskLevel.INFO,
            )
        )
        total_score += 10

    if identity.envelope_mismatch:
        findings.append(
            Finding(
                category="Identidade & BEC",
                title="Envelope Spoofing (From vs Return-Path)",
                description=f"Domínio visível ({identity.from_domain}) difere do Return-Path ({identity.return_path_domain})",
                points=15,
                severity=RiskLevel.HIGH,
            )
        )
        total_score += 15

    # 3. Infraestrutura & Reputação
    if origin_ip.rbl_listed:
        findings.append(
            Finding(
                category="Infraestrutura",
                title="IP em Blacklist (RBL)",
                description=f"IP de origem listado em listas negras ativas: {', '.join(origin_ip.rbl_listings)}",
                points=25,
                severity=RiskLevel.CRITICAL,
            )
        )
        total_score += 25

    if domain.age_days is not None:
        if domain.age_days < 30:
            findings.append(
                Finding(
                    category="Infraestrutura",
                    title="Domínio Recém-Registrado (< 30 dias)",
                    description=f"Domínio registrado há apenas {domain.age_days} dias (alto risco de descarte)",
                    points=20,
                    severity=RiskLevel.HIGH,
                )
            )
            total_score += 20
        elif domain.age_days < 90:
            findings.append(
                Finding(
                    category="Infraestrutura",
                    title="Domínio Jovem (< 90 dias)",
                    description=f"Domínio registrado há {domain.age_days} dias",
                    points=10,
                    severity=RiskLevel.INFO,
                )
            )
            total_score += 10

    if not domain.has_mx:
        findings.append(
            Finding(
                category="Infraestrutura",
                title="Domínio Sem Registros MX",
                description="O domínio emissor não possui servidores MX válidos para receber respostas",
                points=20,
                severity=RiskLevel.HIGH,
            )
        )
        total_score += 20

    # 4. Metadados e Gateways
    if seg.m365_cat in ["PHSH", "MALW"]:
        findings.append(
            Finding(
                category="Gateways SEGs",
                title="Microsoft 365: Veredito de Phishing/Malware",
                description=f"O gateway categorizou o e-mail como {seg.m365_cat}",
                points=25,
                severity=RiskLevel.CRITICAL,
            )
        )
        total_score += 25
    elif seg.m365_scl is not None and seg.m365_scl >= 5:
        findings.append(
            Finding(
                category="Gateways SEGs",
                title="Microsoft 365: SCL Elevado",
                description=f"Spam Confidence Level de {seg.m365_scl} (limiar de spam/risco)",
                points=15,
                severity=RiskLevel.HIGH,
            )
        )
        total_score += 15

    if client.dangerous_attachments:
        findings.append(
            Finding(
                category="Conteúdo MIME",
                title="Anexos Perigosos Detectados",
                description=f"Extensões de alto risco identificadas: {', '.join(client.dangerous_attachments)}",
                points=20,
                severity=RiskLevel.CRITICAL,
            )
        )
        total_score += 20

    if client.time_drift_suspicious:
        findings.append(
            Finding(
                category="Metadados",
                title="Descompasso Temporal Grave",
                description=f"Diferença entre data do emissor e primeiro salto de {client.time_drift_seconds // 60} minutos",
                points=10,
                severity=RiskLevel.INFO,
            )
        )
        total_score += 10

    if client.suspicious_client:
        findings.append(
            Finding(
                category="Metadados",
                title="Cliente / X-Mailer Suspeito",
                description=f"Disparador automatizado identificado: {client.x_mailer}",
                points=10,
                severity=RiskLevel.INFO,
            )
        )
        total_score += 10

    # Normalização
    final_score = min(100, total_score)
    if final_score <= 25:
        risk_level = RiskLevel.SAFE
        verdict = "E-mail com baixíssimo risco de fraude ou falsificação."
        recommendation = "Nenhuma ação bloqueante necessária. Fluxo normal."
    elif final_score <= 50:
        risk_level = RiskLevel.INFO
        verdict = "E-mail com inconsistências moderadas ou configurações permissivas."
        recommendation = "Recomenda-se cautela com links e validação do contexto antes de interagir."
    elif final_score <= 75:
        risk_level = RiskLevel.HIGH
        verdict = "Alto risco de fraude, spam ostensivo ou tentativa de phishing."
        recommendation = "Bloquear remetente e inspecionar anexos/URLs em ambiente sandbox."
    else:
        risk_level = RiskLevel.CRITICAL
        verdict = "Ameaça crítica: Fraude, BEC ou Phishing confirmado."
        recommendation = "Descartar mensagem imediatamente, isolar endpoint e adicionar IOCs ao SIEM/EDR."

    summary = AnalysisSummary(
        score=final_score,
        risk_level=risk_level,
        verdict_text=verdict,
        recommendation=recommendation,
        elapsed_ms=round(elapsed_ms, 2),
        total_hops=total_hops,
    )
    return summary, findings
