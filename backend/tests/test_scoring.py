import pytest
from app.core.schemas import (
    AuthStatus,
    IdentityAnalysis,
    DomainInfo,
    OriginIpInfo,
    ClientMetadata,
    SegVerdicts,
    RiskLevel,
    EmailAnalysisResponse,
    AnalysisSummary,
    Finding,
    HopInfo,
)
from app.engine.scoring import calculate_risk_score
from app.engine.report_generator import generate_pdf_report


def test_calculate_risk_score_clean():
    auth = AuthStatus(spf_verdict="pass", dkim_verdict="pass", dmarc_verdict="pass")
    identity = IdentityAnalysis(from_address="a@b.com", from_domain="b.com", from_display_name="A")
    domain = DomainInfo(domain="b.com", age_days=500, has_mx=True)
    origin_ip = OriginIpInfo(ip="1.2.3.4", rbl_listed=False)
    client = ClientMetadata(message_id_valid=True)
    seg = SegVerdicts()

    summary, findings = calculate_risk_score(auth, identity, domain, origin_ip, client, seg, total_hops=2, elapsed_ms=150.0)
    assert summary.score <= 25
    assert summary.risk_level == RiskLevel.SAFE
    assert summary.total_hops == 2
    assert summary.elapsed_ms == 150.0
    assert "baixíssimo risco" in summary.verdict_text
    assert len(findings) == 0


def test_calculate_risk_score_phishing():
    auth = AuthStatus(spf_verdict="fail", dkim_verdict="none", dmarc_verdict="fail", dmarc_policy="reject")
    identity = IdentityAnalysis(
        from_address="a@fake.com",
        from_domain="fake.com",
        from_display_name="CEO",
        display_name_spoofing=True,
        envelope_mismatch=True,
    )
    domain = DomainInfo(domain="fake.com", age_days=4, has_mx=False)
    origin_ip = OriginIpInfo(ip="1.2.3.4", rbl_listed=True, rbl_listings=["Spamhaus"])
    client = ClientMetadata(suspicious_client=True, dangerous_attachments=["virus.exe"])
    seg = SegVerdicts(m365_cat="PHSH")

    summary, findings = calculate_risk_score(auth, identity, domain, origin_ip, client, seg, total_hops=1, elapsed_ms=100.0)
    assert summary.score >= 76
    assert summary.risk_level == RiskLevel.CRITICAL
    assert "Ameaça crítica" in summary.verdict_text
    assert summary.score == 100  # Capped at 100
    assert len(findings) > 0


def test_calculate_risk_score_info_level():
    # Only modest findings: SPF none (+5), DKIM none (+10), domain age 45 days (+10), reply_to_mismatch (+10) -> 35 (INFO)
    auth = AuthStatus(spf_verdict="none", dkim_verdict="none", dmarc_verdict="pass")
    identity = IdentityAnalysis(
        from_address="user@domain.com",
        from_domain="domain.com",
        from_display_name="User",
        reply_to="other@domain2.com",
        reply_to_domain="domain2.com",
        reply_to_mismatch=True,
        typosquatting_detected=False,
    )
    domain = DomainInfo(domain="domain.com", age_days=45, has_mx=True)
    origin_ip = OriginIpInfo(ip="1.2.3.4", rbl_listed=False)
    client = ClientMetadata(message_id_valid=True)
    seg = SegVerdicts()

    summary, findings = calculate_risk_score(auth, identity, domain, origin_ip, client, seg, total_hops=3, elapsed_ms=80.0)
    assert 26 <= summary.score <= 50
    assert summary.risk_level == RiskLevel.INFO
    assert "moderadas" in summary.verdict_text
    assert len(findings) == 4


def test_calculate_risk_score_high_level():
    # SPF fail (+20), DKIM invalid (+20), Envelope mismatch (+15) -> 55 (HIGH)
    auth = AuthStatus(spf_verdict="fail", dkim_verdict="invalid", dmarc_verdict="pass")
    identity = IdentityAnalysis(
        from_address="user@domain.com",
        from_domain="domain.com",
        from_display_name="User",
        return_path="bounce@other.com",
        return_path_domain="other.com",
        envelope_mismatch=True,
    )
    domain = DomainInfo(domain="domain.com", age_days=200, has_mx=True)
    origin_ip = OriginIpInfo(ip="1.2.3.4", rbl_listed=False)
    client = ClientMetadata(message_id_valid=True)
    seg = SegVerdicts()

    summary, findings = calculate_risk_score(auth, identity, domain, origin_ip, client, seg, total_hops=2, elapsed_ms=95.0)
    assert 51 <= summary.score <= 75
    assert summary.risk_level == RiskLevel.HIGH
    assert "Alto risco" in summary.verdict_text


def test_calculate_risk_score_detailed_findings():
    # Test individual rules:
    # spf softfail (+10)
    # dmarc fail without quarantine/reject (+10)
    # typosquatting (+25)
    # m365 scl 6 (+15)
    # time drift suspicious (+10)
    # suspicious client (+10)
    auth = AuthStatus(spf_verdict="softfail", dkim_verdict="pass", dmarc_verdict="fail", dmarc_policy="none")
    identity = IdentityAnalysis(
        from_address="admin@paypal.com",
        from_domain="paypal.com",
        from_display_name="Admin",
        reply_to_domain="paypa1.com",
        typosquatting_detected=True,
        reply_to_mismatch=True,  # Typosquatting takes priority branch
    )
    domain = DomainInfo(domain="paypal.com", age_days=None, has_mx=True)
    origin_ip = OriginIpInfo(ip="1.2.3.4", rbl_listed=False)
    client = ClientMetadata(time_drift_suspicious=True, time_drift_seconds=3600, suspicious_client=True, x_mailer="DarkMailer")
    seg = SegVerdicts(m365_scl=6)

    summary, findings = calculate_risk_score(auth, identity, domain, origin_ip, client, seg, total_hops=2, elapsed_ms=50.0)
    # 10 + 10 + 25 + 15 + 10 + 10 = 80 -> CRITICAL
    assert summary.score == 80
    assert summary.risk_level == RiskLevel.CRITICAL
    titles = [f.title for f in findings]
    assert "SPF Softfail/Neutral" in titles
    assert "DMARC Fail" in titles
    assert "Typosquatting no Reply-To" in titles
    assert "Microsoft 365: SCL Elevado" in titles
    assert "Descompasso Temporal Grave" in titles
    assert "Cliente / X-Mailer Suspeito" in titles


def test_generate_pdf_report_with_findings_and_hops():
    summary = AnalysisSummary(
        score=85,
        risk_level=RiskLevel.CRITICAL,
        verdict_text="Ameaça crítica: Fraude, BEC ou Phishing confirmado.",
        recommendation="Descartar mensagem imediatamente.",
        elapsed_ms=120.5,
        total_hops=2,
    )
    findings = [
        Finding(category="Autenticação", title="SPF Fail", description="SPF falhou", points=20, severity=RiskLevel.HIGH),
        Finding(category="Identidade & BEC", title="Display Name Spoofing (BEC)", description="Spoofing", points=30, severity=RiskLevel.CRITICAL),
    ]
    hops = [
        HopInfo(order=1, ip="192.168.1.1", is_private=True, fcrdns_passed=None, delay_seconds=0),
        HopInfo(order=2, ip="203.0.113.195", fcrdns_passed=True, country="US", org="Cloudflare", delay_seconds=5),
        HopInfo(order=3, ip="203.0.113.196", fcrdns_passed=False, country="BR", org="ISP", delay_seconds=12),
    ]
    response = EmailAnalysisResponse(
        summary=summary,
        findings=findings,
        hops=hops,
        authentication=AuthStatus(spf_verdict="fail"),
        identity=IdentityAnalysis(from_address="boss@corp.com", from_domain="corp.com", from_display_name="Boss"),
        domain_info=DomainInfo(domain="corp.com"),
        origin_ip=OriginIpInfo(ip="203.0.113.195", country="US", org="Cloudflare"),
        client_metadata=ClientMetadata(),
        seg_verdicts=SegVerdicts(),
        raw_header_hash="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    )

    pdf_bytes = generate_pdf_report(response)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 0
    assert pdf_bytes.startswith(b"%PDF-")


def test_generate_pdf_report_clean_email():
    summary = AnalysisSummary(
        score=0,
        risk_level=RiskLevel.SAFE,
        verdict_text="E-mail com baixíssimo risco de fraude ou falsificação.",
        recommendation="Nenhuma ação bloqueante necessária. Fluxo normal.",
        elapsed_ms=45.0,
        total_hops=0,
    )
    response = EmailAnalysisResponse(
        summary=summary,
        findings=[],
        hops=[],
        authentication=AuthStatus(spf_verdict="pass", dkim_verdict="pass", dmarc_verdict="pass"),
        identity=IdentityAnalysis(from_address="info@google.com", from_domain="google.com", from_display_name="Google"),
        domain_info=DomainInfo(domain="google.com"),
        origin_ip=OriginIpInfo(),
        client_metadata=ClientMetadata(),
        seg_verdicts=SegVerdicts(),
        raw_header_hash="0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff",
    )

    pdf_bytes = generate_pdf_report(response)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 0
    assert pdf_bytes.startswith(b"%PDF-")
