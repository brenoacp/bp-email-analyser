from app.core.config import settings
from app.core.schemas import (
    AnalysisOptions,
    AnalysisSummary,
    AuthStatus,
    ClientMetadata,
    DomainInfo,
    EmailAnalysisRequest,
    EmailAnalysisResponse,
    Finding,
    HopInfo,
    IdentityAnalysis,
    OriginIpInfo,
    RiskLevel,
    SegVerdicts,
)
from tests.fixtures.sample_emails import (
    SAMPLE_BEC_HEADER,
    SAMPLE_BOTNET_HEADER,
    SAMPLE_LEGITIMATE_HEADER,
    SAMPLE_PHISHING_HEADER,
)


def test_schema_serialization():
    req = EmailAnalysisRequest(raw_header="From: test@example.com\nTo: user@example.com\nSubject: Test")
    assert "From:" in req.raw_header
    assert req.options.live_dns is True

    finding = Finding(
        category="Autenticação",
        title="DMARC Fail",
        description="A política DMARC falhou",
        points=20,
        severity=RiskLevel.HIGH,
    )
    assert finding.points == 20
    assert finding.severity == RiskLevel.HIGH


def test_analysis_options_defaults():
    options = AnalysisOptions()
    assert options.live_dns is True
    assert options.rdap_lookup is True
    assert options.rbl_check is True


def test_full_email_analysis_response():
    summary = AnalysisSummary(
        score=15,
        risk_level=RiskLevel.SAFE,
        verdict_text="Seguro",
        recommendation="E-mail legítimo.",
        elapsed_ms=120.5,
        total_hops=2,
    )
    finding = Finding(
        category="SPF",
        title="SPF Pass",
        description="SPF alinhado",
        points=0,
        severity=RiskLevel.SAFE,
    )
    hop = HopInfo(
        order=1,
        by_host="mx.destination.com",
        from_host="mail-ed1-f65.google.com",
        ip="209.85.208.65",
        is_private=False,
    )
    auth = AuthStatus(
        spf_verdict="pass",
        dkim_verdict="pass",
        dmarc_verdict="pass",
    )
    identity = IdentityAnalysis(
        from_address="sender@legitcorp.com",
        from_domain="legitcorp.com",
        from_display_name="Equipe Suporte",
    )
    domain_info = DomainInfo(
        domain="legitcorp.com",
        has_mx=True,
        mx_records=["aspmx.l.google.com"],
    )
    origin_ip = OriginIpInfo(
        ip="209.85.208.65",
        is_private=False,
        country="US",
    )
    client_meta = ClientMetadata(
        message_id="<CABe_3k@mail.legitcorp.com>",
        message_id_valid=True,
    )
    seg_verdicts = SegVerdicts(
        sandbox_detected=False,
    )

    response = EmailAnalysisResponse(
        summary=summary,
        findings=[finding],
        hops=[hop],
        authentication=auth,
        identity=identity,
        domain_info=domain_info,
        origin_ip=origin_ip,
        client_metadata=client_meta,
        seg_verdicts=seg_verdicts,
        raw_header_hash="abc123hash",
    )

    data = response.model_dump()
    assert data["summary"]["score"] == 15
    assert data["summary"]["risk_level"] == "SAFE"
    assert len(data["findings"]) == 1
    assert len(data["hops"]) == 1
    assert data["raw_header_hash"] == "abc123hash"


def test_settings_config():
    assert settings.PROJECT_NAME == "bp-email-analiser"
    assert settings.API_PREFIX == "/api"
    assert settings.NETWORK_TIMEOUT_SECONDS == 2.5
    assert settings.MAX_HEADER_SIZE_BYTES == 1_000_000


def test_sample_email_fixtures():
    assert "From: \"Equipe Suporte\" <sender@legitcorp.com>" in SAMPLE_LEGITIMATE_HEADER
    assert "seguranca@bradesc0-atualizacao.com" in SAMPLE_PHISHING_HEADER
    assert "roberto.silva.ceo2026@gmail.com" in SAMPLE_BEC_HEADER
    assert "dynamic-pool-189-12-34.isp.net" in SAMPLE_BOTNET_HEADER
