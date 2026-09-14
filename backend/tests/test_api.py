from unittest.mock import AsyncMock, patch
import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.fixtures.sample_emails import (
    SAMPLE_BEC_HEADER,
    SAMPLE_BOTNET_HEADER,
    SAMPLE_LEGITIMATE_HEADER,
    SAMPLE_PHISHING_HEADER,
)

client = TestClient(app)


def test_health_endpoint():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["service"] == "bp-email-analiser"


def test_samples_endpoint_valid():
    for sample_id in ["legitimate", "phishing", "bec", "botnet"]:
        resp = client.get(f"/api/samples/{sample_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["sample_id"] == sample_id
        assert "raw_header" in data
        assert len(data["raw_header"]) > 0


def test_samples_endpoint_not_found():
    resp = client.get("/api/samples/nonexistent-sample")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Sample not found"


def test_analyze_legitimate_email():
    payload = {
        "raw_header": SAMPLE_LEGITIMATE_HEADER,
        "options": {"live_dns": False, "rdap_lookup": False, "rbl_check": False},
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "summary" in data
    assert data["summary"]["score"] <= 25
    assert len(data["hops"]) >= 1
    assert data["identity"]["from_domain"] == "legitcorp.com"
    assert data["raw_header_hash"]


def test_analyze_phishing_email():
    payload = {
        "raw_header": SAMPLE_PHISHING_HEADER,
        "options": {"live_dns": False, "rdap_lookup": False, "rbl_check": False},
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "summary" in data
    assert data["summary"]["score"] >= 40
    assert len(data["findings"]) > 0
    assert data["client_metadata"]["suspicious_client"] is True


def test_analyze_empty_header():
    payload = {
        "raw_header": "   ",
        "options": {"live_dns": False, "rdap_lookup": False, "rbl_check": False},
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Cabeçalho vazio fornecido"


def test_export_pdf_endpoint():
    payload = {
        "raw_header": SAMPLE_PHISHING_HEADER,
        "options": {"live_dns": False, "rdap_lookup": False, "rbl_check": False},
    }
    resp = client.post("/api/export-pdf", json=payload)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content[:4] == b"%PDF"
    assert "attachment; filename=soc-email-report-" in resp.headers["content-disposition"]


def test_export_pdf_empty_header():
    payload = {
        "raw_header": "",
        "options": {"live_dns": False, "rdap_lookup": False, "rbl_check": False},
    }
    resp = client.post("/api/export-pdf", json=payload)
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Cabeçalho vazio fornecido"


@pytest.mark.asyncio
async def test_analyze_with_enrichment_flow():
    with patch("app.api.routes.lookup_geoip", new_callable=AsyncMock) as mock_geoip, \
         patch("app.api.routes.lookup_rdap_domain", new_callable=AsyncMock) as mock_rdap, \
         patch("app.api.routes.check_rbls", new_callable=AsyncMock) as mock_rbl:

        mock_geoip.return_value = {
            "country": "Netherlands",
            "city": "Amsterdam",
            "lat": 52.37,
            "lon": 4.89,
            "org": "Tor Exit Node",
            "asn": "AS12345",
        }
        from app.core.schemas import DomainInfo
        mock_rdap.return_value = DomainInfo(
            domain="bradesc0-atualizacao.com",
            registered_at="2026-09-01T00:00:00Z",
            age_days=13,
            registrar="MarkMonitor",
            has_mx=False,
            mx_records=[],
        )
        mock_rbl.return_value = (True, ["zen.spamhaus.org"])

        payload = {
            "raw_header": SAMPLE_PHISHING_HEADER,
            "options": {"live_dns": False, "rdap_lookup": True, "rbl_check": True},
        }
        resp = client.post("/api/analyze", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["origin_ip"]["country"] == "Netherlands"
        assert data["origin_ip"]["rbl_listed"] is True
        assert "zen.spamhaus.org" in data["origin_ip"]["rbl_listings"]
        assert data["domain_info"]["age_days"] == 13


def test_analyze_default_options_omitted():
    with patch("app.api.routes.parse_hops", new_callable=AsyncMock) as mock_hops, \
         patch("app.api.routes.analyze_authentication", new_callable=AsyncMock) as mock_auth, \
         patch("app.api.routes.lookup_geoip", new_callable=AsyncMock) as mock_geo, \
         patch("app.api.routes.lookup_rdap_domain", new_callable=AsyncMock) as mock_rdap, \
         patch("app.api.routes.check_rbls", new_callable=AsyncMock) as mock_rbl:
        from app.core.schemas import AuthStatus, DomainInfo, HopInfo

        mock_hops.return_value = [HopInfo(order=1, ip="209.85.208.65", is_private=False)]
        mock_auth.return_value = AuthStatus(spf_verdict="pass")
        mock_geo.return_value = {"country": "United States"}
        mock_rdap.return_value = DomainInfo(domain="legitcorp.com", age_days=3000)
        mock_rbl.return_value = (False, [])

        resp = client.post("/api/analyze", json={"raw_header": SAMPLE_LEGITIMATE_HEADER})
        assert resp.status_code == 200
        data = resp.json()
        assert data["summary"]["score"] <= 25
        assert data["origin_ip"]["country"] == "United States"

