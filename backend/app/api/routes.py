import asyncio
import hashlib
import time
from email import message_from_string
from email.policy import default
from typing import Dict

import httpx
from fastapi import APIRouter, HTTPException, Response

from app.analyzers.auth_analyzer import analyze_authentication
from app.analyzers.client_analyzer import analyze_client_metadata
from app.analyzers.enrichment import lookup_geoip, lookup_rdap_domain
from app.analyzers.hops_analyzer import is_ip_private, parse_hops
from app.analyzers.identity_analyzer import analyze_identity
from app.analyzers.rbl_analyzer import check_rbls
from app.analyzers.seg_analyzer import analyze_seg_verdicts
from app.core.config import settings
from app.core.schemas import (
    DomainInfo,
    EmailAnalysisRequest,
    EmailAnalysisResponse,
    OriginIpInfo,
)
from app.engine.report_generator import generate_pdf_report
from app.engine.scoring import calculate_risk_score

try:
    from tests.fixtures.sample_emails import (
        SAMPLE_BEC_HEADER,
        SAMPLE_BOTNET_HEADER,
        SAMPLE_LEGITIMATE_HEADER,
        SAMPLE_PHISHING_HEADER,
    )
except ImportError:
    from backend.tests.fixtures.sample_emails import (
        SAMPLE_BEC_HEADER,
        SAMPLE_BOTNET_HEADER,
        SAMPLE_LEGITIMATE_HEADER,
        SAMPLE_PHISHING_HEADER,
    )

router = APIRouter()

SAMPLES: Dict[str, str] = {
    "legitimate": SAMPLE_LEGITIMATE_HEADER,
    "phishing": SAMPLE_PHISHING_HEADER,
    "bec": SAMPLE_BEC_HEADER,
    "botnet": SAMPLE_BOTNET_HEADER,
}


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "bp-email-analiser"}


@router.get("/samples/{sample_id}")
async def get_sample(sample_id: str):
    if sample_id not in SAMPLES:
        raise HTTPException(status_code=404, detail="Sample not found")
    return {"sample_id": sample_id, "raw_header": SAMPLES[sample_id]}


async def process_email(request: EmailAnalysisRequest) -> EmailAnalysisResponse:
    start_time = time.perf_counter()
    raw_header = request.raw_header.strip()
    if len(raw_header.encode("utf-8")) > settings.MAX_HEADER_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Payload Too Large: cabeçalho excede o limite máximo permitido de 1MB",
        )
    if not raw_header:
        raise HTTPException(status_code=400, detail="Cabeçalho vazio fornecido")

    header_hash = hashlib.sha256(raw_header.encode("utf-8")).hexdigest()
    msg = message_from_string(raw_header, policy=default)

    # 1. Hops
    hops = await parse_hops(msg, perform_dns=request.options.live_dns)
    first_hop_date = hops[0].timestamp if hops else None

    # Extract Origin IP (first non-private hop IP or first hop)
    origin_ip_str = None
    for h in hops:
        if h.ip and not h.is_private:
            origin_ip_str = h.ip
            break
    if not origin_ip_str and hops and hops[0].ip:
        origin_ip_str = hops[0].ip

    # 2. Identity
    identity = analyze_identity(msg)
    sender_domain = identity.from_domain

    # 3. Authentication
    auth = await analyze_authentication(
        msg, sender_domain, perform_live_dns=request.options.live_dns
    )

    # 4. Client Metadata & SEGs
    client_meta = analyze_client_metadata(msg, first_hop_date)
    seg_verdicts = analyze_seg_verdicts(msg)

    # 5. Enrichment (GeoIP, RDAP, RBL)
    origin_ip_info = OriginIpInfo(
        ip=origin_ip_str,
        is_private=is_ip_private(origin_ip_str) if origin_ip_str else False,
    )
    domain_info = DomainInfo(domain=sender_domain or "unknown")

    async with httpx.AsyncClient() as http_client:
        if request.options.rdap_lookup:
            # Gather unique public IPs from hops and origin IP
            unique_ips = list(dict.fromkeys(h.ip for h in hops if h.ip and not h.is_private))
            if origin_ip_str and origin_ip_str not in unique_ips:
                unique_ips.append(origin_ip_str)

            if unique_ips:
                geo_results = await asyncio.gather(
                    *(lookup_geoip(ip, http_client) for ip in unique_ips)
                )
                geo_cache = dict(zip(unique_ips, geo_results))
            else:
                geo_cache = {}

            if origin_ip_str and origin_ip_str in geo_cache:
                geo = geo_cache[origin_ip_str]
                origin_ip_info.country = geo.get("country")
                origin_ip_info.city = geo.get("city")
                origin_ip_info.latitude = geo.get("lat")
                origin_ip_info.longitude = geo.get("lon")
                origin_ip_info.asn = geo.get("asn")
                origin_ip_info.org = geo.get("org")

            # Map results back to hops
            for h in hops:
                if h.ip and not h.is_private and h.ip in geo_cache:
                    h_geo = geo_cache[h.ip]
                    h.country = h_geo.get("country")
                    h.city = h_geo.get("city")
                    h.latitude = h_geo.get("lat")
                    h.longitude = h_geo.get("lon")
                    h.org = h_geo.get("org")
                    h.asn = h_geo.get("asn")

        if origin_ip_str and request.options.rbl_check:
            is_listed, listings = await check_rbls(origin_ip_str)
            origin_ip_info.rbl_listed = is_listed
            origin_ip_info.rbl_listings = listings

        if sender_domain and request.options.rdap_lookup:
            domain_info = await lookup_rdap_domain(sender_domain, http_client)

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    # 6. Scoring
    summary, findings = calculate_risk_score(
        auth=auth,
        identity=identity,
        domain=domain_info,
        origin_ip=origin_ip_info,
        client=client_meta,
        seg=seg_verdicts,
        total_hops=len(hops),
        elapsed_ms=elapsed_ms,
    )

    return EmailAnalysisResponse(
        summary=summary,
        findings=findings,
        hops=hops,
        authentication=auth,
        identity=identity,
        domain_info=domain_info,
        origin_ip=origin_ip_info,
        client_metadata=client_meta,
        seg_verdicts=seg_verdicts,
        raw_header_hash=header_hash,
    )


@router.post("/analyze", response_model=EmailAnalysisResponse)
async def analyze(request: EmailAnalysisRequest):
    return await process_email(request)


@router.post("/export-pdf")
async def export_pdf(request: EmailAnalysisRequest):
    analysis = await process_email(request)
    pdf_bytes = generate_pdf_report(analysis)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f"attachment; filename=soc-email-report-{analysis.raw_header_hash[:8]}.pdf"
            )
        },
    )
