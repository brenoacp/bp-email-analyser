import asyncio
import re
from email.message import EmailMessage
from typing import Any, Optional, Tuple, Union

import dns.asyncresolver

from app.core.config import settings
from app.core.schemas import AuthStatus


def parse_dkim_header(header_val: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract domain (d=) and selector (s=) from a DKIM-Signature header value."""
    if not header_val:
        return None, None
    d_match = re.search(r"\bd=([^\s;]+)", header_val)
    s_match = re.search(r"\bs=([^\s;]+)", header_val)
    d = d_match.group(1).strip('"') if d_match else None
    s = s_match.group(1).strip('"') if s_match else None
    return d, s


def extract_header_auth_results(msg: EmailMessage) -> AuthStatus:
    """Extract authentication verdicts (SPF, DKIM, DMARC, ARC) from message headers.

    Inspects Authentication-Results, Received-SPF, DKIM-Signature, and
    ARC-Authentication-Results headers.
    """
    status = AuthStatus()
    auth_headers = msg.get_all("Authentication-Results", [])
    auth_results = " ; ".join(str(h) for h in auth_headers) if auth_headers else str(msg.get("Authentication-Results") or "")

    # SPF
    spf_match = re.search(r"\bspf=(\w+)", auth_results, re.IGNORECASE)
    if spf_match:
        status.spf_verdict = spf_match.group(1).lower()
    else:
        # Fallback to Received-SPF header
        rec_spf = str(msg.get("Received-SPF") or "")
        if rec_spf:
            tokens = rec_spf.strip().split()
            if tokens:
                status.spf_verdict = tokens[0].rstrip(";:,()").lower()

    # DKIM
    dkim_match = re.search(r"\bdkim=(\w+)", auth_results, re.IGNORECASE)
    if dkim_match:
        status.dkim_verdict = dkim_match.group(1).lower()

    # Check DKIM-Signature header for selector and domain
    dkim_header = str(msg.get("DKIM-Signature") or "")
    if dkim_header:
        d, s = parse_dkim_header(dkim_header)
        if d:
            status.dkim_domain = d
        if s:
            status.dkim_selector = s
        if status.dkim_verdict == "none":
            status.dkim_verdict = "signed"

    # Fallback to Authentication-Results tags for DKIM domain/selector if missing
    if not status.dkim_domain:
        i_match = re.search(r"header\.i=@?([^\s;]+)", auth_results, re.IGNORECASE)
        if i_match:
            status.dkim_domain = i_match.group(1).lstrip("@")
    if not status.dkim_selector:
        s_match = re.search(r"header\.s=([^\s;]+)", auth_results, re.IGNORECASE)
        if s_match:
            status.dkim_selector = s_match.group(1)

    # DMARC
    dmarc_match = re.search(r"\bdmarc=(\w+)", auth_results, re.IGNORECASE)
    if dmarc_match:
        status.dmarc_verdict = dmarc_match.group(1).lower()
        pol_match = re.search(r"\bp=(\w+)", auth_results, re.IGNORECASE)
        if pol_match:
            status.dmarc_policy = pol_match.group(1).lower()

    # ARC
    arc_headers = msg.get_all("ARC-Authentication-Results", [])
    arc_results = " ; ".join(str(h) for h in arc_headers) if arc_headers else str(msg.get("ARC-Authentication-Results") or "")
    if arc_results:
        arc_match = re.search(r"\b(?:arc|cv)=(\w+)", arc_results, re.IGNORECASE)
        if arc_match:
            status.arc_verdict = arc_match.group(1).lower()

    return status


async def _query_spf_txt(domain: str, resolver: dns.asyncresolver.Resolver) -> Optional[str]:
    """Query SPF TXT record for a domain."""
    try:
        txt_records = await resolver.resolve(domain, "TXT")
        for rdata in txt_records:
            if hasattr(rdata, "strings"):
                txt_str = "".join(
                    s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s)
                    for s in rdata.strings
                )
            else:
                txt_str = str(rdata)
            txt_str = txt_str.strip(' "')
            if txt_str.lower().startswith("v=spf1"):
                return txt_str
    except Exception:
        pass
    return None


async def _query_dmarc_txt(
    domain: str, resolver: dns.asyncresolver.Resolver
) -> Tuple[Optional[str], Optional[str]]:
    """Query DMARC TXT record for _dmarc.<domain> and extract record and policy."""
    try:
        dmarc_host = f"_dmarc.{domain}"
        txt_records = await resolver.resolve(dmarc_host, "TXT")
        for rdata in txt_records:
            if hasattr(rdata, "strings"):
                txt_str = "".join(
                    s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else str(s)
                    for s in rdata.strings
                )
            else:
                txt_str = str(rdata)
            txt_str = txt_str.strip(' "')
            if txt_str.upper().startswith("V=DMARC1"):
                policy = None
                pol_match = re.search(r"\bp=([a-zA-Z]+)", txt_str, re.IGNORECASE)
                if pol_match:
                    policy = pol_match.group(1).lower()
                return txt_str, policy
    except Exception:
        pass
    return None, None


async def query_live_dns_auth(
    domain: str,
    status: AuthStatus,
    resolver: Optional[dns.asyncresolver.Resolver] = None,
) -> None:
    """Query live DNS TXT records for SPF and DMARC policies in parallel."""
    if not domain:
        return

    if resolver is None:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = settings.NETWORK_TIMEOUT_SECONDS

    spf_record, (dmarc_record, dmarc_policy) = await asyncio.gather(
        _query_spf_txt(domain, resolver),
        _query_dmarc_txt(domain, resolver),
    )

    if spf_record:
        status.spf_record = spf_record

    if dmarc_record:
        status.dmarc_record = dmarc_record
        if not status.dmarc_policy and dmarc_policy:
            status.dmarc_policy = dmarc_policy


async def analyze_authentication(
    msg: EmailMessage,
    sender_domain: str,
    perform_live_dns: Union[bool, Any] = True,
    resolver: Optional[dns.asyncresolver.Resolver] = None,
) -> AuthStatus:
    """Analyze email authentication headers and optionally query live DNS SPF/DMARC records."""
    if not isinstance(perform_live_dns, bool):
        resolver = perform_live_dns
        perform_live_dns = True

    status = extract_header_auth_results(msg)
    if perform_live_dns and sender_domain:
        await query_live_dns_auth(sender_domain, status, resolver=resolver)

    return status
