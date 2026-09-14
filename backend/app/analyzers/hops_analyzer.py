import ipaddress
import re
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
from typing import Any, List, Optional, Tuple

import dns.asyncresolver
import dns.reversename

from app.core.config import settings
from app.core.schemas import HopInfo

BRACKETED_IP_REGEX = re.compile(r"\[(?:IPv6:)?([a-fA-F0-9:.]+)\]", re.IGNORECASE)
IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)


def extract_ip_from_header(header_str: str) -> Optional[str]:
    """Extract an IPv4 or IPv6 address from a Received header string.

    Prioritizes bracketed/tagged MTA IP patterns (e.g. [1.2.3.4], [IPv6:...], [2001:db8::1]),
    falling back to unbracketed IPv4 regex matches, validated with ipaddress.ip_address.
    """
    for match in BRACKETED_IP_REGEX.finditer(header_str):
        candidate = match.group(1).strip()
        if "." in candidate or ":" in candidate:
            try:
                ip_obj = ipaddress.ip_address(candidate)
                return str(ip_obj)
            except ValueError:
                pass

    for candidate in IPV4_REGEX.findall(header_str):
        try:
            ip_obj = ipaddress.ip_address(candidate)
            return str(ip_obj)
        except ValueError:
            pass

    return None


def is_ip_private(ip_str: str) -> bool:
    """Check whether an IP address belongs to RFC 1918, loopback, or reserved ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
    except ValueError:
        return False


async def verify_fcrdns(
    ip: str,
    resolver: Optional[dns.asyncresolver.Resolver] = None,
    claimed_host: Optional[str] = None,
) -> Tuple[bool, Optional[str]]:
    """Verify Forward-Confirmed reverse DNS (FCrDNS) for an IP address.

    Performs PTR reverse lookup followed by forward A/AAAA confirmation.
    Uses canonical IP parsing to prevent false mismatches with compressed/uncompressed IPv6.
    """
    if isinstance(resolver, str):
        claimed_host = resolver
        resolver = None

    if is_ip_private(ip):
        return (True, "private-network")

    if resolver is None:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = settings.NETWORK_TIMEOUT_SECONDS

    try:
        rev_name = dns.reversename.from_address(ip)
        ptr_answers = await resolver.resolve(rev_name, "PTR")
        ptr_hostname = str(ptr_answers[0].target).rstrip(".")

        # Forward check (A/AAAA) with canonical ipaddress comparison
        qtype = "AAAA" if ":" in ip else "A"
        target_ip_obj = ipaddress.ip_address(ip)
        a_answers = await resolver.resolve(ptr_hostname, qtype)
        ips_resolved = []
        for rdata in a_answers:
            try:
                ips_resolved.append(ipaddress.ip_address(str(rdata).strip()))
            except ValueError:
                continue

        if target_ip_obj in ips_resolved:
            return (True, ptr_hostname)
        return (False, ptr_hostname)
    except Exception:
        return (False, None)


async def parse_hops(
    msg: EmailMessage,
    perform_dns: bool = True,
    resolver: Optional[dns.asyncresolver.Resolver] = None,
) -> List[HopInfo]:
    """Parse email Received headers into chronological HopInfo objects.

    Calculates delay between hops and optionally performs FCrDNS verification.
    """
    raw_received = msg.get_all("Received", [])
    if not raw_received:
        return []

    # Received headers are prepended by each MTA (latest first). Reverse to get chronological order.
    chronological_received = list(reversed(raw_received))
    hops: List[HopInfo] = []
    prev_dt = None

    for idx, header_val in enumerate(chronological_received, start=1):
        header_str = str(header_val)

        # Extract IP
        extracted_ip = extract_ip_from_header(header_str)

        # Extract from / by
        from_match = re.search(r"from\s+([^\s;()]+)", header_str, re.IGNORECASE)
        by_match = re.search(r"by\s+([^\s;()]+)", header_str, re.IGNORECASE)
        from_host = from_match.group(1) if from_match else None
        by_host = by_match.group(1) if by_match else None

        # Extract timestamp after semicolon
        timestamp_str = None
        delay_seconds = 0
        if ";" in header_str:
            date_part = header_str.split(";")[-1].strip()
            try:
                dt = parsedate_to_datetime(date_part)
                timestamp_str = dt.isoformat()
                if prev_dt:
                    try:
                        diff = int((dt - prev_dt).total_seconds())
                        delay_seconds = max(0, diff)
                    except (TypeError, ValueError):
                        delay_seconds = 0
                prev_dt = dt
            except Exception:
                timestamp_str = date_part

        is_priv = is_ip_private(extracted_ip) if extracted_ip else False
        fcrdns_ok = None
        fcrdns_host = None

        if extracted_ip and perform_dns and not is_priv:
            fcrdns_ok, fcrdns_host = await verify_fcrdns(extracted_ip, resolver=resolver)

        hop = HopInfo(
            order=idx,
            from_host=from_host,
            by_host=by_host,
            ip=extracted_ip,
            is_private=is_priv,
            timestamp=timestamp_str,
            delay_seconds=delay_seconds,
            fcrdns_passed=fcrdns_ok,
            fcrdns_hostname=fcrdns_host,
        )
        hops.append(hop)

    return hops
