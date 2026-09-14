from datetime import datetime, timezone
import ipaddress
from typing import Any, Dict, List, Optional, Tuple

import dns.asyncresolver
import httpx

from app.core.config import settings
from app.core.schemas import DomainInfo


def calculate_domain_age_days(registered_date_iso: Optional[str]) -> Optional[int]:
    """Calculate the age of a domain in days from its ISO 8601 registration date string."""
    if not registered_date_iso:
        return None
    try:
        clean_date = registered_date_iso.replace("Z", "+00:00")
        reg_dt = datetime.fromisoformat(clean_date)
        if reg_dt.tzinfo is None:
            reg_dt = reg_dt.replace(tzinfo=timezone.utc)
        now_dt = datetime.now(timezone.utc)
        diff = now_dt - reg_dt
        return max(0, diff.days)
    except Exception:
        return None


async def check_mx_records(
    domain: str, resolver: Optional[dns.asyncresolver.Resolver] = None
) -> Tuple[bool, List[str]]:
    """Query MX DNS records for a domain, returning sorted valid mail exchange hosts."""
    if not domain or not domain.strip():
        return (False, [])

    clean_domain = domain.strip().rstrip(".")
    if resolver is None:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = settings.NETWORK_TIMEOUT_SECONDS

    try:
        answers = await resolver.resolve(clean_domain, "MX")
        mx_list = [str(r.exchange).rstrip(".") for r in sorted(answers, key=lambda x: x.preference)]
        # Filter out bogus / loopback MX destinations
        valid_mx = [mx for mx in mx_list if mx.lower() not in ["localhost", "127.0.0.1", "0.0.0.0", ""]]
        return (len(valid_mx) > 0, valid_mx)
    except Exception:
        return (False, [])


async def lookup_geoip(ip: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """Look up geographic and ASN metadata for an IP address using ip-api.com."""
    if not ip:
        return {}

    clean_ip = ip.strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            return {
                "country": "Local",
                "city": "Rede Interna",
                "lat": 0.0,
                "lon": 0.0,
                "org": "Privado",
                "asn": "N/A",
            }
    except ValueError:
        return {}

    try:
        url = f"http://ip-api.com/json/{clean_ip}?fields=status,country,city,lat,lon,org,as"
        resp = await client.get(url, timeout=settings.NETWORK_TIMEOUT_SECONDS)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "org": data.get("org"),
                    "asn": data.get("as"),
                }
    except Exception:
        pass

    return {}


async def lookup_rdap_domain(
    domain: str,
    client: httpx.AsyncClient,
    resolver: Optional[dns.asyncresolver.Resolver] = None,
) -> DomainInfo:
    """Query domain registration details via RDAP and verify active MX records."""
    info = DomainInfo(domain=domain)
    if not domain or not domain.strip():
        info.has_mx = False
        return info

    clean_domain = domain.strip().rstrip(".")

    # Check MX records first
    has_mx, mx_records = await check_mx_records(clean_domain, resolver=resolver)
    info.has_mx = has_mx
    info.mx_records = mx_records

    # Query RDAP
    try:
        url = f"https://rdap.org/domain/{clean_domain}"
        resp = await client.get(url, timeout=settings.NETWORK_TIMEOUT_SECONDS, follow_redirects=True)
        if resp.status_code == 200:
            data = resp.json()
            # Extract events (registration date)
            for ev in data.get("events", []):
                action = ev.get("eventAction")
                if action in ["registration", "created"]:
                    info.registered_at = ev.get("eventDate")
                    info.age_days = calculate_domain_age_days(info.registered_at)

            # Extract registrar entity
            for ent in data.get("entities", []):
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1 and isinstance(vcard[1], list):
                        for prop in vcard[1]:
                            if isinstance(prop, list) and len(prop) > 3 and prop[0] == "fn":
                                info.registrar = prop[3]
    except Exception:
        pass

    return info
