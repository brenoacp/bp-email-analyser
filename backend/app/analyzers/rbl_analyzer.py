import asyncio
import ipaddress
from typing import List, Optional, Tuple

import dns.asyncresolver

from app.core.config import settings

PUBLIC_RBLS: List[str] = [
    "zen.spamhaus.org",
    "b.barracudacentral.org",
    "bl.spamcop.net",
]


def reverse_ip_for_rbl(ip: str) -> str:
    """Reverse IPv4 octets for DNS-based Blackhole List (RBL) query format."""
    parts = ip.strip().split(".")
    return ".".join(reversed(parts))


async def check_rbls(
    ip: str, resolver: Optional[dns.asyncresolver.Resolver] = None
) -> Tuple[bool, List[str]]:
    """Query reputation blacklists (Spamhaus Zen, Barracuda, SpamCop) for an IP address.

    Queries all RBLs concurrently via asyncio.gather.
    Returns a tuple of (is_listed, list_of_rbl_names).
    Private, loopback, empty or invalid IPv4 addresses are safely skipped.
    Filters out Spamhaus open resolver rejection codes (127.255.255.x).
    """
    if not ip:
        return False, []

    clean_ip = ip.strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.version != 4:
            return False, []
    except ValueError:
        return False, []

    if resolver is None:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = settings.NETWORK_TIMEOUT_SECONDS

    rev_ip = reverse_ip_for_rbl(clean_ip)

    async def _query_single_rbl(rbl: str) -> Optional[str]:
        query_host = f"{rev_ip}.{rbl}"
        try:
            answers = await resolver.resolve(query_host, "A")
            for r in answers:
                ip_ans = str(r).strip()
                # Ignore Spamhaus rejection / open resolver return codes (127.255.255.x)
                if ip_ans.startswith("127.255.255."):
                    continue
                if ip_ans.startswith("127."):
                    return rbl
        except Exception:
            pass
        return None

    results = await asyncio.gather(*[_query_single_rbl(rbl) for rbl in PUBLIC_RBLS])
    listings = [r for r in results if r is not None]

    return (len(listings) > 0, listings)
