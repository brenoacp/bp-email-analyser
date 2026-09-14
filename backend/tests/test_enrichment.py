import pytest
from unittest.mock import AsyncMock, MagicMock
import dns.asyncresolver
import httpx

from app.analyzers.enrichment import (
    calculate_domain_age_days,
    check_mx_records,
    lookup_geoip,
    lookup_rdap_domain,
)
from app.analyzers.rbl_analyzer import check_rbls, reverse_ip_for_rbl, PUBLIC_RBLS


def test_calculate_domain_age():
    # 2026-09-01 registered vs 2026-09-14
    age = calculate_domain_age_days("2026-09-01T00:00:00Z")
    assert age is not None
    assert age >= 10


def test_calculate_domain_age_variants():
    # Test None / empty
    assert calculate_domain_age_days(None) is None
    assert calculate_domain_age_days("") is None
    assert calculate_domain_age_days("invalid-date-string") is None

    # Test naive ISO date
    age_naive = calculate_domain_age_days("2020-01-01T00:00:00")
    assert age_naive is not None
    assert age_naive > 1000

    # Test ISO date with timezone offset
    age_tz = calculate_domain_age_days("2020-01-01T00:00:00+02:00")
    assert age_tz is not None
    assert age_tz > 1000

    # Test future date returns 0
    age_future = calculate_domain_age_days("2099-01-01T00:00:00Z")
    assert age_future == 0


def test_reverse_ip_for_rbl():
    rev = reverse_ip_for_rbl("185.220.101.5")
    assert rev == "5.101.220.185"

    rev2 = reverse_ip_for_rbl("  1.2.3.4  ")
    assert rev2 == "4.3.2.1"


@pytest.mark.asyncio
async def test_check_rbls_private_ip():
    is_listed, listings = await check_rbls("127.0.0.1")
    assert not is_listed
    assert listings == []

    is_listed, listings = await check_rbls("192.168.1.1")
    assert not is_listed
    assert listings == []

    is_listed, listings = await check_rbls("10.0.0.5")
    assert not is_listed
    assert listings == []

    is_listed, listings = await check_rbls("172.16.0.1")
    assert not is_listed
    assert listings == []

    is_listed, listings = await check_rbls("172.31.255.254")
    assert not is_listed
    assert listings == []

    is_listed, listings = await check_rbls("")
    assert not is_listed
    assert listings == []


@pytest.mark.asyncio
async def test_check_rbls_public_172_ip():
    # 172.217.16.1 is a public Google IP, must NOT be skipped
    mock_resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
    mock_resolver.resolve = AsyncMock(return_value=["127.0.0.2"])

    is_listed, listings = await check_rbls("172.217.16.1", resolver=mock_resolver)
    assert is_listed is True
    assert len(listings) == 3


@pytest.mark.asyncio
async def test_check_rbls_spamhaus_open_resolver_rejection():
    # 127.255.255.254 / 255 indicates Spamhaus query refusal, not a blacklist hit
    mock_resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
    mock_resolver.resolve = AsyncMock(return_value=["127.255.255.254"])

    is_listed, listings = await check_rbls("185.220.101.5", resolver=mock_resolver)
    assert is_listed is False
    assert listings == []


@pytest.mark.asyncio
async def test_check_rbls_listed_and_clean():
    mock_resolver = AsyncMock(spec=dns.asyncresolver.Resolver)

    async def mock_resolve(qname, rtype):
        if "zen.spamhaus.org" in str(qname):
            return ["127.0.0.2"]
        raise dns.resolver.NXDOMAIN()

    mock_resolver.resolve = AsyncMock(side_effect=mock_resolve)

    is_listed, listings = await check_rbls("185.220.101.5", resolver=mock_resolver)
    assert is_listed is True
    assert listings == ["zen.spamhaus.org"]


@pytest.mark.asyncio
async def test_check_rbls_all_clean():
    mock_resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
    mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

    is_listed, listings = await check_rbls("8.8.8.8", resolver=mock_resolver)
    assert is_listed is False
    assert listings == []


@pytest.mark.asyncio
async def test_check_mx_records_success():
    mock_resolver = AsyncMock(spec=dns.asyncresolver.Resolver)

    mx1 = MagicMock()
    mx1.preference = 10
    mx1.exchange = "mail.example.com."

    mx2 = MagicMock()
    mx2.preference = 5
    mx2.exchange = "mail-priority.example.com."

    mock_resolver.resolve = AsyncMock(return_value=[mx1, mx2])

    has_mx, records = await check_mx_records("example.com", resolver=mock_resolver)
    assert has_mx is True
    # Priority 5 should come before priority 10
    assert records == ["mail-priority.example.com", "mail.example.com"]


@pytest.mark.asyncio
async def test_check_mx_records_bogus_localhost():
    mock_resolver = AsyncMock(spec=dns.asyncresolver.Resolver)

    mx_bogus = MagicMock()
    mx_bogus.preference = 10
    mx_bogus.exchange = "localhost."

    mock_resolver.resolve = AsyncMock(return_value=[mx_bogus])

    has_mx, records = await check_mx_records("bogus.example.com", resolver=mock_resolver)
    assert has_mx is False
    assert records == []


@pytest.mark.asyncio
async def test_check_mx_records_error():
    mock_resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
    mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

    has_mx, records = await check_mx_records("nonexistent.example.com", resolver=mock_resolver)
    assert has_mx is False
    assert records == []

    # Empty domain test
    has_mx_empty, records_empty = await check_mx_records("", resolver=mock_resolver)
    assert has_mx_empty is False
    assert records_empty == []


@pytest.mark.asyncio
async def test_lookup_geoip_private_ip():
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    res = await lookup_geoip("192.168.1.1", mock_client)
    assert res["country"] == "Local"
    assert res["city"] == "Rede Interna"
    assert res["org"] == "Privado"
    assert res["asn"] == "N/A"
    mock_client.get.assert_not_called()

    # RFC 1918 172.16.x.x
    res_172 = await lookup_geoip("172.16.0.1", mock_client)
    assert res_172["country"] == "Local"
    mock_client.get.assert_not_called()


@pytest.mark.asyncio
async def test_lookup_geoip_public_172_ip():
    # Public 172.217.16.1 (Google) should query ip-api, not be treated as Local
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "success",
        "country": "United States",
        "city": "Mountain View",
        "lat": 37.4056,
        "lon": -122.0775,
        "org": "Google LLC",
        "as": "AS15169 Google LLC",
    }
    mock_client.get = AsyncMock(return_value=mock_resp)

    res = await lookup_geoip("172.217.16.1", mock_client)
    assert res["country"] == "United States"
    assert res["org"] == "Google LLC"
    mock_client.get.assert_called_once()


@pytest.mark.asyncio
async def test_lookup_geoip_success():
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "success",
        "country": "Germany",
        "city": "Frankfurt",
        "lat": 50.1109,
        "lon": 8.6821,
        "org": "Example ISP",
        "as": "AS12345 Example AG",
    }
    mock_client.get = AsyncMock(return_value=mock_resp)

    res = await lookup_geoip("185.220.101.5", mock_client)
    assert res["country"] == "Germany"
    assert res["city"] == "Frankfurt"
    assert res["lat"] == 50.1109
    assert res["lon"] == 8.6821
    assert res["org"] == "Example ISP"
    assert res["asn"] == "AS12345 Example AG"


@pytest.mark.asyncio
async def test_lookup_geoip_failure_and_exception():
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    # Fail response from ip-api
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "fail", "message": "reserved range"}
    mock_client.get = AsyncMock(return_value=mock_resp)

    res = await lookup_geoip("8.8.8.8", mock_client)
    assert res == {}

    # HTTP error / Exception
    mock_client.get = AsyncMock(side_effect=httpx.ConnectTimeout("timeout"))
    res2 = await lookup_geoip("8.8.8.8", mock_client)
    assert res2 == {}


@pytest.mark.asyncio
async def test_lookup_rdap_domain_success():
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-15T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2024-01-15T00:00:00Z"},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "GoDaddy.com, LLC"],
                    ],
                ],
            }
        ],
    }
    mock_client.get = AsyncMock(return_value=mock_resp)

    mock_resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
    mx = MagicMock()
    mx.preference = 10
    mx.exchange = "mail.example.com."
    mock_resolver.resolve = AsyncMock(return_value=[mx])

    info = await lookup_rdap_domain("example.com", mock_client, resolver=mock_resolver)
    assert info.domain == "example.com"
    assert info.has_mx is True
    assert info.mx_records == ["mail.example.com"]
    assert info.registered_at == "2020-01-15T00:00:00Z"
    assert info.age_days is not None
    assert info.age_days > 1000
    assert info.registrar == "GoDaddy.com, LLC"


@pytest.mark.asyncio
async def test_lookup_rdap_domain_network_failure():
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(side_effect=httpx.ConnectTimeout("timeout"))

    mock_resolver = AsyncMock(spec=dns.asyncresolver.Resolver)
    mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

    info = await lookup_rdap_domain("failing.com", mock_client, resolver=mock_resolver)
    assert info.domain == "failing.com"
    assert info.has_mx is False
    assert info.mx_records == []
    assert info.registered_at is None
    assert info.age_days is None
    assert info.registrar is None
