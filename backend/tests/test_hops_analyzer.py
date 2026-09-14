import pytest
from email import message_from_string
from email.policy import default
from unittest.mock import AsyncMock, MagicMock
import dns.resolver

from app.analyzers.hops_analyzer import is_ip_private, parse_hops, verify_fcrdns
from tests.fixtures.sample_emails import SAMPLE_LEGITIMATE_HEADER


@pytest.mark.asyncio
async def test_parse_hops_chronological_order():
    msg = message_from_string(SAMPLE_LEGITIMATE_HEADER, policy=default)
    hops = await parse_hops(msg, perform_dns=False)
    assert len(hops) == 1
    assert hops[0].order == 1
    assert hops[0].ip == "209.85.208.65"
    assert is_ip_private("127.0.0.1") is True
    assert is_ip_private("192.168.1.1") is True
    assert is_ip_private("209.85.208.65") is False


def test_is_ip_private_various():
    assert is_ip_private("127.0.0.1") is True
    assert is_ip_private("::1") is True
    assert is_ip_private("10.0.0.1") is True
    assert is_ip_private("172.16.5.4") is True
    assert is_ip_private("192.168.0.1") is True
    assert is_ip_private("209.85.208.65") is False
    assert is_ip_private("8.8.8.8") is False
    assert is_ip_private("invalid-ip") is False
    assert is_ip_private("") is False


@pytest.mark.asyncio
async def test_parse_hops_multiple_hops_and_delays():
    multi_hop_raw = """Received: from mx.internal.net (mx.internal.net [10.0.0.2])
    by mailbox.internal.net (Postfix) with ESMTPS id DEF456
    for <user@destination.com>; Mon, 14 Sep 2026 14:20:10 -0300
Received: from mail-ed1-f65.google.com (mail-ed1-f65.google.com [209.85.208.65])
    by mx.internal.net (Postfix) with ESMTPS id ABC123
    for <user@destination.com>; Mon, 14 Sep 2026 14:20:05 -0300
Received: from client-pc.corp (unknown [192.168.1.50])
    by mail-ed1-f65.google.com with HTTP; Mon, 14 Sep 2026 14:20:00 -0300
From: test@legitcorp.com
To: user@destination.com
Subject: Test Multi-Hop
"""
    msg = message_from_string(multi_hop_raw, policy=default)
    hops = await parse_hops(msg, perform_dns=False)

    assert len(hops) == 3

    # Hop 1: earliest hop (client to google)
    assert hops[0].order == 1
    assert hops[0].ip == "192.168.1.50"
    assert hops[0].is_private is True
    assert hops[0].from_host == "client-pc.corp"
    assert hops[0].by_host == "mail-ed1-f65.google.com"
    assert hops[0].delay_seconds == 0

    # Hop 2: google to mx.internal.net (5s delay)
    assert hops[1].order == 2
    assert hops[1].ip == "209.85.208.65"
    assert hops[1].is_private is False
    assert hops[1].from_host == "mail-ed1-f65.google.com"
    assert hops[1].by_host == "mx.internal.net"
    assert hops[1].delay_seconds == 5

    # Hop 3: mx.internal.net to mailbox.internal.net (5s delay)
    assert hops[2].order == 3
    assert hops[2].ip == "10.0.0.2"
    assert hops[2].is_private is True
    assert hops[2].from_host == "mx.internal.net"
    assert hops[2].by_host == "mailbox.internal.net"
    assert hops[2].delay_seconds == 5


@pytest.mark.asyncio
async def test_parse_hops_no_received_headers():
    raw = """From: test@example.com
To: user@example.com
Subject: No Received Headers
"""
    msg = message_from_string(raw, policy=default)
    hops = await parse_hops(msg, perform_dns=False)
    assert hops == []


@pytest.mark.asyncio
async def test_verify_fcrdns_private_ip():
    passed, hostname = await verify_fcrdns("192.168.1.1")
    assert passed is True
    assert hostname == "private-network"

    passed_v6, hostname_v6 = await verify_fcrdns("::1")
    assert passed_v6 is True
    assert hostname_v6 == "private-network"


@pytest.mark.asyncio
async def test_verify_fcrdns_mock_success():
    mock_resolver = MagicMock()

    # Mock PTR resolution
    ptr_answer = MagicMock()
    ptr_answer.target = "mail-ed1-f65.google.com."
    mock_resolver.resolve = AsyncMock(side_effect=[
        [ptr_answer],  # PTR response
        ["209.85.208.65"]  # A response
    ])

    passed, hostname = await verify_fcrdns("209.85.208.65", resolver=mock_resolver)
    assert passed is True
    assert hostname == "mail-ed1-f65.google.com"


@pytest.mark.asyncio
async def test_verify_fcrdns_mock_ip_mismatch():
    mock_resolver = MagicMock()

    # Mock PTR resolution pointing to hostname, but forward A resolves to different IP
    ptr_answer = MagicMock()
    ptr_answer.target = "spoofed-host.net."
    mock_resolver.resolve = AsyncMock(side_effect=[
        [ptr_answer],  # PTR response
        ["1.2.3.4"]  # A response does NOT match 209.85.208.65
    ])

    passed, hostname = await verify_fcrdns("209.85.208.65", resolver=mock_resolver)
    assert passed is False
    assert hostname == "spoofed-host.net"


@pytest.mark.asyncio
async def test_verify_fcrdns_mock_dns_exception():
    mock_resolver = MagicMock()
    mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

    passed, hostname = await verify_fcrdns("209.85.208.65", resolver=mock_resolver)
    assert passed is False
    assert hostname is None


@pytest.mark.asyncio
async def test_parse_hops_with_dns_resolution():
    mock_resolver = MagicMock()
    ptr_answer = MagicMock()
    ptr_answer.target = "mail-ed1-f65.google.com."
    mock_resolver.resolve = AsyncMock(side_effect=[
        [ptr_answer],
        ["209.85.208.65"]
    ])

    msg = message_from_string(SAMPLE_LEGITIMATE_HEADER, policy=default)
    hops = await parse_hops(msg, perform_dns=True, resolver=mock_resolver)
    assert len(hops) == 1
    assert hops[0].fcrdns_passed is True
    assert hops[0].fcrdns_hostname == "mail-ed1-f65.google.com"


@pytest.mark.asyncio
async def test_parse_hops_malformed_date():
    raw = """Received: from relay.example.com by mx.example.com; This is not a valid date
From: test@example.com
Subject: Test
"""
    msg = message_from_string(raw, policy=default)
    hops = await parse_hops(msg, perform_dns=False)
    assert len(hops) == 1
    assert hops[0].timestamp == "This is not a valid date"
    assert hops[0].delay_seconds == 0
