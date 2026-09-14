import pytest
from email import message_from_string
from email.policy import default
from unittest.mock import AsyncMock, MagicMock
import dns.resolver

from app.analyzers.auth_analyzer import (
    extract_header_auth_results,
    parse_dkim_header,
    query_live_dns_auth,
    analyze_authentication,
)
from app.core.schemas import AuthStatus
from tests.fixtures.sample_emails import SAMPLE_LEGITIMATE_HEADER


def test_extract_header_auth_results():
    msg = message_from_string(SAMPLE_LEGITIMATE_HEADER, policy=default)
    auth = extract_header_auth_results(msg)
    assert auth.spf_verdict == "pass"
    assert auth.dkim_verdict == "pass"
    assert auth.dmarc_verdict == "pass"
    assert auth.dkim_domain == "legitcorp.com"
    assert auth.dkim_selector == "google"
    assert auth.dmarc_policy == "reject"


def test_parse_dkim_signature():
    dkim_sig = "v=1; a=rsa-sha256; d=example.com; s=sel1; b=abc"
    d, s = parse_dkim_header(dkim_sig)
    assert d == "example.com"
    assert s == "sel1"


def test_parse_dkim_signature_none_or_malformed():
    assert parse_dkim_header("") == (None, None)
    assert parse_dkim_header("v=1; a=rsa-sha256; b=abc") == (None, None)
    d, s = parse_dkim_header("d=domain.org; other=123")
    assert d == "domain.org"
    assert s is None


def test_fallback_received_spf():
    email_text = """From: user@example.com
Received-SPF: pass (myusers.net: domain of sender@example.com designates 1.2.3.4 as permitted sender)
Subject: Test SPF Fallback
"""
    msg = message_from_string(email_text, policy=default)
    auth = extract_header_auth_results(msg)
    assert auth.spf_verdict == "pass"


def test_fallback_received_spf_softfail():
    email_text = """From: user@example.com
Received-SPF: softfail (mx.google.com: domain of transitioning sender@example.com does not designate 1.2.3.4)
Subject: Test Softfail
"""
    msg = message_from_string(email_text, policy=default)
    auth = extract_header_auth_results(msg)
    assert auth.spf_verdict == "softfail"


def test_dkim_signature_fallback_signed():
    email_text = """From: user@corp.net
DKIM-Signature: v=1; a=rsa-sha256; d=corp.net; s=key2026; b=12345
Subject: Signed Email
"""
    msg = message_from_string(email_text, policy=default)
    auth = extract_header_auth_results(msg)
    assert auth.dkim_verdict == "signed"
    assert auth.dkim_domain == "corp.net"
    assert auth.dkim_selector == "key2026"


def test_arc_authentication_results():
    email_text = """From: user@corp.net
ARC-Authentication-Results: i=1; mx.google.com;
    dkim=pass header.i=@corp.net header.s=key1;
    spf=pass (google.com: domain of user@corp.net designates 10.0.0.1 as permitted sender);
    arc=pass (as.1.corp.net)
Subject: ARC Test
"""
    msg = message_from_string(email_text, policy=default)
    auth = extract_header_auth_results(msg)
    assert auth.arc_verdict == "pass"


def test_arc_cv_variant():
    email_text = """From: user@corp.net
ARC-Authentication-Results: i=1; mx.google.com; cv=pass
Subject: ARC CV Test
"""
    msg = message_from_string(email_text, policy=default)
    auth = extract_header_auth_results(msg)
    assert auth.arc_verdict == "pass"


def test_empty_email():
    msg = message_from_string("", policy=default)
    auth = extract_header_auth_results(msg)
    assert auth.spf_verdict == "none"
    assert auth.dkim_verdict == "none"
    assert auth.dmarc_verdict == "none"
    assert auth.arc_verdict == "none"
    assert auth.spf_record is None
    assert auth.dmarc_record is None


@pytest.mark.asyncio
async def test_query_live_dns_auth_success():
    status = AuthStatus()

    mock_resolver = AsyncMock()

    spf_rdata = MagicMock()
    spf_rdata.strings = [b"v=spf1 include:_spf.example.com ~all"]

    dmarc_rdata = MagicMock()
    dmarc_rdata.strings = [b"v=DMARC1; p=quarantine; pct=100;"]

    async def mock_resolve(qname, qtype):
        if qtype == "TXT" and qname == "example.com":
            return [spf_rdata]
        elif qtype == "TXT" and qname == "_dmarc.example.com":
            return [dmarc_rdata]
        raise dns.resolver.NXDOMAIN()

    mock_resolver.resolve = AsyncMock(side_effect=mock_resolve)

    await query_live_dns_auth("example.com", status, resolver=mock_resolver)

    assert status.spf_record == "v=spf1 include:_spf.example.com ~all"
    assert status.dmarc_record == "v=DMARC1; p=quarantine; pct=100;"
    assert status.dmarc_policy == "quarantine"


@pytest.mark.asyncio
async def test_query_live_dns_auth_error_handling():
    status = AuthStatus()
    mock_resolver = AsyncMock()
    mock_resolver.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

    await query_live_dns_auth("nonexistent.invalid", status, resolver=mock_resolver)

    assert status.spf_record is None
    assert status.dmarc_record is None


@pytest.mark.asyncio
async def test_query_live_dns_auth_empty_domain():
    status = AuthStatus()
    await query_live_dns_auth("", status)
    assert status.spf_record is None
    assert status.dmarc_record is None


@pytest.mark.asyncio
async def test_analyze_authentication_with_dns():
    msg = message_from_string(SAMPLE_LEGITIMATE_HEADER, policy=default)

    mock_resolver = AsyncMock()
    spf_rdata = MagicMock()
    spf_rdata.strings = [b"v=spf1 include:_spf.legitcorp.com ~all"]
    dmarc_rdata = MagicMock()
    dmarc_rdata.strings = [b"v=DMARC1; p=reject;"]

    async def mock_resolve(qname, qtype):
        if qtype == "TXT" and qname == "legitcorp.com":
            return [spf_rdata]
        elif qtype == "TXT" and qname == "_dmarc.legitcorp.com":
            return [dmarc_rdata]
        raise dns.resolver.NXDOMAIN()

    mock_resolver.resolve = AsyncMock(side_effect=mock_resolve)

    auth = await analyze_authentication(
        msg,
        "legitcorp.com",
        perform_live_dns=True,
        resolver=mock_resolver,
    )

    assert auth.spf_verdict == "pass"
    assert auth.dkim_verdict == "pass"
    assert auth.dmarc_verdict == "pass"
    assert auth.dkim_domain == "legitcorp.com"
    assert auth.spf_record == "v=spf1 include:_spf.legitcorp.com ~all"
    assert auth.dmarc_record == "v=DMARC1; p=reject;"
    assert auth.dmarc_policy == "reject"


@pytest.mark.asyncio
async def test_analyze_authentication_skip_dns():
    msg = message_from_string(SAMPLE_LEGITIMATE_HEADER, policy=default)

    auth = await analyze_authentication(
        msg,
        "legitcorp.com",
        perform_live_dns=False,
    )

    assert auth.spf_verdict == "pass"
    assert auth.spf_record is None
    assert auth.dmarc_record is None


def test_extract_multiple_authentication_results_headers():
    email_text = """From: user@example.com
Authentication-Results: mta1.example.com; spf=pass smtp.mailfrom=example.com
Authentication-Results: mta2.example.com; dkim=pass header.i=@example.com header.s=s1; dmarc=pass p=reject
Subject: Multi-header test
"""
    msg = message_from_string(email_text, policy=default)
    auth = extract_header_auth_results(msg)
    assert auth.spf_verdict == "pass"
    assert auth.dkim_verdict == "pass"
    assert auth.dmarc_verdict == "pass"
    assert auth.dmarc_policy == "reject"
    assert auth.dkim_domain == "example.com"
    assert auth.dkim_selector == "s1"


@pytest.mark.asyncio
async def test_analyze_authentication_positional_resolver():
    msg = message_from_string(SAMPLE_LEGITIMATE_HEADER, policy=default)

    mock_resolver = AsyncMock()
    spf_rdata = MagicMock()
    spf_rdata.strings = [b"v=spf1 -all"]
    dmarc_rdata = MagicMock()
    dmarc_rdata.strings = [b"v=DMARC1; p=none;"]

    async def mock_resolve(qname, qtype):
        if qtype == "TXT" and qname == "legitcorp.com":
            return [spf_rdata]
        elif qtype == "TXT" and qname == "_dmarc.legitcorp.com":
            return [dmarc_rdata]
        raise dns.resolver.NXDOMAIN()

    mock_resolver.resolve = AsyncMock(side_effect=mock_resolve)

    # Calling with resolver as 3rd positional argument
    auth = await analyze_authentication(msg, "legitcorp.com", mock_resolver)
    assert auth.spf_record == "v=spf1 -all"
    assert auth.dmarc_record == "v=DMARC1; p=none;"

