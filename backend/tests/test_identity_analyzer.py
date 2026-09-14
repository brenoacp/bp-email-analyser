from email import message_from_string
from email.policy import default
from app.analyzers.identity_analyzer import (
    analyze_identity,
    is_display_name_spoofing,
    calculate_levenshtein_ratio,
    extract_domain,
)
from tests.fixtures.sample_emails import (
    SAMPLE_BEC_HEADER,
    SAMPLE_PHISHING_HEADER,
    SAMPLE_LEGITIMATE_HEADER,
)


def test_bec_display_name_detection():
    assert is_display_name_spoofing("Diretoria Financeira - Roberto", "attacker@gmail.com") is True
    assert is_display_name_spoofing("CEO da Empresa", "hacker@hotmail.com") is True
    assert is_display_name_spoofing("Amigo Pessoal", "amigo@gmail.com") is False
    # Case insensitivity and boundary check
    assert is_display_name_spoofing("TI Suporte", "attacker@outlook.com") is True
    assert is_display_name_spoofing("participante", "attacker@gmail.com") is False
    # Corporate domain is not free webmail, so not BEC spoofing
    assert is_display_name_spoofing("Diretoria Financeira", "roberto@empresa.com.br") is False
    # Empty inputs
    assert is_display_name_spoofing("", "attacker@gmail.com") is False
    assert is_display_name_spoofing("CEO", "") is False


def test_levenshtein_ratio():
    ratio = calculate_levenshtein_ratio("paypal.com", "paypa1.com")
    assert ratio > 0.85
    # Identical strings
    assert calculate_levenshtein_ratio("test.com", "test.com") == 1.0
    # Case insensitive
    assert calculate_levenshtein_ratio("PAYPAL.COM", "paypal.com") == 1.0


def test_extract_domain():
    assert extract_domain("user@example.com") == "example.com"
    assert extract_domain("<user@EXAMPLE.COM>") == "example.com"
    assert extract_domain("no-at-sign") == ""
    assert extract_domain("") == ""


def test_analyze_identity_bec():
    msg = message_from_string(SAMPLE_BEC_HEADER, policy=default)
    identity = analyze_identity(msg)
    assert identity.display_name_spoofing is True
    assert identity.from_domain == "gmail.com"
    assert identity.from_address == "roberto.silva.ceo2026@gmail.com"
    assert "Diretoria Financeira" in identity.from_display_name
    assert identity.return_path == "roberto.silva.ceo2026@gmail.com"
    assert identity.return_path_domain == "gmail.com"
    assert identity.reply_to == "financeiro-urgente@gmail.com"
    assert identity.reply_to_domain == "gmail.com"
    assert identity.envelope_mismatch is False
    assert identity.reply_to_mismatch is False
    assert identity.typosquatting_detected is False


def test_analyze_identity_phishing_mismatches():
    msg = message_from_string(SAMPLE_PHISHING_HEADER, policy=default)
    identity = analyze_identity(msg)
    assert identity.from_address == "seguranca@bradesc0-atualizacao.com"
    assert identity.from_domain == "bradesc0-atualizacao.com"
    assert identity.from_display_name == "Banco Bradesco"
    assert identity.return_path == "bounce@malicious-spammer.ru"
    assert identity.return_path_domain == "malicious-spammer.ru"
    assert identity.reply_to == "coletor@hacker-server.cc"
    assert identity.reply_to_domain == "hacker-server.cc"
    assert identity.envelope_mismatch is True
    assert identity.reply_to_mismatch is True
    # Not typosquatting because distance is low between bradesc0-atualizacao.com and hacker-server.cc
    assert identity.typosquatting_detected is False
    # Not display name spoofing because bradesc0-atualizacao.com is not in free domains
    assert identity.display_name_spoofing is False


def test_analyze_identity_typosquatting():
    raw = (
        "From: \"PayPal Support\" <service@paypal.com>\n"
        "Reply-To: <service@paypa1.com>\n"
        "Return-Path: <service@paypal.com>\n"
        "Subject: Account Alert\n\n"
    )
    msg = message_from_string(raw, policy=default)
    identity = analyze_identity(msg)
    assert identity.reply_to_mismatch is True
    assert identity.typosquatting_detected is True
    assert identity.envelope_mismatch is False


def test_analyze_identity_legitimate():
    msg = message_from_string(SAMPLE_LEGITIMATE_HEADER, policy=default)
    identity = analyze_identity(msg)
    assert identity.from_address == "sender@legitcorp.com"
    assert identity.from_domain == "legitcorp.com"
    assert identity.from_display_name == "Equipe Suporte"
    assert identity.return_path == "sender@legitcorp.com"
    assert identity.return_path_domain == "legitcorp.com"
    assert identity.reply_to is None
    assert identity.reply_to_domain is None
    assert identity.sender is None
    assert identity.envelope_mismatch is False
    assert identity.reply_to_mismatch is False
    assert identity.typosquatting_detected is False
    assert identity.display_name_spoofing is False


def test_analyze_identity_with_sender():
    raw = (
        "From: user@company.com\n"
        "Sender: marketing-robot@mailservice.com\n"
        "Return-Path: <bounce@mailservice.com>\n"
        "Subject: Newsletter\n\n"
    )
    msg = message_from_string(raw, policy=default)
    identity = analyze_identity(msg)
    assert identity.from_address == "user@company.com"
    assert identity.sender == "marketing-robot@mailservice.com"
    assert identity.envelope_mismatch is True


def test_analyze_identity_empty_headers():
    msg = message_from_string("", policy=default)
    identity = analyze_identity(msg)
    assert identity.from_address == ""
    assert identity.from_domain == ""
    assert identity.from_display_name == ""
    assert identity.return_path is None
    assert identity.return_path_domain is None
    assert identity.reply_to is None
    assert identity.reply_to_domain is None
    assert identity.sender is None
    assert identity.envelope_mismatch is False
    assert identity.reply_to_mismatch is False
    assert identity.typosquatting_detected is False
    assert identity.display_name_spoofing is False


def test_analyze_identity_empty_return_path_bracket():
    raw = (
        "From: bounce-test@domain.com\n"
        "Return-Path: <>\n\n"
    )
    msg = message_from_string(raw, policy=default)
    identity = analyze_identity(msg)
    assert identity.return_path is None
    assert identity.return_path_domain is None
    assert identity.envelope_mismatch is False
