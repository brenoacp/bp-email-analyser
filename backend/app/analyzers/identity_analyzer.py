import re
from difflib import SequenceMatcher
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.utils import parseaddr
from typing import Optional

from app.core.schemas import IdentityAnalysis

FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "bol.com.br",
    "uol.com.br",
    "terra.com.br",
    "icloud.com",
    "proton.me",
    "protonmail.com",
}

SUSPICIOUS_NAME_KEYWORDS = [
    "diretoria",
    "financeiro",
    "ceo",
    "cfo",
    "diretor",
    "presidente",
    "rh",
    "suporte",
    "ti",
    "security",
    "banco",
    "pagamento",
    "urgente",
    "microsoft",
    "google",
    "apple",
    "admin",
    "helpdesk",
]


def calculate_levenshtein_ratio(s1: str, s2: str) -> float:
    return SequenceMatcher(None, s1.lower(), s2.lower()).ratio()


def extract_domain(email_addr: str) -> str:
    if email_addr and "@" in email_addr:
        return email_addr.split("@")[-1].strip().lower().rstrip(">")
    return ""


def _decode_header_str(val: str) -> str:
    if not val:
        return ""
    try:
        return str(make_header(decode_header(val)))
    except Exception:
        return val


def is_display_name_spoofing(display_name: str, email_address: str) -> bool:
    if not display_name or not email_address:
        return False
    name_lower = display_name.lower()
    domain = extract_domain(email_address)

    # If the domain is a free/generic webmail but display name contains corporate or executive authority words
    if domain in FREE_EMAIL_DOMAINS:
        for kw in SUSPICIOUS_NAME_KEYWORDS:
            if re.search(rf"\b{re.escape(kw)}\b", name_lower):
                return True
    return False


def analyze_identity(msg: EmailMessage) -> IdentityAnalysis:
    from_header = msg.get("From", "")
    from_name, from_email = parseaddr(from_header)
    from_name = _decode_header_str(from_name)
    from_domain = extract_domain(from_email)

    return_path_header = msg.get("Return-Path", "")
    _, return_path_email = parseaddr(return_path_header)
    return_path_domain: Optional[str] = (
        extract_domain(return_path_email) or None if return_path_email else None
    )

    reply_to_header = msg.get("Reply-To", "")
    _, reply_to_email = parseaddr(reply_to_header)
    reply_to_domain: Optional[str] = (
        extract_domain(reply_to_email) or None if reply_to_email else None
    )

    sender_header = msg.get("Sender", "")
    _, sender_email = parseaddr(sender_header)

    envelope_mismatch = False
    if return_path_domain and from_domain and (return_path_domain != from_domain):
        envelope_mismatch = True

    reply_to_mismatch = False
    typosquatting = False
    if reply_to_domain and from_domain and (reply_to_domain != from_domain):
        reply_to_mismatch = True
        # Check similarity between From domain and Reply-To domain
        ratio = calculate_levenshtein_ratio(from_domain, reply_to_domain)
        if 0.75 <= ratio < 1.0:
            typosquatting = True

    bec_flag = is_display_name_spoofing(from_name, from_email)

    return IdentityAnalysis(
        from_address=from_email,
        from_domain=from_domain,
        from_display_name=from_name,
        return_path=return_path_email or None,
        return_path_domain=return_path_domain,
        reply_to=reply_to_email or None,
        reply_to_domain=reply_to_domain,
        sender=sender_email or None,
        envelope_mismatch=envelope_mismatch,
        reply_to_mismatch=reply_to_mismatch,
        typosquatting_detected=typosquatting,
        display_name_spoofing=bec_flag,
    )
