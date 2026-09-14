import re
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
from typing import List, Optional

from app.core.schemas import ClientMetadata

SUSPICIOUS_CLIENT_PATTERNS = [
    r"phpmailer",
    r"python",
    r"curl",
    r"libwww",
    r"lwp",
    r"powershell",
    r"massmail",
    r"blaster",
]

DANGEROUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".vbs",
    ".iso",
    ".bat",
    ".xlsm",
    ".hta",
    ".one",
    ".ps1",
    ".jar",
    ".cmd",
    ".lnk",
}


def _parse_datetime(date_str: str) -> Optional[datetime]:
    if not date_str or not isinstance(date_str, str):
        return None
    try:
        return parsedate_to_datetime(date_str)
    except Exception:
        pass
    try:
        return datetime.fromisoformat(date_str)
    except Exception:
        pass
    return None


def analyze_client_metadata(
    msg: EmailMessage,
    first_hop_date: Optional[str] = None,
    first_hop_iso: Optional[str] = None,
) -> ClientMetadata:
    message_id = str(msg.get("Message-ID", "")).strip()
    msg_id_domain = None
    msg_id_valid = False

    if message_id:
        match = re.search(r"@([^>]+)>?", message_id)
        if match:
            msg_id_domain = match.group(1).strip()
            msg_id_valid = True
        else:
            msg_id_valid = False

    x_mailer_val = str(msg.get("X-Mailer", "")).strip() if msg.get("X-Mailer") else ""
    user_agent_val = (
        str(msg.get("User-Agent", "")).strip() if msg.get("User-Agent") else ""
    )
    x_mailer = x_mailer_val or user_agent_val or None
    user_agent = user_agent_val or None

    suspicious_client = False
    combined_client = f"{x_mailer_val} {user_agent_val}".strip()
    if combined_client:
        for pat in SUSPICIOUS_CLIENT_PATTERNS:
            if re.search(pat, combined_client, re.IGNORECASE):
                suspicious_client = True
                break

    # Check Date vs Received drift
    date_header = str(msg.get("Date", "")).strip() if msg.get("Date") else ""
    drift_sec = 0
    drift_suspicious = False
    effective_hop_date = first_hop_date or first_hop_iso

    if date_header and effective_hop_date:
        try:
            client_dt = _parse_datetime(date_header)
            hop_dt = _parse_datetime(effective_hop_date)
            if client_dt and hop_dt:
                # Align timezones if one is naive and the other is aware
                if client_dt.tzinfo is not None and hop_dt.tzinfo is None:
                    hop_dt = hop_dt.replace(tzinfo=timezone.utc)
                elif client_dt.tzinfo is None and hop_dt.tzinfo is not None:
                    client_dt = client_dt.replace(tzinfo=timezone.utc)
                diff = abs(int((hop_dt - client_dt).total_seconds()))
                drift_sec = diff
                # Drift > 2 hours (7200s)
                if diff > 7200:
                    drift_suspicious = True
        except Exception:
            pass

    # Inspect attachments mentioned in MIME
    dangerous: List[str] = []
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            fn_lower = filename.lower()
            for ext in DANGEROUS_EXTENSIONS:
                if fn_lower.endswith(ext):
                    dangerous.append(filename)
                    break
        content_type = str(part.get("Content-Type", ""))
        for ext in DANGEROUS_EXTENSIONS:
            if ext in content_type.lower():
                dangerous.append(f"MIME Content-Type contains {ext}")
                break

    return ClientMetadata(
        message_id=message_id or None,
        message_id_domain=msg_id_domain,
        message_id_valid=msg_id_valid,
        x_mailer=x_mailer,
        user_agent=user_agent,
        suspicious_client=suspicious_client,
        date_header=date_header or None,
        received_date=effective_hop_date,
        time_drift_seconds=drift_sec,
        time_drift_suspicious=drift_suspicious,
        dangerous_attachments=sorted(list(set(dangerous))),
    )
