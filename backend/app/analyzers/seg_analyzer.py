import re
from email.message import EmailMessage
from typing import List

from app.core.schemas import SegVerdicts


def analyze_seg_verdicts(msg: EmailMessage) -> SegVerdicts:
    verdicts = SegVerdicts()

    # Microsoft 365 / Exchange Antispam
    forefront_headers = msg.get_all("X-Forefront-Antispam-Report", [])
    x_ms_antispam_headers = msg.get_all("X-Microsoft-Antispam", [])
    combined_antispam = " ".join(
        str(h) for h in (forefront_headers + x_ms_antispam_headers)
    )

    if combined_antispam:
        scl_m = re.search(r"\bSCL:(-?\d+)", combined_antispam)
        if scl_m:
            verdicts.m365_scl = int(scl_m.group(1))

        bcl_m = re.search(r"\bBCL:(\d+)", combined_antispam)
        if bcl_m:
            verdicts.m365_bcl = int(bcl_m.group(1))

        cat_m = re.search(r"\bCAT:(\w+)", combined_antispam)
        if cat_m:
            verdicts.m365_cat = cat_m.group(1).upper()

        sfv_m = re.search(r"\bSFV:(\w+)", combined_antispam)
        if sfv_m:
            verdicts.m365_sfv = sfv_m.group(1).upper()

    # Exchange AuthAs
    exchange_auth = msg.get("X-MS-Exchange-Organization-AuthAs", "")
    if exchange_auth:
        verdicts.exchange_auth_as = str(exchange_auth).strip()

    # Google Workspace
    google_smtp = msg.get("X-Google-Smtp-Source", None)
    if google_smtp:
        verdicts.google_smtp_source = str(google_smtp).strip()
    google_state = msg.get("X-Gm-Message-State", None)
    if google_state:
        verdicts.google_message_state = str(google_state).strip()

    # Sandbox / URL Rewriting
    sandboxes: List[str] = []

    # Proofpoint TAP
    if (
        msg.get("X-Proofpoint-Virus-Version")
        or msg.get("X-Proofpoint-Spam-Details")
        or msg.get("X-Proofpoint-GUID")
    ):
        sandboxes.append("Proofpoint TAP")

    # Microsoft Defender Safe Links
    msg_str = ""
    try:
        msg_str = str(msg.as_string())
    except Exception:
        pass
    msg_str_lower = msg_str.lower()

    if (
        "safelinks" in str(msg.get_all("X-MS-Exchange-Organization-SCL", [])).lower()
        or "safelinks" in msg_str_lower
        or msg.get("X-MS-Exchange-Organization-SafeLinksProcessing")
    ):
        sandboxes.append("Microsoft Defender Safe Links")

    # Mimecast Targeted Threat Protection
    if (
        msg.get("X-Mimecast-Spam-Score")
        or msg.get("X-Mimecast-Impersonation-Protect")
    ):
        sandboxes.append("Mimecast Targeted Threat Protection")

    verdicts.sandbox_detected = len(sandboxes) > 0
    verdicts.sandbox_names = sorted(list(set(sandboxes)))

    return verdicts
