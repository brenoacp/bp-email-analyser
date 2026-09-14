from email import message_from_string
from email.message import EmailMessage
from email.policy import default

from app.analyzers.client_analyzer import analyze_client_metadata
from app.analyzers.seg_analyzer import analyze_seg_verdicts
from tests.fixtures.sample_emails import (
    SAMPLE_BOTNET_HEADER,
    SAMPLE_LEGITIMATE_HEADER,
    SAMPLE_PHISHING_HEADER,
)


def test_client_analyzer_phishing():
    msg = message_from_string(SAMPLE_PHISHING_HEADER, policy=default)
    client = analyze_client_metadata(msg)
    assert client.x_mailer == "PHPMailer 5.2.1"
    assert client.suspicious_client is True
    assert "comprovante.exe" in client.dangerous_attachments


def test_seg_analyzer_m365():
    sample_m365 = """From: a@b.com
X-Forefront-Antispam-Report: CIP:1.2.3.4;CTRY:US;SCL:6;BCL:0;CAT:PHSH;SFV:SPM;
X-MS-Exchange-Organization-AuthAs: Anonymous
"""
    msg = message_from_string(sample_m365, policy=default)
    seg = analyze_seg_verdicts(msg)
    assert seg.m365_scl == 6
    assert seg.m365_bcl == 0
    assert seg.m365_cat == "PHSH"
    assert seg.m365_sfv == "SPM"
    assert seg.exchange_auth_as == "Anonymous"


def test_client_analyzer_legitimate():
    msg = message_from_string(SAMPLE_LEGITIMATE_HEADER, policy=default)
    client = analyze_client_metadata(
        msg, first_hop_date="Mon, 14 Sep 2026 14:20:05 -0300"
    )
    assert client.message_id == "<CABe_3k@mail.legitcorp.com>"
    assert client.message_id_domain == "mail.legitcorp.com"
    assert client.message_id_valid is True
    assert client.suspicious_client is False
    assert client.time_drift_seconds == 15
    assert client.time_drift_suspicious is False
    assert client.dangerous_attachments == []


def test_client_analyzer_time_drift_suspicious():
    msg = message_from_string(SAMPLE_PHISHING_HEADER, policy=default)
    # Date in phishing is Sun, 13 Sep 2026 10:00:00 -0300, hop is Mon, 14 Sep 2026 14:20:00 -0300 (ISO)
    client = analyze_client_metadata(msg, first_hop_iso="2026-09-14T14:20:00-03:00")
    assert client.time_drift_seconds > 7200
    assert client.time_drift_suspicious is True
    assert client.received_date == "2026-09-14T14:20:00-03:00"


def test_client_analyzer_botnet_no_at_in_message_id():
    msg = message_from_string(SAMPLE_BOTNET_HEADER, policy=default)
    client = analyze_client_metadata(msg)
    assert client.message_id == "<random-botnet-id>"
    assert client.message_id_domain is None
    assert client.message_id_valid is False


def test_client_analyzer_user_agent_suspicious():
    raw = """From: attacker@evil.com
User-Agent: python-requests/2.28.1
Date: Mon, 14 Sep 2026 10:00:00 +0000
Message-ID: <test@evil.com>
"""
    msg = message_from_string(raw, policy=default)
    client = analyze_client_metadata(msg)
    assert client.user_agent == "python-requests/2.28.1"
    assert client.suspicious_client is True


def test_client_analyzer_dangerous_extensions_mime():
    raw = """From: attacker@evil.com
Subject: Test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="sep"

--sep
Content-Type: text/plain

Hello

--sep
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.xlsm"

dummy
--sep
Content-Type: application/x-powershell; name="script.ps1"
Content-Disposition: attachment; filename="script.ps1"

dummy
--sep--
"""
    msg = message_from_string(raw, policy=default)
    client = analyze_client_metadata(msg)
    assert "invoice.xlsm" in client.dangerous_attachments
    assert "script.ps1" in client.dangerous_attachments


def test_client_analyzer_empty_message():
    msg = EmailMessage()
    client = analyze_client_metadata(msg)
    assert client.message_id is None
    assert client.message_id_domain is None
    assert client.message_id_valid is False
    assert client.x_mailer is None
    assert client.suspicious_client is False
    assert client.dangerous_attachments == []
    assert client.time_drift_seconds == 0
    assert client.time_drift_suspicious is False


def test_seg_analyzer_m365_negative_scl():
    sample = """From: partner@trusted.com
X-Forefront-Antispam-Report: CIP:10.0.0.1;CTRY:BR;SCL:-1;BCL:0;CAT:NONE;SFV:SKN;
X-MS-Exchange-Organization-AuthAs: Internal
"""
    msg = message_from_string(sample, policy=default)
    seg = analyze_seg_verdicts(msg)
    assert seg.m365_scl == -1
    assert seg.m365_cat == "NONE"
    assert seg.m365_sfv == "SKN"
    assert seg.exchange_auth_as == "Internal"


def test_seg_analyzer_google_workspace():
    sample = """From: sender@gmail.com
X-Google-Smtp-Source: AGHT+IF9q0Z1m...
X-Gm-Message-State: AOJu0YwX9...
"""
    msg = message_from_string(sample, policy=default)
    seg = analyze_seg_verdicts(msg)
    assert seg.google_smtp_source == "AGHT+IF9q0Z1m..."
    assert seg.google_message_state == "AOJu0YwX9..."
    assert seg.sandbox_detected is False


def test_seg_analyzer_sandboxes():
    sample = """From: alert@service.com
X-Proofpoint-Virus-Version: vendor=fsecure
X-Mimecast-Spam-Score: 0
Subject: Link test
Content-Type: text/plain

Please check https://nam01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fgoogle.com
"""
    msg = message_from_string(sample, policy=default)
    seg = analyze_seg_verdicts(msg)
    assert seg.sandbox_detected is True
    assert "Proofpoint TAP" in seg.sandbox_names
    assert "Microsoft Defender Safe Links" in seg.sandbox_names
    assert "Mimecast Targeted Threat Protection" in seg.sandbox_names


def test_seg_analyzer_empty_email():
    msg = EmailMessage()
    seg = analyze_seg_verdicts(msg)
    assert seg.m365_scl is None
    assert seg.m365_bcl is None
    assert seg.m365_cat is None
    assert seg.m365_sfv is None
    assert seg.exchange_auth_as is None
    assert seg.google_smtp_source is None
    assert seg.google_message_state is None
    assert seg.sandbox_detected is False
    assert seg.sandbox_names == []
