from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    SAFE = "SAFE"           # 0 - 25
    INFO = "INFO"           # 26 - 50
    HIGH = "HIGH"           # 51 - 75
    CRITICAL = "CRITICAL"   # 76 - 100


class AnalysisOptions(BaseModel):
    live_dns: bool = True
    rdap_lookup: bool = True
    rbl_check: bool = True


class EmailAnalysisRequest(BaseModel):
    raw_header: str
    options: AnalysisOptions = Field(default_factory=AnalysisOptions)


class Finding(BaseModel):
    category: str
    title: str
    description: str
    points: int
    severity: RiskLevel


class HopInfo(BaseModel):
    order: int
    by_host: Optional[str] = None
    from_host: Optional[str] = None
    ip: Optional[str] = None
    is_private: bool = False
    timestamp: Optional[str] = None
    delay_seconds: int = 0
    fcrdns_passed: Optional[bool] = None
    fcrdns_hostname: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    org: Optional[str] = None


class AuthStatus(BaseModel):
    spf_verdict: str = "none"
    spf_record: Optional[str] = None
    dkim_verdict: str = "none"
    dkim_domain: Optional[str] = None
    dkim_selector: Optional[str] = None
    dmarc_verdict: str = "none"
    dmarc_policy: Optional[str] = None
    dmarc_record: Optional[str] = None
    arc_verdict: str = "none"


class IdentityAnalysis(BaseModel):
    from_address: str
    from_domain: str
    from_display_name: str
    return_path: Optional[str] = None
    return_path_domain: Optional[str] = None
    reply_to: Optional[str] = None
    reply_to_domain: Optional[str] = None
    sender: Optional[str] = None
    envelope_mismatch: bool = False
    reply_to_mismatch: bool = False
    typosquatting_detected: bool = False
    display_name_spoofing: bool = False


class DomainInfo(BaseModel):
    domain: str
    registered_at: Optional[str] = None
    age_days: Optional[int] = None
    registrar: Optional[str] = None
    country: Optional[str] = None
    has_mx: bool = True
    mx_records: List[str] = Field(default_factory=list)


class OriginIpInfo(BaseModel):
    ip: Optional[str] = None
    is_private: bool = False
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    rbl_listed: bool = False
    rbl_listings: List[str] = Field(default_factory=list)


class ClientMetadata(BaseModel):
    message_id: Optional[str] = None
    message_id_domain: Optional[str] = None
    message_id_valid: bool = True
    x_mailer: Optional[str] = None
    user_agent: Optional[str] = None
    suspicious_client: bool = False
    date_header: Optional[str] = None
    received_date: Optional[str] = None
    time_drift_seconds: int = 0
    time_drift_suspicious: bool = False
    dangerous_attachments: List[str] = Field(default_factory=list)


class SegVerdicts(BaseModel):
    m365_scl: Optional[int] = None
    m365_bcl: Optional[int] = None
    m365_cat: Optional[str] = None
    m365_sfv: Optional[str] = None
    exchange_auth_as: Optional[str] = None
    google_smtp_source: Optional[str] = None
    google_message_state: Optional[str] = None
    sandbox_detected: bool = False
    sandbox_names: List[str] = Field(default_factory=list)


class AnalysisSummary(BaseModel):
    score: int
    risk_level: RiskLevel
    verdict_text: str
    recommendation: str
    elapsed_ms: float
    total_hops: int


class EmailAnalysisResponse(BaseModel):
    summary: AnalysisSummary
    findings: List[Finding]
    hops: List[HopInfo]
    authentication: AuthStatus
    identity: IdentityAnalysis
    domain_info: DomainInfo
    origin_ip: OriginIpInfo
    client_metadata: ClientMetadata
    seg_verdicts: SegVerdicts
    raw_header_hash: str
