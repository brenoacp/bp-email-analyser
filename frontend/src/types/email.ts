export type RiskLevel = "SAFE" | "INFO" | "HIGH" | "CRITICAL";

export interface Finding {
  category: string;
  title: string;
  description: string;
  points: number;
  severity: RiskLevel;
}

export interface HopInfo {
  order: number;
  from_host: string | null;
  by_host: string | null;
  ip: string | null;
  is_private: boolean;
  timestamp: string | null;
  delay_seconds: number;
  fcrdns_passed: boolean | null;
  fcrdns_hostname: string | null;
  country: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  asn: string | null;
  org: string | null;
}

export interface AuthStatus {
  spf_verdict: string;
  spf_record: string | null;
  dkim_verdict: string;
  dkim_domain: string | null;
  dkim_selector: string | null;
  dmarc_verdict: string;
  dmarc_policy: string | null;
  dmarc_record: string | null;
  arc_verdict: string;
}

export interface IdentityAnalysis {
  from_address: string;
  from_domain: string;
  from_display_name: string;
  return_path: string | null;
  return_path_domain: string | null;
  reply_to: string | null;
  reply_to_domain: string | null;
  sender: string | null;
  envelope_mismatch: boolean;
  reply_to_mismatch: boolean;
  typosquatting_detected: boolean;
  display_name_spoofing: boolean;
}

export interface DomainInfo {
  domain: string;
  registered_at: string | null;
  age_days: number | null;
  registrar: string | null;
  country: string | null;
  has_mx: boolean;
  mx_records: string[];
}

export interface OriginIpInfo {
  ip: string | null;
  is_private: boolean;
  country: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  asn: string | null;
  org: string | null;
  rbl_listed: boolean;
  rbl_listings: string[];
}

export interface ClientMetadata {
  message_id: string | null;
  message_id_domain: string | null;
  message_id_valid: boolean;
  x_mailer: string | null;
  user_agent: string | null;
  suspicious_client: boolean;
  date_header: string | null;
  received_date: string | null;
  time_drift_seconds: number;
  time_drift_suspicious: boolean;
  dangerous_attachments: string[];
}

export interface SegVerdicts {
  m365_scl: number | null;
  m365_bcl: number | null;
  m365_cat: string | null;
  m365_sfv: string | null;
  exchange_auth_as: string | null;
  google_smtp_source: string | null;
  google_message_state: string | null;
  sandbox_detected: boolean;
  sandbox_names: string[];
}

export interface AnalysisSummary {
  score: number;
  risk_level: RiskLevel;
  verdict_text: string;
  recommendation: string;
  elapsed_ms: number;
  total_hops: number;
}

export interface EmailAnalysisResponse {
  summary: AnalysisSummary;
  findings: Finding[];
  hops: HopInfo[];
  authentication: AuthStatus;
  identity: IdentityAnalysis;
  domain_info: DomainInfo;
  origin_ip: OriginIpInfo;
  client_metadata: ClientMetadata;
  seg_verdicts: SegVerdicts;
  raw_header_hash: string;
}

export interface AnalysisOptions {
  live_dns?: boolean;
  rdap_lookup?: boolean;
  rbl_check?: boolean;
}

export interface EmailAnalysisRequest {
  raw_header: string;
  options?: AnalysisOptions;
}

export type SampleId = "legitimate" | "phishing" | "bec" | "botnet";
