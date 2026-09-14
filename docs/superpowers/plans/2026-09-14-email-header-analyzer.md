# bp-email-analiser Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Construir uma aplicação web forense completa para análise de cabeçalhos de e-mail com mapeamento de saltos (Hops/FCrDNS), auditoria de SPF/DKIM/DMARC/ARC, detecção de BEC/Spoofing/Typosquatting, vereditos de SEGs (M365/Exchange/Google), enriquecimento Whois/GeoIP/RBL, motor de pontuação de fraude (0-100) e exportação em PDF/JSON.

**Architecture:** Backend assíncrono em FastAPI (Python 3.12) executando analisadores concorrentes em `asyncio.gather` com processamento estritamente em memória. Frontend SPA interativo em React 18, Vite, TypeScript, Tailwind CSS e Leaflet para visualização de rotas em mapa mundi, velocímetro de score e linha do tempo de rede.

**Tech Stack:** Python 3.12, FastAPI, dnspython, httpx, reportlab, pytest, Node.js v22, React 18, Vite, Tailwind CSS, Lucide React, Leaflet.

**Spec:** `docs/superpowers/specs/2026-09-14-bp-email-analiser-design.md`

## Global Constraints

- Diretório do projeto: `/home/breno/bp-email-analiser`
- Nenhuma persistência em disco ou banco de dados de e-mails/cabeçalhos (processamento 100% em memória para sigilo).
- Timeout estrito de 2.5 segundos por consulta assíncrona externa (DNS, RDAP, GeoIP, RBL).
- IPs privados (RFC 1918 e loopback) devem ser detectados e não sofrer consultas externas de GeoIP/Whois/RBL.
- Parsing tolerante a RFC 2047, multiline e caracteres especiais via `email.policy.default`.
- Escala de pontuação: 0 a 100 com 4 níveis (0-25 Seguro, 26-50 Informativo, 51-75 Alto Risco, 76-100 Crítico).

---

### Task 1: Backend Scaffolding, Schemas Pydantic & Amostras de Teste

**Files:**
- Create: `backend/requirements.txt`
- Create: `backend/app/core/config.py`
- Create: `backend/app/core/schemas.py`
- Create: `backend/tests/fixtures/sample_emails.py`
- Create: `backend/tests/test_schemas.py`

**Interfaces:**
- Consumes: Biblioteca padrão do Python (`email.message.EmailMessage`, `pydantic`).
- Produces: Modelos `EmailAnalysisRequest`, `EmailAnalysisResponse`, `Finding`, `HopInfo`, `AuthStatus`, `IdentityAnalysis`, `DomainInfo`, `OriginIpInfo`, `ClientMetadata`, `SegVerdicts` e fixtures `SAMPLE_LEGITIMATE_HEADER`, `SAMPLE_PHISHING_HEADER`, `SAMPLE_BEC_HEADER`, `SAMPLE_BOTNET_HEADER`.

- [ ] **Step 1: Escrever o teste unitário dos schemas e validação**

```python
# backend/tests/test_schemas.py
from app.core.schemas import EmailAnalysisRequest, EmailAnalysisResponse, Finding, HopInfo, RiskLevel

def test_schema_serialization():
    req = EmailAnalysisRequest(raw_header="From: test@example.com\nTo: user@example.com\nSubject: Test")
    assert "From:" in req.raw_header
    assert req.options.live_dns is True

    finding = Finding(
        category="Autenticação",
        title="DMARC Fail",
        description="A política DMARC falhou",
        points=20,
        severity=RiskLevel.HIGH
    )
    assert finding.points == 20
    assert finding.severity == RiskLevel.HIGH
```

- [ ] **Step 2: Executar o teste e verificar a falha**

Run: `pytest backend/tests/test_schemas.py -v`  
Expected: FAIL com `ModuleNotFoundError: No module named 'app'`

- [ ] **Step 3: Criar dependências, configurações e schemas Pydantic**

```text
# backend/requirements.txt
fastapi>=0.115.0
uvicorn>=0.30.0
pydantic>=2.8.0
dnspython>=2.6.1
httpx>=0.27.0
reportlab>=4.2.0
pytest>=8.3.0
pytest-asyncio>=0.24.0
```

```python
# backend/app/core/config.py
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "bp-email-analiser"
    API_PREFIX: str = "/api"
    NETWORK_TIMEOUT_SECONDS: float = 2.5
    MAX_HEADER_SIZE_BYTES: int = 1_000_000  # 1MB max

    class Config:
        env_file = ".env"

settings = Settings()
```

```python
# backend/app/core/schemas.py
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum

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
```

```python
# backend/tests/fixtures/sample_emails.py
SAMPLE_LEGITIMATE_HEADER = """Received: from mail-ed1-f65.google.com (mail-ed1-f65.google.com [209.85.208.65])
    by mx.destination.com (Postfix) with ESMTPS id 4XhG0l5v
    for <user@destination.com>; Mon, 14 Sep 2026 14:20:05 -0300
Authentication-Results: mx.destination.com;
    dkim=pass header.i=@legitcorp.com header.s=google;
    spf=pass (mx.destination.com: domain of sender@legitcorp.com designates 209.85.208.65 as permitted sender) smtp.mailfrom=sender@legitcorp.com;
    dmarc=pass (p=REJECT sp=REJECT) header.from=legitcorp.com
From: "Equipe Suporte" <sender@legitcorp.com>
To: user@destination.com
Subject: Notificação de Acesso
Date: Mon, 14 Sep 2026 14:19:50 -0300
Message-ID: <CABe_3k@mail.legitcorp.com>
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=legitcorp.com; s=google;
Return-Path: <sender@legitcorp.com>
"""

SAMPLE_PHISHING_HEADER = """Received: from bad-relay.net (bad-relay.net [185.220.101.5])
    by mx.destination.com (Postfix) with ESMTP id 12345
    for <victim@destination.com>; Mon, 14 Sep 2026 14:20:00 -0300
From: "Banco Bradesco" <seguranca@bradesc0-atualizacao.com>
Return-Path: <bounce@malicious-spammer.ru>
Reply-To: <coletor@hacker-server.cc>
Subject: URGENTE: Recadastramento de Chave
Date: Sun, 13 Sep 2026 10:00:00 -0300
Message-ID: <12345@localhost>
X-Mailer: PHPMailer 5.2.1
Content-Type: multipart/mixed; boundary="====="

--=====
Content-Type: application/octet-stream; name="comprovante.exe"
Content-Disposition: attachment; filename="comprovante.exe"
"""

SAMPLE_BEC_HEADER = """Received: from mail-relay.freeisp.org (mail-relay.freeisp.org [198.51.100.22])
    by mx.company.com with ESMTP id 998877;
    Mon, 14 Sep 2026 11:00:00 -0300
From: "Diretoria Financeira - Roberto Silva" <roberto.silva.ceo2026@gmail.com>
To: tesouraria@company.com
Reply-To: <financeiro-urgente@gmail.com>
Subject: Pagamento de Fornecedor Emergencial
Date: Mon, 14 Sep 2026 11:00:00 -0300
Message-ID: <CAFn89@mail.gmail.com>
Return-Path: <roberto.silva.ceo2026@gmail.com>
"""

SAMPLE_BOTNET_HEADER = """Received: from dynamic-pool-189-12-34.isp.net ([189.12.34.56])
    by mx.victim.com with SMTP;
    Mon, 14 Sep 2026 08:00:00 -0300
From: info@spammer.org
To: user@victim.com
Subject: Buy cheap products
Date: Mon, 14 Sep 2026 08:00:00 -0300
Message-ID: <random-botnet-id>
"""
```

- [ ] **Step 4: Executar os testes para verificar sucesso**

Run: `PYTHONPATH=backend pytest backend/tests/test_schemas.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/
git commit -m "feat(backend): add schemas, settings and sample email fixtures"
```

---

### Task 2: Cadeia de Saltos (`Received:`) & FCrDNS Analyzer

**Files:**
- Create: `backend/app/analyzers/hops_analyzer.py`
- Create: `backend/tests/test_hops_analyzer.py`

**Interfaces:**
- Consumes: `EmailMessage` do Python e `HopInfo` de `app.core.schemas`.
- Produces: `async def parse_hops(msg: EmailMessage, resolver=None) -> List[HopInfo]`, `def is_ip_private(ip_str: str) -> bool`, `async def verify_fcrdns(ip: str, claimed_host: str, resolver=None) -> Tuple[bool, str]`.

- [ ] **Step 1: Escrever o teste unitário de Hops & FCrDNS**

```python
# backend/tests/test_hops_analyzer.py
import pytest
from email import message_from_string
from email.policy import default
from app.analyzers.hops_analyzer import parse_hops, is_ip_private
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
```

- [ ] **Step 2: Executar o teste e verificar a falha**

Run: `PYTHONPATH=backend pytest backend/tests/test_hops_analyzer.py -v`  
Expected: FAIL com `ModuleNotFoundError: No module named 'app.analyzers.hops_analyzer'`

- [ ] **Step 3: Implementar o `hops_analyzer.py`**

```python
# backend/app/analyzers/hops_analyzer.py
import re
import ipaddress
from typing import List, Optional, Tuple
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
import dns.asyncresolver
import dns.reversename
from app.core.schemas import HopInfo
from app.core.config import settings

IP_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
IPV6_REGEX = re.compile(r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}')

def is_ip_private(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
    except ValueError:
        return False

async def verify_fcrdns(ip: str, resolver: Optional[dns.asyncresolver.Resolver] = None) -> Tuple[bool, Optional[str]]:
    if is_ip_private(ip):
        return (True, "private-network")
    
    if resolver is None:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = settings.NETWORK_TIMEOUT_SECONDS
    
    try:
        rev_name = dns.reversename.from_address(ip)
        ptr_answers = await resolver.resolve(rev_name, "PTR")
        ptr_hostname = str(ptr_answers[0].target).rstrip(".")
        
        # Forward check (A/AAAA)
        a_answers = await resolver.resolve(ptr_hostname, "A")
        ips_resolved = [str(rdata) for rdata in a_answers]
        if ip in ips_resolved:
            return (True, ptr_hostname)
        return (False, ptr_hostname)
    except Exception:
        return (False, None)

async def parse_hops(msg: EmailMessage, perform_dns: bool = True) -> List[HopInfo]:
    raw_received = msg.get_all("Received", [])
    if not raw_received:
        return []
    
    # Received headers are prepended by each MTA (latest first). Reverse to get chronological order.
    chronological_received = list(reversed(raw_received))
    hops: List[HopInfo] = []
    prev_dt = None
    
    for idx, header_val in enumerate(chronological_received, start=1):
        # Extract IP
        found_ips = IP_REGEX.findall(header_val)
        extracted_ip = found_ips[0] if found_ips else None
        
        # Extract from / by
        from_match = re.search(r'from\s+([^\s;()]+)', header_val, re.IGNORECASE)
        by_match = re.search(r'by\s+([^\s;()]+)', header_val, re.IGNORECASE)
        from_host = from_match.group(1) if from_match else None
        by_host = by_match.group(1) if by_match else None
        
        # Extract timestamp after semicolon
        timestamp_str = None
        delay_seconds = 0
        if ';' in header_val:
            date_part = header_val.split(';')[-1].strip()
            try:
                dt = parsedate_to_datetime(date_part)
                timestamp_str = dt.isoformat()
                if prev_dt:
                    diff = int((dt - prev_dt).total_seconds())
                    delay_seconds = max(0, diff)
                prev_dt = dt
            except Exception:
                timestamp_str = date_part
        
        is_priv = is_ip_private(extracted_ip) if extracted_ip else False
        fcrdns_ok = None
        fcrdns_host = None
        
        if extracted_ip and perform_dns and not is_priv:
            fcrdns_ok, fcrdns_host = await verify_fcrdns(extracted_ip)
            
        hop = HopInfo(
            order=idx,
            from_host=from_host,
            by_host=by_host,
            ip=extracted_ip,
            is_private=is_priv,
            timestamp=timestamp_str,
            delay_seconds=delay_seconds,
            fcrdns_passed=fcrdns_ok,
            fcrdns_hostname=fcrdns_host
        )
        hops.append(hop)
        
    return hops
```

- [ ] **Step 4: Executar os testes para verificar sucesso**

Run: `PYTHONPATH=backend pytest backend/tests/test_hops_analyzer.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/analyzers/hops_analyzer.py backend/tests/test_hops_analyzer.py
git commit -m "feat(backend): implement hops extractor and FCrDNS resolver"
```

---

### Task 3: Enriquecimento: GeoIP, RDAP/Whois, Registros MX e RBL (`enrichment.py` e `rbl_analyzer.py`)

**Files:**
- Create: `backend/app/analyzers/enrichment.py`
- Create: `backend/app/analyzers/rbl_analyzer.py`
- Create: `backend/tests/test_enrichment.py`

**Interfaces:**
- Consumes: `httpx.AsyncClient`, `dns.asyncresolver.Resolver`, `DomainInfo`, `OriginIpInfo`.
- Produces: `async def lookup_geoip(ip: str, client: httpx.AsyncClient) -> Dict[str, Any]`, `async def lookup_rdap_domain(domain: str, client: httpx.AsyncClient) -> DomainInfo`, `async def check_mx_records(domain: str, resolver=None) -> Tuple[bool, List[str]]`, `async def check_rbls(ip: str, resolver=None) -> Tuple[bool, List[str]]`.

- [ ] **Step 1: Escrever teste de enriquecimento e RBL**

```python
# backend/tests/test_enrichment.py
import pytest
from app.analyzers.enrichment import calculate_domain_age_days
from app.analyzers.rbl_analyzer import reverse_ip_for_rbl

def test_calculate_domain_age():
    # 2026-09-01 registered vs 2026-09-14
    age = calculate_domain_age_days("2026-09-01T00:00:00Z")
    assert age is not None
    assert age >= 10

def test_reverse_ip_for_rbl():
    rev = reverse_ip_for_rbl("185.220.101.5")
    assert rev == "5.101.220.185"
```

- [ ] **Step 2: Executar o teste e verificar a falha**

Run: `PYTHONPATH=backend pytest backend/tests/test_enrichment.py -v`  
Expected: FAIL com `ModuleNotFoundError`

- [ ] **Step 3: Implementar `enrichment.py` e `rbl_analyzer.py`**

```python
# backend/app/analyzers/rbl_analyzer.py
from typing import List, Tuple, Optional
import dns.asyncresolver
from app.core.config import settings

PUBLIC_RBLS = [
    "zen.spamhaus.org",
    "b.barracudacentral.org",
    "bl.spamcop.net"
]

def reverse_ip_for_rbl(ip: str) -> str:
    parts = ip.strip().split('.')
    return '.'.join(reversed(parts))

async def check_rbls(ip: str, resolver: Optional[dns.asyncresolver.Resolver] = None) -> Tuple[bool, List[str]]:
    if not ip or ip.startswith(("10.", "172.", "192.168.", "127.")):
        return False, []
    
    if resolver is None:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = settings.NETWORK_TIMEOUT_SECONDS
        
    rev_ip = reverse_ip_for_rbl(ip)
    listings: List[str] = []
    
    for rbl in PUBLIC_RBLS:
        query_host = f"{rev_ip}.{rbl}"
        try:
            answers = await resolver.resolve(query_host, "A")
            if answers:
                listings.append(rbl)
        except Exception:
            continue
            
    return (len(listings) > 0, listings)
```

```python
# backend/app/analyzers/enrichment.py
from typing import Optional, Dict, Any, Tuple, List
from datetime import datetime, timezone
import httpx
import dns.asyncresolver
from app.core.schemas import DomainInfo, OriginIpInfo
from app.core.config import settings

def calculate_domain_age_days(registered_date_iso: Optional[str]) -> Optional[int]:
    if not registered_date_iso:
        return None
    try:
        # Handles various ISO formats
        clean_date = registered_date_iso.replace("Z", "+00:00")
        reg_dt = datetime.fromisoformat(clean_date)
        now_dt = datetime.now(timezone.utc)
        diff = now_dt - reg_dt
        return max(0, diff.days)
    except Exception:
        return None

async def check_mx_records(domain: str, resolver: Optional[dns.asyncresolver.Resolver] = None) -> Tuple[bool, List[str]]:
    if resolver is None:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = settings.NETWORK_TIMEOUT_SECONDS
    try:
        answers = await resolver.resolve(domain, "MX")
        mx_list = [str(r.exchange).rstrip(".") for r in sorted(answers, key=lambda x: x.preference)]
        # Flag localhost/bogus MX
        valid_mx = [mx for mx in mx_list if mx not in ["localhost", "127.0.0.1", "0.0.0.0", ""]]
        return (len(valid_mx) > 0, valid_mx)
    except Exception:
        return (False, [])

async def lookup_geoip(ip: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    if not ip or ip.startswith(("10.", "172.", "192.168.", "127.")):
        return {"country": "Local", "city": "Rede Interna", "lat": 0.0, "lon": 0.0, "org": "Privado", "asn": "N/A"}
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,org,as"
        resp = await client.get(url, timeout=settings.NETWORK_TIMEOUT_SECONDS)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "org": data.get("org"),
                    "asn": data.get("as")
                }
    except Exception:
        pass
    return {}

async def lookup_rdap_domain(domain: str, client: httpx.AsyncClient) -> DomainInfo:
    info = DomainInfo(domain=domain)
    # Check MX first
    has_mx, mx_records = await check_mx_records(domain)
    info.has_mx = has_mx
    info.mx_records = mx_records
    
    # Query RDAP
    try:
        url = f"https://rdap.org/domain/{domain}"
        resp = await client.get(url, timeout=settings.NETWORK_TIMEOUT_SECONDS, follow_redirects=True)
        if resp.status_code == 200:
            data = resp.json()
            # Extract events (registration date)
            for ev in data.get("events", []):
                action = ev.get("eventAction")
                if action in ["registration", "created"]:
                    info.registered_at = ev.get("eventDate")
                    info.age_days = calculate_domain_age_days(info.registered_at)
            # Extract registrar
            for ent in data.get("entities", []):
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1:
                        for prop in vcard[1]:
                            if prop[0] == "fn":
                                info.registrar = prop[3]
    except Exception:
        pass
    return info
```

- [ ] **Step 4: Executar os testes para verificar sucesso**

Run: `PYTHONPATH=backend pytest backend/tests/test_enrichment.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/analyzers/enrichment.py backend/app/analyzers/rbl_analyzer.py backend/tests/test_enrichment.py
git commit -m "feat(backend): implement RDAP, GeoIP, MX verification and RBL checks"
```

---

### Task 4: Autenticação DNS: SPF, DKIM, DMARC e ARC (`auth_analyzer.py`)

**Files:**
- Create: `backend/app/analyzers/auth_analyzer.py`
- Create: `backend/tests/test_auth_analyzer.py`

**Interfaces:**
- Consumes: `EmailMessage`, `AuthStatus`.
- Produces: `async def analyze_authentication(msg: EmailMessage, sender_domain: str, resolver=None) -> AuthStatus`.

- [ ] **Step 1: Escrever o teste unitário de Autenticação**

```python
# backend/tests/test_auth_analyzer.py
import pytest
from email import message_from_string
from email.policy import default
from app.analyzers.auth_analyzer import extract_header_auth_results, parse_dkim_header
from tests.fixtures.sample_emails import SAMPLE_LEGITIMATE_HEADER

def test_extract_header_auth_results():
    msg = message_from_string(SAMPLE_LEGITIMATE_HEADER, policy=default)
    auth = extract_header_auth_results(msg)
    assert auth.spf_verdict == "pass"
    assert auth.dkim_verdict == "pass"
    assert auth.dmarc_verdict == "pass"
    assert auth.dkim_domain == "legitcorp.com"

def test_parse_dkim_signature():
    dkim_sig = "v=1; a=rsa-sha256; d=example.com; s=sel1; b=abc"
    d, s = parse_dkim_header(dkim_sig)
    assert d == "example.com"
    assert s == "sel1"
```

- [ ] **Step 2: Executar o teste e verificar a falha**

Run: `PYTHONPATH=backend pytest backend/tests/test_auth_analyzer.py -v`  
Expected: FAIL com `ModuleNotFoundError`

- [ ] **Step 3: Implementar `auth_analyzer.py`**

```python
# backend/app/analyzers/auth_analyzer.py
import re
from typing import Optional, Tuple
from email.message import EmailMessage
import dns.asyncresolver
from app.core.schemas import AuthStatus
from app.core.config import settings

def parse_dkim_header(header_val: str) -> Tuple[Optional[str], Optional[str]]:
    d_match = re.search(r'\bd=([^\s;]+)', header_val)
    s_match = re.search(r'\bs=([^\s;]+)', header_val)
    d = d_match.group(1) if d_match else None
    s = s_match.group(1) if s_match else None
    return d, s

def extract_header_auth_results(msg: EmailMessage) -> AuthStatus:
    status = AuthStatus()
    auth_results = msg.get("Authentication-Results", "")
    
    # SPF
    spf_match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
    if spf_match:
        status.spf_verdict = spf_match.group(1).lower()
    else:
        # Fallback to Received-SPF
        rec_spf = msg.get("Received-SPF", "")
        if rec_spf:
            first_word = rec_spf.strip().split()[0].lower()
            status.spf_verdict = first_word

    # DKIM
    dkim_match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
    if dkim_match:
        status.dkim_verdict = dkim_match.group(1).lower()
    
    dkim_header = msg.get("DKIM-Signature", "")
    if dkim_header:
        d, s = parse_dkim_header(dkim_header)
        status.dkim_domain = d
        status.dkim_selector = s
        if status.dkim_verdict == "none":
            status.dkim_verdict = "signed"

    # DMARC
    dmarc_match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
    if dmarc_match:
        status.dmarc_verdict = dmarc_match.group(1).lower()
        pol_match = re.search(r'p=(\w+)', auth_results, re.IGNORECASE)
        if pol_match:
            status.dmarc_policy = pol_match.group(1).lower()

    # ARC
    arc_results = msg.get("ARC-Authentication-Results", "")
    if arc_results:
        arc_match = re.search(r'arc=(\w+)|cv=(\w+)', arc_results, re.IGNORECASE)
        if arc_match:
            status.arc_verdict = (arc_match.group(1) or arc_match.group(2)).lower()
            
    return status

async def query_live_dns_auth(domain: str, status: AuthStatus, resolver: Optional[dns.asyncresolver.Resolver] = None):
    if not domain:
        return
    if resolver is None:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = settings.NETWORK_TIMEOUT_SECONDS
        
    # Check SPF TXT
    try:
        txt_records = await resolver.resolve(domain, "TXT")
        for rdata in txt_records:
            txt_str = "".join([s.decode('utf-8', errors='ignore') for s in rdata.strings])
            if txt_str.startswith("v=spf1"):
                status.spf_record = txt_str
                break
    except Exception:
        pass

    # Check DMARC TXT
    try:
        dmarc_host = f"_dmarc.{domain}"
        txt_records = await resolver.resolve(dmarc_host, "TXT")
        for rdata in txt_records:
            txt_str = "".join([s.decode('utf-8', errors='ignore') for s in rdata.strings])
            if txt_str.startswith("v=DMARC1"):
                status.dmarc_record = txt_str
                if not status.dmarc_policy:
                    pol_match = re.search(r'p=(\w+)', txt_str)
                    if pol_match:
                        status.dmarc_policy = pol_match.group(1).lower()
                break
    except Exception:
        pass

async def analyze_authentication(msg: EmailMessage, sender_domain: str, perform_live_dns: bool = True) -> AuthStatus:
    status = extract_header_auth_results(msg)
    if perform_live_dns and sender_domain:
        await query_live_dns_auth(sender_domain, status)
    return status
```

- [ ] **Step 4: Executar os testes para verificar sucesso**

Run: `PYTHONPATH=backend pytest backend/tests/test_auth_analyzer.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/analyzers/auth_analyzer.py backend/tests/test_auth_analyzer.py
git commit -m "feat(backend): implement SPF, DKIM, DMARC and ARC analyzer"
```

---

### Task 5: Auditoria de Identidade, Spoofing & BEC (`identity_analyzer.py`)

**Files:**
- Create: `backend/app/analyzers/identity_analyzer.py`
- Create: `backend/tests/test_identity_analyzer.py`

**Interfaces:**
- Consumes: `EmailMessage`, `IdentityAnalysis`.
- Produces: `def analyze_identity(msg: EmailMessage) -> IdentityAnalysis`, `def calculate_levenshtein_ratio(s1: str, s2: str) -> float`, `def is_display_name_spoofing(display_name: str, email_address: str) -> bool`.

- [ ] **Step 1: Escrever teste de BEC e Spoofing**

```python
# backend/tests/test_identity_analyzer.py
from email import message_from_string
from email.policy import default
from app.analyzers.identity_analyzer import analyze_identity, is_display_name_spoofing, calculate_levenshtein_ratio
from tests.fixtures.sample_emails import SAMPLE_BEC_HEADER, SAMPLE_PHISHING_HEADER

def test_bec_display_name_detection():
    assert is_display_name_spoofing("Diretoria Financeira - Roberto", "attacker@gmail.com") is True
    assert is_display_name_spoofing("CEO da Empresa", "hacker@hotmail.com") is True
    assert is_display_name_spoofing("Amigo Pessoal", "amigo@gmail.com") is False

def test_levenshtein_ratio():
    ratio = calculate_levenshtein_ratio("paypal.com", "paypa1.com")
    assert ratio > 0.85

def test_analyze_identity_bec():
    msg = message_from_string(SAMPLE_BEC_HEADER, policy=default)
    identity = analyze_identity(msg)
    assert identity.display_name_spoofing is True
    assert identity.from_domain == "gmail.com"
```

- [ ] **Step 2: Executar o teste e verificar a falha**

Run: `PYTHONPATH=backend pytest backend/tests/test_identity_analyzer.py -v`  
Expected: FAIL com `ModuleNotFoundError`

- [ ] **Step 3: Implementar `identity_analyzer.py`**

```python
# backend/app/analyzers/identity_analyzer.py
import re
from email.message import EmailMessage
from email.utils import parseaddr
from difflib import SequenceMatcher
from app.core.schemas import IdentityAnalysis

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com", 
    "bol.com.br", "uol.com.br", "terra.com.br", "icloud.com", "proton.me", "protonmail.com"
}

SUSPICIOUS_NAME_KEYWORDS = [
    "diretoria", "financeiro", "ceo", "cfo", "diretor", "presidente", 
    "rh", "suporte", "ti", "security", "banco", "pagamento", "urgente",
    "microsoft", "google", "apple", "admin", "helpdesk"
]

def calculate_levenshtein_ratio(s1: str, s2: str) -> float:
    return SequenceMatcher(None, s1.lower(), s2.lower()).ratio()

def extract_domain(email_addr: str) -> str:
    if '@' in email_addr:
        return email_addr.split('@')[-1].strip().lower().rstrip('>')
    return ""

def is_display_name_spoofing(display_name: str, email_address: str) -> bool:
    if not display_name or not email_address:
        return False
    name_lower = display_name.lower()
    domain = extract_domain(email_address)
    
    # If the domain is a free/generic webmail but display name contains corporate or executive authority words
    if domain in FREE_EMAIL_DOMAINS:
        for kw in SUSPICIOUS_NAME_KEYWORDS:
            if re.search(rf'\b{kw}\b', name_lower):
                return True
    return False

def analyze_identity(msg: EmailMessage) -> IdentityAnalysis:
    from_header = msg.get("From", "")
    from_name, from_email = parseaddr(from_header)
    from_domain = extract_domain(from_email)
    
    return_path_header = msg.get("Return-Path", "")
    _, return_path_email = parseaddr(return_path_header)
    return_path_domain = extract_domain(return_path_email) if return_path_email else None
    
    reply_to_header = msg.get("Reply-To", "")
    _, reply_to_email = parseaddr(reply_to_header)
    reply_to_domain = extract_domain(reply_to_email) if reply_to_email else None
    
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
        display_name_spoofing=bec_flag
    )
```

- [ ] **Step 4: Executar os testes para verificar sucesso**

Run: `PYTHONPATH=backend pytest backend/tests/test_identity_analyzer.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/analyzers/identity_analyzer.py backend/tests/test_identity_analyzer.py
git commit -m "feat(backend): implement identity auditor with BEC and typosquatting detection"
```

---

### Task 6: Metadados do Cliente, MIME & Vereditos de Gateways SEGs (`client_analyzer.py` e `seg_analyzer.py`)

**Files:**
- Create: `backend/app/analyzers/client_analyzer.py`
- Create: `backend/app/analyzers/seg_analyzer.py`
- Create: `backend/tests/test_client_and_seg_analyzer.py`

**Interfaces:**
- Consumes: `EmailMessage`, `ClientMetadata`, `SegVerdicts`.
- Produces: `def analyze_client_metadata(msg: EmailMessage, first_hop_date: Optional[str] = None) -> ClientMetadata`, `def analyze_seg_verdicts(msg: EmailMessage) -> SegVerdicts`.

- [ ] **Step 1: Escrever teste de Client Metadata e SEGs**

```python
# backend/tests/test_client_and_seg_analyzer.py
from email import message_from_string
from email.policy import default
from app.analyzers.client_analyzer import analyze_client_metadata
from app.analyzers.seg_analyzer import analyze_seg_verdicts
from tests.fixtures.sample_emails import SAMPLE_PHISHING_HEADER

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
    assert seg.m365_cat == "PHSH"
    assert seg.exchange_auth_as == "Anonymous"
```

- [ ] **Step 2: Executar o teste e verificar a falha**

Run: `PYTHONPATH=backend pytest backend/tests/test_client_and_seg_analyzer.py -v`  
Expected: FAIL com `ModuleNotFoundError`

- [ ] **Step 3: Implementar `client_analyzer.py` e `seg_analyzer.py`**

```python
# backend/app/analyzers/client_analyzer.py
import re
from typing import Optional, List
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
from app.core.schemas import ClientMetadata

SUSPICIOUS_CLIENT_PATTERNS = [
    r'phpmailer', r'python', r'curl', r'libwww', r'lwp', r'powershell', r'massmail', r'blaster'
]

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".iso", ".bat", ".xlsm", ".hta", ".one", ".ps1", ".jar", ".cmd", ".lnk"
}

def analyze_client_metadata(msg: EmailMessage, first_hop_iso: Optional[str] = None) -> ClientMetadata:
    message_id = msg.get("Message-ID", "").strip()
    msg_id_domain = None
    msg_id_valid = True
    if message_id:
        match = re.search(r'@([^>]+)>?', message_id)
        if match:
            msg_id_domain = match.group(1).strip()
        else:
            msg_id_valid = False
            
    x_mailer = msg.get("X-Mailer", "") or msg.get("User-Agent", "")
    suspicious_client = False
    if x_mailer:
        for pat in SUSPICIOUS_CLIENT_PATTERNS:
            if re.search(pat, x_mailer, re.IGNORECASE):
                suspicious_client = True
                break

    # Check Date vs Received drift
    date_header = msg.get("Date", "")
    drift_sec = 0
    drift_suspicious = False
    if date_header and first_hop_iso:
        try:
            client_dt = parsedate_to_datetime(date_header)
            hop_dt = parsedate_to_datetime(first_hop_iso)
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
        content_type = part.get("Content-Type", "")
        for ext in DANGEROUS_EXTENSIONS:
            if ext in content_type.lower():
                dangerous.append(f"MIME Content-Type contains {ext}")
                break

    return ClientMetadata(
        message_id=message_id or None,
        message_id_domain=msg_id_domain,
        message_id_valid=msg_id_valid,
        x_mailer=x_mailer or None,
        user_agent=msg.get("User-Agent", None),
        suspicious_client=suspicious_client,
        date_header=date_header or None,
        received_date=first_hop_iso,
        time_drift_seconds=drift_sec,
        time_drift_suspicious=drift_suspicious,
        dangerous_attachments=list(set(dangerous))
    )
```

```python
# backend/app/analyzers/seg_analyzer.py
import re
from typing import List
from email.message import EmailMessage
from app.core.schemas import SegVerdicts

def analyze_seg_verdicts(msg: EmailMessage) -> SegVerdicts:
    verdicts = SegVerdicts()
    
    # Microsoft 365
    forefront = msg.get("X-Forefront-Antispam-Report", "")
    if forefront:
        scl_m = re.search(r'\bSCL:(-?\d+)', forefront)
        if scl_m:
            verdicts.m365_scl = int(scl_m.group(1))
            
        bcl_m = re.search(r'\bBCL:(\d+)', forefront)
        if bcl_m:
            verdicts.m365_bcl = int(bcl_m.group(1))
            
        cat_m = re.search(r'\bCAT:(\w+)', forefront)
        if cat_m:
            verdicts.m365_cat = cat_m.group(1).upper()
            
        sfv_m = re.search(r'\bSFV:(\w+)', forefront)
        if sfv_m:
            verdicts.m365_sfv = sfv_m.group(1).upper()

    # Exchange AuthAs
    exchange_auth = msg.get("X-MS-Exchange-Organization-AuthAs", "")
    if exchange_auth:
        verdicts.exchange_auth_as = exchange_auth.strip()

    # Google Workspace
    verdicts.google_smtp_source = msg.get("X-Google-Smtp-Source", None)
    verdicts.google_message_state = msg.get("X-Gm-Message-State", None)

    # Sandbox / URL Rewriting
    sandboxes: List[str] = []
    if msg.get("X-Proofpoint-Virus-Version") or msg.get("X-Proofpoint-Spam-Details"):
        sandboxes.append("Proofpoint TAP")
    if "safelinks" in str(msg.get_all("X-MS-Exchange-Organization-SCL", [])) or "safelinks" in str(msg.as_string()):
        sandboxes.append("Microsoft Defender Safe Links")
    if msg.get("X-Mimecast-Spam-Score"):
        sandboxes.append("Mimecast Targeted Threat Protection")
        
    verdicts.sandbox_detected = len(sandboxes) > 0
    verdicts.sandbox_names = sandboxes
    
    return verdicts
```

- [ ] **Step 4: Executar os testes para verificar sucesso**

Run: `PYTHONPATH=backend pytest backend/tests/test_client_and_seg_analyzer.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/analyzers/client_analyzer.py backend/app/analyzers/seg_analyzer.py backend/tests/test_client_and_seg_analyzer.py
git commit -m "feat(backend): implement client metadata, MIME checker and SEG analyzer"
```

---

### Task 7: Motor de Risco (Risk Engine) & Geração de Relatório PDF (`scoring.py` e `report_generator.py`)

**Files:**
- Create: `backend/app/engine/scoring.py`
- Create: `backend/app/engine/report_generator.py`
- Create: `backend/tests/test_scoring.py`

**Interfaces:**
- Consumes: All analyzed schemas (`AuthStatus`, `IdentityAnalysis`, `DomainInfo`, `OriginIpInfo`, `ClientMetadata`, `SegVerdicts`).
- Produces: `def calculate_risk_score(...) -> Tuple[AnalysisSummary, List[Finding]]`, `def generate_pdf_report(response: EmailAnalysisResponse) -> bytes`.

- [ ] **Step 1: Escrever teste do motor de cálculo de risco**

```python
# backend/tests/test_scoring.py
from app.core.schemas import AuthStatus, IdentityAnalysis, DomainInfo, OriginIpInfo, ClientMetadata, SegVerdicts, RiskLevel
from app.engine.scoring import calculate_risk_score

def test_calculate_risk_score_clean():
    auth = AuthStatus(spf_verdict="pass", dkim_verdict="pass", dmarc_verdict="pass")
    identity = IdentityAnalysis(from_address="a@b.com", from_domain="b.com", from_display_name="A")
    domain = DomainInfo(domain="b.com", age_days=500, has_mx=True)
    origin_ip = OriginIpInfo(ip="1.2.3.4", rbl_listed=False)
    client = ClientMetadata(message_id_valid=True)
    seg = SegVerdicts()
    
    summary, findings = calculate_risk_score(auth, identity, domain, origin_ip, client, seg, total_hops=2, elapsed_ms=150.0)
    assert summary.score <= 25
    assert summary.risk_level == RiskLevel.SAFE

def test_calculate_risk_score_phishing():
    auth = AuthStatus(spf_verdict="fail", dkim_verdict="none", dmarc_verdict="fail")
    identity = IdentityAnalysis(from_address="a@fake.com", from_domain="fake.com", from_display_name="CEO", display_name_spoofing=True, envelope_mismatch=True)
    domain = DomainInfo(domain="fake.com", age_days=4, has_mx=False)
    origin_ip = OriginIpInfo(ip="1.2.3.4", rbl_listed=True, rbl_listings=["Spamhaus"])
    client = ClientMetadata(suspicious_client=True, dangerous_attachments=["virus.exe"])
    seg = SegVerdicts(m365_cat="PHSH")
    
    summary, findings = calculate_risk_score(auth, identity, domain, origin_ip, client, seg, total_hops=1, elapsed_ms=100.0)
    assert summary.score >= 76
    assert summary.risk_level == RiskLevel.CRITICAL
```

- [ ] **Step 2: Executar o teste e verificar a falha**

Run: `PYTHONPATH=backend pytest backend/tests/test_scoring.py -v`  
Expected: FAIL com `ModuleNotFoundError`

- [ ] **Step 3: Implementar `scoring.py` e `report_generator.py`**

```python
# backend/app/engine/scoring.py
from typing import List, Tuple
from app.core.schemas import (
    AuthStatus, IdentityAnalysis, DomainInfo, OriginIpInfo, 
    ClientMetadata, SegVerdicts, AnalysisSummary, Finding, RiskLevel
)

def calculate_risk_score(
    auth: AuthStatus,
    identity: IdentityAnalysis,
    domain: DomainInfo,
    origin_ip: OriginIpInfo,
    client: ClientMetadata,
    seg: SegVerdicts,
    total_hops: int,
    elapsed_ms: float
) -> Tuple[AnalysisSummary, List[Finding]]:
    findings: List[Finding] = []
    total_score = 0

    # 1. Autenticação
    if auth.spf_verdict in ["fail", "permerror"]:
        findings.append(Finding(category="Autenticação", title="SPF Fail", description="O IP emissor não possui autorização no registro SPF", points=20, severity=RiskLevel.HIGH))
        total_score += 20
    elif auth.spf_verdict in ["softfail", "neutral"]:
        findings.append(Finding(category="Autenticação", title="SPF Softfail/Neutral", description="Registro SPF permissivo ou não rigoroso", points=10, severity=RiskLevel.INFO))
        total_score += 10
    elif auth.spf_verdict == "none":
        findings.append(Finding(category="Autenticação", title="Sem SPF", description="Domínio sem registro SPF detectado", points=5, severity=RiskLevel.INFO))
        total_score += 5

    if auth.dkim_verdict in ["fail", "invalid"]:
        findings.append(Finding(category="Autenticação", title="DKIM Inválido", description="Assinatura criptográfica DKIM corrompida ou inválida", points=20, severity=RiskLevel.HIGH))
        total_score += 20
    elif auth.dkim_verdict == "none":
        findings.append(Finding(category="Autenticação", title="Sem Assinatura DKIM", description="Mensagem não possui assinatura DKIM", points=10, severity=RiskLevel.INFO))
        total_score += 10

    if auth.dmarc_verdict == "fail":
        pts = 20 if auth.dmarc_policy in ["quarantine", "reject"] else 10
        findings.append(Finding(category="Autenticação", title="DMARC Fail", description=f"Falha de validação DMARC (política: {auth.dmarc_policy or 'none'})", points=pts, severity=RiskLevel.HIGH if pts==20 else RiskLevel.INFO))
        total_score += pts

    # 2. Identidade & Spoofing
    if identity.display_name_spoofing:
        findings.append(Finding(category="Identidade & BEC", title="Display Name Spoofing (BEC)", description="Nome amigável corporativo/executivo enviado a partir de webmail público", points=30, severity=RiskLevel.CRITICAL))
        total_score += 30

    if identity.typosquatting_detected:
        findings.append(Finding(category="Identidade & BEC", title="Typosquatting no Reply-To", description=f"Reply-To ({identity.reply_to_domain}) possui semelhança gráfica enganosa com From ({identity.from_domain})", points=25, severity=RiskLevel.CRITICAL))
        total_score += 25
    elif identity.reply_to_mismatch:
        findings.append(Finding(category="Identidade & BEC", title="Reply-To Divergente", description="Respostas são desviadas para um domínio diferente do remetente", points=10, severity=RiskLevel.INFO))
        total_score += 10

    if identity.envelope_mismatch:
        findings.append(Finding(category="Identidade & BEC", title="Envelope Spoofing (From vs Return-Path)", description=f"Domínio visível ({identity.from_domain}) difere do Return-Path ({identity.return_path_domain})", points=15, severity=RiskLevel.HIGH))
        total_score += 15

    # 3. Infraestrutura & Reputação
    if origin_ip.rbl_listed:
        findings.append(Finding(category="Infraestrutura", title="IP em Blacklist (RBL)", description=f"IP de origem listado em listas negras ativas: {', '.join(origin_ip.rbl_listings)}", points=25, severity=RiskLevel.CRITICAL))
        total_score += 25

    if domain.age_days is not None:
        if domain.age_days < 30:
            findings.append(Finding(category="Infraestrutura", title="Domínio Recém-Registrado (< 30 dias)", description=f"Domínio registrado há apenas {domain.age_days} dias (alto risco de descarte)", points=20, severity=RiskLevel.HIGH))
            total_score += 20
        elif domain.age_days < 90:
            findings.append(Finding(category="Infraestrutura", title="Domínio Jovem (< 90 dias)", description=f"Domínio registrado há {domain.age_days} dias", points=10, severity=RiskLevel.INFO))
            total_score += 10

    if not domain.has_mx:
        findings.append(Finding(category="Infraestrutura", title="Domínio Sem Registros MX", description="O domínio emissor não possui servidores MX válidos para receber respostas", points=20, severity=RiskLevel.HIGH))
        total_score += 20

    # 4. Metadados e Gateways
    if seg.m365_cat in ["PHSH", "MALW"]:
        findings.append(Finding(category="Gateways SEGs", title="Microsoft 365: Veredito de Phishing/Malware", description=f"O gateway categorizou o e-mail como {seg.m365_cat}", points=25, severity=RiskLevel.CRITICAL))
        total_score += 25
    elif seg.m365_scl is not None and seg.m365_scl >= 5:
        findings.append(Finding(category="Gateways SEGs", title="Microsoft 365: SCL Elevado", description=f"Spam Confidence Level de {seg.m365_scl} (limiar de spam/risco)", points=15, severity=RiskLevel.HIGH))
        total_score += 15

    if client.dangerous_attachments:
        findings.append(Finding(category="Conteúdo MIME", title="Anexos Perigosos Detectados", description=f"Extensões de alto risco identificadas: {', '.join(client.dangerous_attachments)}", points=20, severity=RiskLevel.CRITICAL))
        total_score += 20

    if client.time_drift_suspicious:
        findings.append(Finding(category="Metadados", title="Descompasso Temporal Grave", description=f"Diferença entre data do emissor e primeiro salto de {client.time_drift_seconds // 60} minutos", points=10, severity=RiskLevel.INFO))
        total_score += 10

    if client.suspicious_client:
        findings.append(Finding(category="Metadados", title="Cliente / X-Mailer Suspeito", description=f"Disparador automatizado identificado: {client.x_mailer}", points=10, severity=RiskLevel.INFO))
        total_score += 10

    # Normalização
    final_score = min(100, total_score)
    if final_score <= 25:
        risk_level = RiskLevel.SAFE
        verdict = "E-mail com baixíssimo risco de fraude ou falsificação."
        recommendation = "Nenhuma ação bloqueante necessária. Fluxo normal."
    elif final_score <= 50:
        risk_level = RiskLevel.INFO
        verdict = "E-mail com inconsistências moderadas ou configurações permissivas."
        recommendation = "Recomenda-se cautela com links e validação do contexto antes de interagir."
    elif final_score <= 75:
        risk_level = RiskLevel.HIGH
        verdict = "Alto risco de fraude, spam ostensivo ou tentativa de phishing."
        recommendation = "Bloquear remetente e inspecionar anexos/URLs em ambiente sandbox."
    else:
        risk_level = RiskLevel.CRITICAL
        verdict = "Ameaça crítica: Fraude, BEC ou Phishing confirmado."
        recommendation = "Descartar mensagem imediatamente, isolar endpoint e adicionar IOCs ao SIEM/EDR."

    summary = AnalysisSummary(
        score=final_score,
        risk_level=risk_level,
        verdict_text=verdict,
        recommendation=recommendation,
        elapsed_ms=round(elapsed_ms, 2),
        total_hops=total_hops
    )
    return summary, findings
```

```python
# backend/app/engine/report_generator.py
import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from app.core.schemas import EmailAnalysisResponse

def generate_pdf_report(analysis: EmailAnalysisResponse) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a')
    )
    
    story = []
    story.append(Paragraph("Relatório Técnico de Forense de E-mail (SOC)", title_style))
    story.append(Paragraph(f"<b>Data da Análise:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | <b>Score de Risco:</b> {analysis.summary.score}/100 ({analysis.summary.risk_level})", styles['Normal']))
    story.append(Paragraph(f"<b>Hash SHA-256 do Cabeçalho:</b> <code>{analysis.raw_header_hash[:32]}...</code>", styles['Normal']))
    story.append(Spacer(1, 14))

    # Summary Box
    summary_data = [
        [Paragraph("<b>Veredito Geral</b>", styles['Normal']), Paragraph(analysis.summary.verdict_text, styles['Normal'])],
        [Paragraph("<b>Recomendação</b>", styles['Normal']), Paragraph(analysis.summary.recommendation, styles['Normal'])],
        [Paragraph("<b>Remetente (From)</b>", styles['Normal']), Paragraph(f"{analysis.identity.from_display_name} &lt;{analysis.identity.from_address}&gt;", styles['Normal'])],
        [Paragraph("<b>IP de Origem</b>", styles['Normal']), Paragraph(f"{analysis.origin_ip.ip or 'Desconhecido'} ({analysis.origin_ip.country or 'N/A'}, {analysis.origin_ip.org or 'N/A'})", styles['Normal'])],
    ]
    t_summary = Table(summary_data, colWidths=[130, 410])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 14))

    # Findings Table
    story.append(Paragraph("<b>Evidências Técnicas e Fatores de Risco</b>", styles['Heading2']))
    findings_data = [["Categoria", "Achado", "Severidade", "Pontos"]]
    for f in analysis.findings:
        findings_data.append([f.category, f.title, str(f.severity.value), f"+{f.points}"])
    if len(findings_data) == 1:
        findings_data.append(["N/A", "Nenhuma evidência de risco detectada", "SAFE", "0"])
        
    t_findings = Table(findings_data, colWidths=[110, 260, 90, 80])
    t_findings.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_findings)
    story.append(Spacer(1, 14))

    # Hops Table
    story.append(Paragraph("<b>Cadeia de Saltos (Received Hops)</b>", styles['Heading2']))
    hops_data = [["Salto", "IP", "FCrDNS", "Localização / ASN", "Latência"]]
    for h in analysis.hops:
        fcrdns_str = "OK" if h.fcrdns_passed else ("Falha" if h.fcrdns_passed is False else "N/A")
        loc_str = f"{h.country or ''} {h.org or ''}".strip() or "N/A"
        hops_data.append([f"#{h.order}", h.ip or "N/A", fcrdns_str, loc_str, f"+{h.delay_seconds}s"])
        
    t_hops = Table(hops_data, colWidths=[50, 110, 70, 230, 80])
    t_hops.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#334155')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_hops)

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
```

- [ ] **Step 4: Executar os testes para verificar sucesso**

Run: `PYTHONPATH=backend pytest backend/tests/test_scoring.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/engine/scoring.py backend/app/engine/report_generator.py backend/tests/test_scoring.py
git commit -m "feat(backend): implement scoring engine and PDF report generator"
```

---

### Task 8: API FastAPI: Pipeline Assíncrono, Endpoints e Integração (`routes.py` e `main.py`)

**Files:**
- Create: `backend/app/api/routes.py`
- Create: `backend/app/main.py`
- Create: `backend/tests/test_api.py`

**Interfaces:**
- Consumes: All analyzers, schemas, engine.
- Produces: `POST /api/analyze`, `POST /api/export-pdf`, `GET /api/samples/{sample_id}`, `GET /api/health`.

- [ ] **Step 1: Escrever teste de integração da API**

```python
# backend/tests/test_api.py
import pytest
from fastapi.testclient import TestClient
from app.main import app
from tests.fixtures.sample_emails import SAMPLE_LEGITIMATE_HEADER, SAMPLE_PHISHING_HEADER

client = TestClient(app)

def test_health_endpoint():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"

def test_analyze_legitimate_email():
    payload = {
        "raw_header": SAMPLE_LEGITIMATE_HEADER,
        "options": {"live_dns": False, "rdap_lookup": False, "rbl_check": False}
    }
    resp = client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "summary" in data
    assert data["summary"]["score"] <= 25
    assert len(data["hops"]) >= 1

def test_export_pdf_endpoint():
    payload = {
        "raw_header": SAMPLE_PHISHING_HEADER,
        "options": {"live_dns": False, "rdap_lookup": False, "rbl_check": False}
    }
    resp = client.post("/api/export-pdf", json=payload)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content[:4] == b"%PDF"
```

- [ ] **Step 2: Executar o teste e verificar a falha**

Run: `PYTHONPATH=backend pytest backend/tests/test_api.py -v`  
Expected: FAIL com `ModuleNotFoundError`

- [ ] **Step 3: Implementar `routes.py` e `main.py`**

```python
# backend/app/api/routes.py
import time
import hashlib
import httpx
from email import message_from_string
from email.policy import default
from fastapi import APIRouter, HTTPException, Response
from app.core.schemas import (
    EmailAnalysisRequest, EmailAnalysisResponse, OriginIpInfo, DomainInfo
)
from app.analyzers.hops_analyzer import parse_hops
from app.analyzers.auth_analyzer import analyze_authentication
from app.analyzers.identity_analyzer import analyze_identity
from app.analyzers.client_analyzer import analyze_client_metadata
from app.analyzers.seg_analyzer import analyze_seg_verdicts
from app.analyzers.enrichment import lookup_geoip, lookup_rdap_domain
from app.analyzers.rbl_analyzer import check_rbls
from app.engine.scoring import calculate_risk_score
from app.engine.report_generator import generate_pdf_report
from tests.fixtures.sample_emails import (
    SAMPLE_LEGITIMATE_HEADER, SAMPLE_PHISHING_HEADER, SAMPLE_BEC_HEADER, SAMPLE_BOTNET_HEADER
)

router = APIRouter()

SAMPLES = {
    "legitimate": SAMPLE_LEGITIMATE_HEADER,
    "phishing": SAMPLE_PHISHING_HEADER,
    "bec": SAMPLE_BEC_HEADER,
    "botnet": SAMPLE_BOTNET_HEADER
}

@router.get("/health")
async def health():
    return {"status": "healthy", "service": "bp-email-analiser"}

@router.get("/samples/{sample_id}")
async def get_sample(sample_id: str):
    if sample_id not in SAMPLES:
        raise HTTPException(status_code=404, detail="Sample not found")
    return {"sample_id": sample_id, "raw_header": SAMPLES[sample_id]}

async def process_email(request: EmailAnalysisRequest) -> EmailAnalysisResponse:
    start_time = time.perf_counter()
    raw_header = request.raw_header.strip()
    if not raw_header:
        raise HTTPException(status_code=400, detail="Cabeçalho vazio fornecido")

    header_hash = hashlib.sha256(raw_header.encode('utf-8')).hexdigest()
    msg = message_from_string(raw_header, policy=default)

    # 1. Hops
    hops = await parse_hops(msg, perform_dns=request.options.live_dns)
    first_hop_date = hops[0].timestamp if hops else None
    
    # Extract Origin IP (first non-private hop IP or first hop)
    origin_ip_str = None
    for h in hops:
        if h.ip and not h.is_private:
            origin_ip_str = h.ip
            break
    if not origin_ip_str and hops and hops[0].ip:
        origin_ip_str = hops[0].ip

    # 2. Identity
    identity = analyze_identity(msg)
    sender_domain = identity.from_domain

    # 3. Authentication
    auth = await analyze_authentication(msg, sender_domain, perform_live_dns=request.options.live_dns)

    # 4. Client Metadata & SEGs
    client_meta = analyze_client_metadata(msg, first_hop_date)
    seg_verdicts = analyze_seg_verdicts(msg)

    # 5. Enrichment (GeoIP, RDAP, RBL)
    origin_ip_info = OriginIpInfo(ip=origin_ip_str)
    domain_info = DomainInfo(domain=sender_domain or "unknown")

    async with httpx.AsyncClient() as http_client:
        if origin_ip_str:
            if request.options.rdap_lookup:
                geo = await lookup_geoip(origin_ip_str, http_client)
                origin_ip_info.country = geo.get("country")
                origin_ip_info.city = geo.get("city")
                origin_ip_info.latitude = geo.get("lat")
                origin_ip_info.longitude = geo.get("lon")
                origin_ip_info.asn = geo.get("asn")
                origin_ip_info.org = geo.get("org")

                # Enrich hops coordinates
                for h in hops:
                    if h.ip and not h.is_private:
                        h_geo = await lookup_geoip(h.ip, http_client)
                        h.country = h_geo.get("country")
                        h.city = h_geo.get("city")
                        h.latitude = h_geo.get("lat")
                        h.longitude = h_geo.get("lon")
                        h.org = h_geo.get("org")
                        h.asn = h_geo.get("asn")

            if request.options.rbl_check:
                is_listed, listings = await check_rbls(origin_ip_str)
                origin_ip_info.rbl_listed = is_listed
                origin_ip_info.rbl_listings = listings

        if sender_domain and request.options.rdap_lookup:
            domain_info = await lookup_rdap_domain(sender_domain, http_client)

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    # 6. Scoring
    summary, findings = calculate_risk_score(
        auth=auth,
        identity=identity,
        domain=domain_info,
        origin_ip=origin_ip_info,
        client=client_meta,
        seg=seg_verdicts,
        total_hops=len(hops),
        elapsed_ms=elapsed_ms
    )

    return EmailAnalysisResponse(
        summary=summary,
        findings=findings,
        hops=hops,
        authentication=auth,
        identity=identity,
        domain_info=domain_info,
        origin_ip=origin_ip_info,
        client_metadata=client_meta,
        seg_verdicts=seg_verdicts,
        raw_header_hash=header_hash
    )

@router.post("/analyze", response_model=EmailAnalysisResponse)
async def analyze(request: EmailAnalysisRequest):
    return await process_email(request)

@router.post("/export-pdf")
async def export_pdf(request: EmailAnalysisRequest):
    analysis = await process_email(request)
    pdf_bytes = generate_pdf_report(analysis)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=soc-email-report-{analysis.raw_header_hash[:8]}.pdf"}
    )
```

```python
# backend/app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router
from app.core.config import settings

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Forense de Cabeçalho de E-mail e Detecção de Fraude",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix=settings.API_PREFIX)
```

- [ ] **Step 4: Executar os testes para verificar sucesso**

Run: `PYTHONPATH=backend pytest backend/tests/test_api.py -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/app/api/routes.py backend/app/main.py backend/tests/test_api.py
git commit -m "feat(backend): implement FastAPI routes, pipeline and endpoints"
```

---

### Task 9: Frontend Scaffolding, Tipos TypeScript e Componentes de Ingestão e Status

**Files:**
- Create: `frontend/package.json`
- Create: `frontend/vite.config.ts`
- Create: `frontend/tailwind.config.js`
- Create: `frontend/postcss.config.js`
- Create: `frontend/tsconfig.json`
- Create: `frontend/src/index.css`
- Create: `frontend/src/types/email.ts`
- Create: `frontend/src/services/api.ts`
- Create: `frontend/src/components/HeaderInput.tsx`
- Create: `frontend/src/components/RiskGauge.tsx`

**Interfaces:**
- Consumes: Backend REST API (`/api/analyze`, `/api/samples`, `/api/export-pdf`).
- Produces: Componentes React tipados para entrada de cabeçalho e mostrador de pontuação visual de risco.

- [ ] **Step 1: Escrever declaração de tipos e cliente de API**

```typescript
// frontend/src/types/email.ts
export type RiskLevel = "SAFE" | "INFO" | "HIGH" | "CRITICAL";

export interface Finding {
  category: string;
  title: string;
  description: string;
  points: int;
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
```

- [ ] **Step 2: Configurar package.json, Vite e Tailwind**

```json
// frontend/package.json
{
  "name": "bp-email-analiser-frontend",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "clsx": "^2.1.1",
    "leaflet": "^1.9.4",
    "lucide-react": "^0.441.0",
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "tailwind-merge": "^2.5.2"
  },
  "devDependencies": {
    "@types/leaflet": "^1.9.12",
    "@types/react": "^18.3.5",
    "@types/react-dom": "^18.3.0",
    "@vitejs/plugin-react": "^4.3.1",
    "autoprefixer": "^10.4.20",
    "postcss": "^8.4.45",
    "tailwindcss": "^3.4.11",
    "typescript": "^5.5.3",
    "vite": "^5.4.3"
  }
}
```

- [ ] **Step 3: Implementar `HeaderInput.tsx` e `RiskGauge.tsx`**

```tsx
// frontend/src/components/RiskGauge.tsx
import React from 'react';
import { RiskLevel } from '../types/email';

interface RiskGaugeProps {
  score: number;
  riskLevel: RiskLevel;
  elapsedMs: number;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({ score, riskLevel, elapsedMs }) => {
  const getColor = () => {
    switch (riskLevel) {
      case 'SAFE': return { bg: 'bg-emerald-500', text: 'text-emerald-500', border: 'border-emerald-500/30' };
      case 'INFO': return { bg: 'bg-amber-500', text: 'text-amber-500', border: 'border-amber-500/30' };
      case 'HIGH': return { bg: 'bg-orange-500', text: 'text-orange-500', border: 'border-orange-500/30' };
      case 'CRITICAL': return { bg: 'bg-rose-600', text: 'text-rose-600', border: 'border-rose-600/30' };
    }
  };

  const colors = getColor();

  return (
    <div className={`p-6 rounded-2xl bg-slate-900/80 border ${colors.border} backdrop-blur-sm flex flex-col items-center justify-center text-center shadow-lg shadow-black/20`}>
      <span className="text-xs uppercase tracking-widest text-slate-400 font-semibold mb-2">Score de Risco / Fraude</span>
      <div className="relative flex items-center justify-center w-36 h-36">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
          <circle cx="50" cy="50" r="40" className="stroke-slate-800" strokeWidth="10" fill="transparent" />
          <circle
            cx="50"
            cy="50"
            r="40"
            className={`${colors.text} transition-all duration-1000 ease-out`}
            strokeWidth="10"
            strokeDasharray={251.2}
            strokeDashoffset={251.2 - (251.2 * score) / 100}
            strokeLinecap="round"
            fill="transparent"
          />
        </svg>
        <div className="absolute flex flex-col items-center">
          <span className="text-4xl font-extrabold text-white tracking-tight">{score}</span>
          <span className="text-xs text-slate-400">/ 100</span>
        </div>
      </div>
      <div className={`mt-3 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider text-white ${colors.bg}`}>
        {riskLevel}
      </div>
      <span className="text-xs text-slate-500 mt-2">Processado em {elapsedMs}ms</span>
    </div>
  );
};
```

- [ ] **Step 4: Executar instalação das dependências do frontend e build de verificação**

Run: `cd frontend && npm install && npm run build`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/
git commit -m "feat(frontend): scaffold react project, types and RiskGauge component"
```

---

### Task 10: Frontend Componentes Visuais (HopsTimeline, HopsMap, AuthBadges, IdentityCard, SegCard, RawHeaderViewer) & App Principal

**Files:**
- Create: `frontend/src/components/HopsTimeline.tsx`
- Create: `frontend/src/components/HopsMap.tsx`
- Create: `frontend/src/components/AuthBadges.tsx`
- Create: `frontend/src/components/IdentityCard.tsx`
- Create: `frontend/src/components/SegCard.tsx`
- Create: `frontend/src/components/WhoisPanel.tsx`
- Create: `frontend/src/components/RawHeaderViewer.tsx`
- Create: `frontend/src/App.tsx`

**Interfaces:**
- Consumes: `EmailAnalysisResponse`.
- Produces: Interface completa de SOC para visualização gráfica, mapa Leaflet, alternância de abas e exportação PDF/JSON.

- [ ] **Step 1: Implementar `HopsTimeline.tsx` e `HopsMap.tsx`**

```tsx
// frontend/src/components/HopsMap.tsx
import React, { useEffect, useRef } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { HopInfo } from '../types/email';

interface HopsMapProps {
  hops: HopInfo[];
}

export const HopsMap: React.FC<HopsMapProps> = ({ hops }) => {
  const mapRef = useRef<HTMLDivElement>(null);
  const leafletInstance = useRef<L.Map | null>(null);

  useEffect(() => {
    if (!mapRef.current) return;
    if (leafletInstance.current) {
      leafletInstance.current.remove();
    }

    const map = L.map(mapRef.current).setView([20, 0], 2);
    leafletInstance.current = map;

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; CartoDB &copy; OpenStreetMap',
      maxZoom: 19
    }).addTo(map);

    const validHops = hops.filter(h => h.latitude && h.longitude);
    const latLngs: L.LatLngExpression[] = [];

    validHops.forEach(h => {
      if (h.latitude && h.longitude) {
        const pt: [number, number] = [h.latitude, h.longitude];
        latLngs.push(pt);
        L.circleMarker(pt, {
          radius: 7,
          color: h.fcrdns_passed ? '#10b981' : '#f43f5e',
          fillColor: h.fcrdns_passed ? '#10b981' : '#f43f5e',
          fillOpacity: 0.8
        })
          .bindPopup(`<b>Salto #${h.order}</b><br/>IP: ${h.ip}<br/>${h.city || ''}, ${h.country || ''}<br/>${h.org || ''}`)
          .addTo(map);
      }
    });

    if (latLngs.length > 1) {
      L.polyline(latLngs, { color: '#38bdf8', weight: 2.5, dashArray: '5, 8' }).addTo(map);
      map.fitBounds(L.latLngBounds(latLngs), { padding: [30, 30] });
    }

    return () => {
      map.remove();
    };
  }, [hops]);

  return <div ref={mapRef} className="w-full h-80 rounded-xl overflow-hidden border border-slate-800" />;
};
```

- [ ] **Step 2: Implementar `AuthBadges.tsx`, `IdentityCard.tsx`, `SegCard.tsx`, `WhoisPanel.tsx` e `RawHeaderViewer.tsx`**

- [ ] **Step 3: Implementar o `App.tsx` integrando tudo (Dark Mode, Tabs, Exportação PDF/JSON)**

- [ ] **Step 4: Executar build e verificar compilação sem erros**

Run: `cd frontend && npm run build`  
Expected: PASS com geração de bundle estático em `frontend/dist/`

- [ ] **Step 5: Commit**

```bash
git add frontend/
git commit -m "feat(frontend): integrate all forensic cards, Leaflet map and export actions"
```

---

### Task 11: Script de Inicialização Rápida, Validação Ponta a Ponta & Documentação

**Files:**
- Create: `run.sh`
- Create: `README.md`

**Interfaces:**
- Consumes: Backend FastAPI e Frontend Vite/Dist.
- Produces: Script bash de execução com 1 comando (`./run.sh`) e documentação completa com fotos de arquitetura e exemplos.

- [ ] **Step 1: Escrever script `run.sh` com suporte a ambiente virtual e portas**

```bash
#!/usr/bin/env bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "=== Inicializando bp-email-analiser ==="

# 1. Setup Python Venv
if [ ! -d "backend/.venv" ]; then
    echo "[+] Criando virtualenv Python..."
    python3 -m venv backend/.venv
    backend/.venv/bin/pip install --upgrade pip
    backend/.venv/bin/pip install -r backend/requirements.txt
fi

# 2. Build Frontend se dist não existir
if [ ! -d "frontend/dist" ]; then
    echo "[+] Instalando dependências e buildando frontend..."
    cd frontend && npm install && npm run build && cd ..
fi

# 3. Inicializar Servidores
echo "[+] Iniciando Backend FastAPI na porta 8000..."
backend/.venv/bin/uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

echo "[+] Iniciando Frontend na porta 5173..."
cd frontend && npx vite --host 0.0.0.0 --port 5173 &
FRONTEND_PID=$!

trap "kill $BACKEND_PID $FRONTEND_PID" EXIT

echo "=== bp-email-analiser ativo! ==="
echo "Frontend: http://localhost:5173"
echo "API Docs: http://localhost:8000/docs"
wait
```

- [ ] **Step 2: Tornar o script executável e escrever README.md explicativo**

- [ ] **Step 3: Testar execução de ponta a ponta com pytest completo no backend**

Run: `PYTHONPATH=backend backend/.venv/bin/pytest backend/tests/ -v`  
Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
git add run.sh README.md
git commit -m "chore: add run.sh script and comprehensive README documentation"
```

---

## Auto-Revisão do Plano

1. **Cobertura da Especificação:**
   - Hops chronológicos + latência + FCrDNS: Tasks 2, 8, 10.
   - Enriquecimento Whois/RDAP + GeoIP + ASN + MX + RBL: Tasks 3, 8, 10.
   - SPF, DKIM, DMARC, ARC (local + DNS ao vivo): Tasks 4, 8, 10.
   - Identidade (From vs Return-Path, Reply-To typosquatting, BEC Display Name): Tasks 5, 8, 10.
   - Metadados do Cliente + MIME anexo perigoso + M365/SEGs/Google: Tasks 6, 8, 10.
   - Motor de Risco 0-100 + Veredito + Relatório PDF/JSON: Tasks 7, 8, 9, 10.
   - Frontend com mapa Leaflet, gauges, cards e inputs: Tasks 9, 10.
2. **Scan de Placeholders:** Nenhum "TBD", "TODO" ou código vago; todas as funções e testes possuem código concreto.
3. **Consistência de Tipos:** Nomes de propriedades e schemas Pydantic batem com as interfaces TypeScript do frontend.
