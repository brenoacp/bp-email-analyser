import json
import logging
import os
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Optional

from app.core.config import settings
from app.core.schemas import AnalysisOptions, EmailAnalysisResponse

AUDIT_LOGGER_NAME = "bp.audit"


def get_audit_logger() -> logging.Logger:
    return logging.getLogger(AUDIT_LOGGER_NAME)


def setup_audit_logging() -> logging.Logger:
    logger = logging.getLogger(AUDIT_LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Clear existing handlers
    while logger.handlers:
        h = logger.handlers.pop()
        h.close()

    if not settings.AUDIT_LOG_ENABLED:
        return logger

    # Ensure log directory exists
    log_file_path = settings.AUDIT_LOG_FILE
    log_dir = os.path.dirname(log_file_path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    # Formatter for single-line JSON records
    formatter = logging.Formatter("%(message)s")

    # Rotating file handler
    file_handler = RotatingFileHandler(
        log_file_path,
        maxBytes=settings.AUDIT_LOG_MAX_BYTES,
        backupCount=settings.AUDIT_LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Console stdout handler
    if settings.AUDIT_LOG_STDOUT:
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    return logger


def log_http_access(
    client_ip: Optional[str],
    user_agent: Optional[str],
    method: str,
    path: str,
    status_code: int,
    latency_ms: float,
) -> None:
    if not settings.AUDIT_LOG_ENABLED:
        return

    logger = get_audit_logger()
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "http_access",
        "client_ip": client_ip or "unknown",
        "user_agent": user_agent or "unknown",
        "method": method,
        "path": path,
        "status_code": status_code,
        "latency_ms": round(latency_ms, 2),
    }
    logger.info(json.dumps(record, ensure_ascii=False))


def log_forensic_analysis(
    raw_header: str,
    analysis: EmailAnalysisResponse,
    options: Optional[AnalysisOptions] = None,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> None:
    if not settings.AUDIT_LOG_ENABLED:
        return

    level = (settings.AUDIT_LOG_LEVEL or "FULL").upper()
    if level == "MINIMAL":
        return

    logger = get_audit_logger()
    risk_label = (
        analysis.summary.risk_level.value
        if hasattr(analysis.summary.risk_level, "value")
        else str(analysis.summary.risk_level)
    )

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "forensic_analysis",
        "client_ip": client_ip or "unknown",
        "user_agent": user_agent or "unknown",
        "raw_header_hash": analysis.raw_header_hash,
        "score": analysis.summary.score,
        "risk_level": risk_label,
        "verdict": analysis.summary.verdict_text,
        "recommendation": analysis.summary.recommendation,
        "options": {
            "live_dns": options.live_dns if options else None,
            "rdap_lookup": options.rdap_lookup if options else None,
            "rbl_check": options.rbl_check if options else None,
        },
        "identity": {
            "from_address": analysis.identity.from_address,
            "from_display_name": analysis.identity.from_display_name,
            "from_domain": analysis.identity.from_domain,
            "reply_to": analysis.identity.reply_to,
            "return_path": analysis.identity.return_path,
        },
        "origin_ip": {
            "ip": analysis.origin_ip.ip,
            "country": analysis.origin_ip.country,
            "asn": analysis.origin_ip.asn,
            "org": analysis.origin_ip.org,
            "is_private": analysis.origin_ip.is_private,
        },
        "hops": [h.ip for h in analysis.hops if h.ip],
        "total_hops": len(analysis.hops),
        "findings": [
            {
                "category": f.category,
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "points": f.points,
            }
            for f in analysis.findings
        ],
        "elapsed_ms": analysis.summary.elapsed_ms,
    }

    if level == "FULL":
        record["raw_header"] = raw_header

    logger.info(json.dumps(record, ensure_ascii=False))
