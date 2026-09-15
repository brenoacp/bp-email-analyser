import json
import os
import tempfile
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.fixtures.sample_emails import SAMPLE_PHISHING_HEADER


@pytest.fixture
def temp_log_file():
    fd, path = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.remove(path)


def test_audit_logging_disabled(temp_log_file):
    from app.core.config import settings
    from app.core.logging import setup_audit_logging

    with patch.object(settings, "AUDIT_LOG_ENABLED", False), \
         patch.object(settings, "AUDIT_LOG_FILE", temp_log_file):
        setup_audit_logging()
        client = TestClient(app)
        resp = client.get("/api/health")
        assert resp.status_code == 200

        # Log file should be empty or non-existent
        if os.path.exists(temp_log_file):
            assert os.path.getsize(temp_log_file) == 0


def test_audit_logging_full_level(temp_log_file):
    from app.core.config import settings
    from app.core.logging import setup_audit_logging

    with patch.object(settings, "AUDIT_LOG_ENABLED", True), \
         patch.object(settings, "AUDIT_LOG_LEVEL", "FULL"), \
         patch.object(settings, "AUDIT_LOG_FILE", temp_log_file), \
         patch.object(settings, "AUDIT_LOG_STDOUT", False):
        setup_audit_logging()
        client = TestClient(app)
        payload = {
            "raw_header": SAMPLE_PHISHING_HEADER,
            "options": {"live_dns": False, "rdap_lookup": False, "rbl_check": False},
        }
        resp = client.post("/api/analyze", json=payload)
        assert resp.status_code == 200

        with open(temp_log_file, "r", encoding="utf-8") as f:
            lines = [json.loads(line.strip()) for line in f if line.strip()]

        event_types = [entry["event_type"] for entry in lines]
        assert "http_access" in event_types
        assert "forensic_analysis" in event_types

        # Verify HTTP access log details
        http_entry = next(e for e in lines if e["event_type"] == "http_access")
        assert http_entry["path"] == "/api/analyze"
        assert http_entry["method"] == "POST"
        assert http_entry["status_code"] == 200
        assert "latency_ms" in http_entry

        # Verify Forensic log details with FULL verbosity (including raw_header)
        forensic_entry = next(e for e in lines if e["event_type"] == "forensic_analysis")
        assert forensic_entry["raw_header"] == SAMPLE_PHISHING_HEADER
        assert "raw_header_hash" in forensic_entry
        assert "score" in forensic_entry
        assert "risk_level" in forensic_entry
        assert "options" in forensic_entry
        assert "identity" in forensic_entry
        assert "origin_ip" in forensic_entry
        assert "findings" in forensic_entry


def test_audit_logging_metadata_level(temp_log_file):
    from app.core.config import settings
    from app.core.logging import setup_audit_logging

    with patch.object(settings, "AUDIT_LOG_ENABLED", True), \
         patch.object(settings, "AUDIT_LOG_LEVEL", "METADATA"), \
         patch.object(settings, "AUDIT_LOG_FILE", temp_log_file), \
         patch.object(settings, "AUDIT_LOG_STDOUT", False):
        setup_audit_logging()
        client = TestClient(app)
        payload = {
            "raw_header": SAMPLE_PHISHING_HEADER,
            "options": {"live_dns": False, "rdap_lookup": False, "rbl_check": False},
        }
        resp = client.post("/api/analyze", json=payload)
        assert resp.status_code == 200

        with open(temp_log_file, "r", encoding="utf-8") as f:
            lines = [json.loads(line.strip()) for line in f if line.strip()]

        forensic_entry = next(e for e in lines if e["event_type"] == "forensic_analysis")
        # raw_header must NOT be in metadata level
        assert "raw_header" not in forensic_entry or forensic_entry["raw_header"] is None
        # But metadata must be present
        assert "raw_header_hash" in forensic_entry
        assert "score" in forensic_entry
        assert "risk_level" in forensic_entry
        assert "identity" in forensic_entry


def test_audit_logging_minimal_level(temp_log_file):
    from app.core.config import settings
    from app.core.logging import setup_audit_logging

    with patch.object(settings, "AUDIT_LOG_ENABLED", True), \
         patch.object(settings, "AUDIT_LOG_LEVEL", "MINIMAL"), \
         patch.object(settings, "AUDIT_LOG_FILE", temp_log_file), \
         patch.object(settings, "AUDIT_LOG_STDOUT", False):
        setup_audit_logging()
        client = TestClient(app)
        payload = {
            "raw_header": SAMPLE_PHISHING_HEADER,
            "options": {"live_dns": False, "rdap_lookup": False, "rbl_check": False},
        }
        resp = client.post("/api/analyze", json=payload)
        assert resp.status_code == 200

        with open(temp_log_file, "r", encoding="utf-8") as f:
            lines = [json.loads(line.strip()) for line in f if line.strip()]

        event_types = [entry["event_type"] for entry in lines]
        assert "http_access" in event_types
        # In MINIMAL mode, forensic_analysis event should NOT be logged
        assert "forensic_analysis" not in event_types


def test_audit_logging_export_pdf_triggers_log(temp_log_file):
    from app.core.config import settings
    from app.core.logging import setup_audit_logging

    with patch.object(settings, "AUDIT_LOG_ENABLED", True), \
         patch.object(settings, "AUDIT_LOG_LEVEL", "METADATA"), \
         patch.object(settings, "AUDIT_LOG_FILE", temp_log_file), \
         patch.object(settings, "AUDIT_LOG_STDOUT", False):
        setup_audit_logging()
        client = TestClient(app)
        payload = {
            "raw_header": SAMPLE_PHISHING_HEADER,
            "options": {"live_dns": False, "rdap_lookup": False, "rbl_check": False},
        }
        resp = client.post("/api/export-pdf", json=payload)
        assert resp.status_code == 200

        with open(temp_log_file, "r", encoding="utf-8") as f:
            lines = [json.loads(line.strip()) for line in f if line.strip()]

        event_types = [entry["event_type"] for entry in lines]
        assert "http_access" in event_types
        assert "forensic_analysis" in event_types
        http_entry = next(e for e in lines if e["event_type"] == "http_access")
        assert http_entry["path"] == "/api/export-pdf"
