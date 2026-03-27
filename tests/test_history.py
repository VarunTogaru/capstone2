import tempfile
from pathlib import Path

import pytest

from app.scan.db import init_db, save_scan, complete_scan, fail_scan, list_scans, get_scan, generate_id, delete_scan


@pytest.fixture(autouse=True)
def _fresh_db(tmp_path):
    """Initialise a throwaway database for each test."""
    init_db(tmp_path / "test.db")


class TestScanDb:
    def test_save_and_list(self):
        save_scan("s1", "10.0.0.1", "tcp", None, [], False)
        scans = list_scans()
        assert len(scans) == 1
        assert scans[0]["target"] == "10.0.0.1"
        assert scans[0]["status"] == "running"

    def test_complete_scan(self):
        save_scan("s2", "10.0.0.2", "syn", "80", ["-Pn"], True)
        complete_scan("s2", {"hosts": [{"address": "10.0.0.2"}]})
        record = get_scan("s2")
        assert record["status"] == "completed"
        assert record["result_json"]["hosts"][0]["address"] == "10.0.0.2"
        assert record["finished_at"] is not None

    def test_fail_scan(self):
        save_scan("s3", "10.0.0.3", "tcp", None, [], False)
        fail_scan("s3", "nmap not found")
        record = get_scan("s3")
        assert record["status"] == "failed"
        assert record["result_json"]["error"] == "nmap not found"

    def test_get_nonexistent(self):
        assert get_scan("does_not_exist") is None

    def test_list_ordering(self):
        save_scan("a", "host-a", "tcp", None, [], False)
        save_scan("b", "host-b", "syn", None, [], False)
        scans = list_scans()
        # Most recent first
        assert scans[0]["id"] == "b"
        assert scans[1]["id"] == "a"

    def test_list_limit(self):
        for i in range(5):
            save_scan(f"s{i}", f"host-{i}", "tcp", None, [], False)
        assert len(list_scans(limit=3)) == 3

    def test_generate_id_format(self):
        scan_id = generate_id()
        assert scan_id.startswith("scan_")
        assert len(scan_id) > 5

    def test_delete_scan(self):
        save_scan("del1", "10.0.0.1", "tcp", None, [], False)
        assert delete_scan("del1") is True
        assert get_scan("del1") is None

    def test_delete_nonexistent(self):
        assert delete_scan("nope") is False

    def test_extra_args_roundtrip(self):
        save_scan("s4", "host", "tcp", None, ["-Pn", "-T4"], False)
        record = get_scan("s4")
        assert record["extra_args"] == ["-Pn", "-T4"]


class TestHistoryEndpoints:
    """Integration tests for GET /scans and GET /scans/{id}."""

    def test_list_scans_empty(self):
        from starlette.testclient import TestClient
        from app.main import app
        client = TestClient(app)
        response = client.get("/scans")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_get_scan_not_found(self):
        from starlette.testclient import TestClient
        from app.main import app
        client = TestClient(app)
        response = client.get("/scans/nonexistent")
        assert response.status_code == 404
