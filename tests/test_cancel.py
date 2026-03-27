from unittest.mock import MagicMock

import pytest
from app.connect.runner import RUNNING_PROCESSES, cancel_scan


class TestCancelScan:
    def setup_method(self):
        RUNNING_PROCESSES.clear()

    def test_cancel_existing_process(self):
        proc = MagicMock()
        RUNNING_PROCESSES["req_123"] = proc
        assert cancel_scan("req_123") is True
        proc.kill.assert_called_once()
        assert "req_123" not in RUNNING_PROCESSES

    def test_cancel_nonexistent_returns_false(self):
        assert cancel_scan("no_such_id") is False

    def test_cancel_already_dead_process(self):
        proc = MagicMock()
        proc.kill.side_effect = ProcessLookupError
        RUNNING_PROCESSES["req_456"] = proc
        assert cancel_scan("req_456") is True
        assert "req_456" not in RUNNING_PROCESSES


class TestCancelEndpoint:
    def test_cancel_not_found(self):
        RUNNING_PROCESSES.clear()
        from starlette.testclient import TestClient
        from app.main import app
        client = TestClient(app)
        response = client.post("/scan/cancel", json={"request_id": "nonexistent"})
        assert response.status_code == 404

    def test_cancel_missing_body(self):
        from starlette.testclient import TestClient
        from app.main import app
        client = TestClient(app)
        response = client.post("/scan/cancel", json={})
        assert response.status_code == 422
