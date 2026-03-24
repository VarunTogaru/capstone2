import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
from starlette.testclient import TestClient

from app.main import app

SAMPLE_XML = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -oX - scanme.nmap.org"
         start="1234567890" version="7.94" xmloutputversion="1.05">
  <scaninfo type="connect" protocol="tcp" numservices="1" services="80"/>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="45.33.32.156" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1234567900"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
"""

client = TestClient(app)


def _make_mock_process(stdout: bytes, stderr: bytes = b"", returncode: int = 0):
    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.returncode = returncode
    proc.kill = MagicMock()
    return proc


class TestScanEndpoint:
    @patch("app.connect.runner.shutil.which", return_value="/usr/bin/nmap")
    @patch("app.connect.runner.asyncio.create_subprocess_exec")
    def test_successful_scan(self, mock_exec, mock_which):
        mock_exec.return_value = _make_mock_process(SAMPLE_XML.encode())

        response = client.post("/scan", json={
            "target": "scanme.nmap.org",
            "scan_type": "tcp",
        })
        assert response.status_code == 200
        data = response.json()
        assert "hosts" in data
        assert len(data["hosts"]) == 1
        assert data["hosts"][0]["address"] == "45.33.32.156"

    def test_empty_target_returns_422(self):
        response = client.post("/scan", json={
            "target": "",
            "scan_type": "tcp",
        })
        assert response.status_code == 422

    def test_invalid_target_returns_422(self):
        response = client.post("/scan", json={
            "target": "; rm -rf /",
            "scan_type": "tcp",
        })
        assert response.status_code == 422

    @patch("app.connect.runner.shutil.which", return_value="/usr/bin/nmap")
    @patch("app.connect.runner.asyncio.create_subprocess_exec")
    def test_nmap_failure_returns_500(self, mock_exec, mock_which):
        mock_exec.return_value = _make_mock_process(b"", b"Nmap failed", returncode=1)

        response = client.post("/scan", json={
            "target": "10.0.0.1",
            "scan_type": "tcp",
        })
        assert response.status_code == 500

    @patch("app.connect.runner.shutil.which", return_value="/usr/bin/nmap")
    @patch("app.connect.runner.asyncio.create_subprocess_exec")
    def test_timeout_returns_408(self, mock_exec, mock_which):
        proc = AsyncMock()
        proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        proc.kill = MagicMock()
        # After kill, communicate returns empty
        proc.communicate.side_effect = [asyncio.TimeoutError(), (b"", b"")]
        mock_exec.return_value = proc

        response = client.post("/scan", json={
            "target": "10.0.0.1",
            "scan_type": "tcp",
            "timeout_seconds": 10,
        })
        assert response.status_code == 408

    @patch("app.connect.runner.shutil.which", return_value=None)
    def test_nmap_not_installed_returns_500(self, mock_which):
        response = client.post("/scan", json={
            "target": "10.0.0.1",
            "scan_type": "tcp",
        })
        assert response.status_code == 500
