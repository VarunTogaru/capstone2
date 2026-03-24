import pytest
from app.scan.request import Request
from app.connect.runner import build_nmap_args


class TestBuildNmapArgs:
    def test_tcp_scan(self):
        req = Request(target="scanme.nmap.org", scan_type="tcp")
        args = build_nmap_args(req)
        assert args[0] == "nmap"
        assert "-sT" in args
        assert args[-3:] == ["-oX", "-", "scanme.nmap.org"]

    def test_syn_scan(self):
        req = Request(target="10.0.0.1", scan_type="syn")
        args = build_nmap_args(req)
        assert "-sS" in args

    def test_version_scan(self):
        req = Request(target="10.0.0.1", scan_type="version")
        args = build_nmap_args(req)
        assert "-sV" in args

    def test_custom_scan_no_type_flag(self):
        req = Request(target="10.0.0.1", scan_type="custom")
        args = build_nmap_args(req)
        assert args == ["nmap", "-oX", "-", "10.0.0.1"]

    def test_with_ports(self):
        req = Request(target="10.0.0.1", scan_type="tcp", ports="22,80,443")
        args = build_nmap_args(req)
        p_index = args.index("-p")
        assert args[p_index + 1] == "22,80,443"

    def test_with_extra_args(self):
        req = Request(target="10.0.0.1", scan_type="tcp", extra_args=["-Pn", "-T4"])
        args = build_nmap_args(req)
        assert "-Pn" in args
        assert "-T4" in args

    def test_ports_and_extra_args(self):
        req = Request(target="10.0.0.1", scan_type="tcp", ports="443", extra_args=["-T4"])
        args = build_nmap_args(req)
        assert "-p" in args
        assert "443" in args
        assert "-T4" in args
        assert args[-3:] == ["-oX", "-", "10.0.0.1"]

    def test_no_ports_no_extras(self):
        req = Request(target="10.0.0.1", scan_type="tcp")
        args = build_nmap_args(req)
        assert "-p" not in args

    def test_invalid_scan_type(self):
        req = Request(target="10.0.0.1")
        req.scan_type = "invalid"
        with pytest.raises(RuntimeError, match="Unsupported scan type"):
            build_nmap_args(req)

    def test_xml_output_always_present(self):
        req = Request(target="host.example.com", scan_type="tcp")
        args = build_nmap_args(req)
        assert "-oX" in args
        oX_index = args.index("-oX")
        assert args[oX_index + 1] == "-"

    def test_target_is_last_arg(self):
        req = Request(target="host.example.com", scan_type="syn", ports="80", extra_args=["-Pn"])
        args = build_nmap_args(req)
        assert args[-1] == "host.example.com"
