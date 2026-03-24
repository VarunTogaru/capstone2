import pytest
from pydantic import ValidationError
from app.scan.request import Request


class TestTargetValidation:
    def test_valid_hostname(self):
        req = Request(target="scanme.nmap.org")
        assert req.target == "scanme.nmap.org"

    def test_valid_ipv4(self):
        req = Request(target="192.168.1.1")
        assert req.target == "192.168.1.1"

    def test_valid_cidr(self):
        req = Request(target="10.0.0.0/24")
        assert req.target == "10.0.0.0/24"

    def test_valid_range(self):
        req = Request(target="192.168.1.1-255")
        assert req.target == "192.168.1.1-255"

    def test_valid_ipv6(self):
        req = Request(target="::1")
        assert req.target == "::1"

    def test_valid_ipv6_full(self):
        req = Request(target="fe80::1")
        assert req.target == "fe80::1"

    def test_valid_ipv6_brackets(self):
        req = Request(target="[::1]")
        assert req.target == "[::1]"

    def test_whitespace_stripped(self):
        req = Request(target="  scanme.nmap.org  ")
        assert req.target == "scanme.nmap.org"

    def test_empty_target_rejected(self):
        with pytest.raises(ValidationError, match="target must not be empty"):
            Request(target="")

    def test_whitespace_only_rejected(self):
        with pytest.raises(ValidationError, match="target must not be empty"):
            Request(target="   ")

    def test_hyphen_prefix_rejected(self):
        with pytest.raises(ValidationError, match="must not start with a hyphen"):
            Request(target="-badarg")

    def test_shell_metacharacters_rejected(self):
        for bad in ["host;rm", "host&cmd", "host|pipe", "host$(cmd)", "host`cmd`"]:
            with pytest.raises(ValidationError, match="invalid characters"):
                Request(target=bad)

    def test_too_long_rejected(self):
        with pytest.raises(ValidationError, match="exceeds maximum length"):
            Request(target="a" * 300)

    def test_comma_separated_targets(self):
        req = Request(target="10.0.0.1,10.0.0.2")
        assert req.target == "10.0.0.1,10.0.0.2"

    def test_wildcard_target(self):
        req = Request(target="192.168.1.*")
        assert req.target == "192.168.1.*"
