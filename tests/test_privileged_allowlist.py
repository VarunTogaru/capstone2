import pytest
from app.connect.privileged_allowlist import validate_privileged_command


class TestValidatePrivilegedCommand:
    def test_valid_basic_tcp(self):
        errors = validate_privileged_command(["nmap", "-sT", "-oX", "-", "scanme.nmap.org"])
        assert errors == []

    def test_valid_syn_scan(self):
        errors = validate_privileged_command(["nmap", "-sS", "-oX", "-", "10.0.0.1"])
        assert errors == []

    def test_valid_with_timing(self):
        errors = validate_privileged_command(["nmap", "-sS", "-T4", "-oX", "-", "target"])
        assert errors == []

    def test_valid_with_ports(self):
        errors = validate_privileged_command(["nmap", "-sT", "-p", "22,80,443", "-oX", "-", "target"])
        assert errors == []

    def test_valid_with_script_separate(self):
        errors = validate_privileged_command(["nmap", "--script", "safe", "-oX", "-", "target"])
        assert errors == []

    def test_valid_with_script_inline(self):
        errors = validate_privileged_command(["nmap", "--script=default,safe", "-oX", "-", "target"])
        assert errors == []

    def test_valid_multiple_allowed_flags(self):
        errors = validate_privileged_command(
            ["nmap", "-sS", "-sV", "-Pn", "-n", "--open", "--reason", "-oX", "-", "target"]
        )
        assert errors == []

    def test_valid_all_timing_levels(self):
        for level in range(6):
            errors = validate_privileged_command(["nmap", f"-T{level}", "-oX", "-", "target"])
            assert errors == [], f"-T{level} should be allowed"

    def test_blocked_flag_decoy(self):
        errors = validate_privileged_command(["nmap", "-D", "decoy", "-oX", "-", "target"])
        assert any("'-D'" in e for e in errors)

    def test_blocked_flag_spoof_source(self):
        errors = validate_privileged_command(["nmap", "-S", "10.0.0.5", "-oX", "-", "target"])
        assert any("'-S'" in e for e in errors)

    def test_blocked_flag_proxies(self):
        errors = validate_privileged_command(["nmap", "--proxies", "socks4://127.0.0.1:9050", "-oX", "-", "target"])
        assert any("'--proxies'" in e for e in errors)

    def test_blocked_output_flags(self):
        for flag in ["-oN", "-oS", "-oG", "-oA"]:
            errors = validate_privileged_command(["nmap", flag, "file", "-oX", "-", "target"])
            assert any(f"'{flag}'" in e for e in errors), f"{flag} should be blocked"

    def test_non_nmap_prefix(self):
        errors = validate_privileged_command(["notmap", "-sT", "target"])
        assert errors == ["Privileged command must start with nmap"]

    def test_empty_args(self):
        errors = validate_privileged_command([])
        assert errors == ["Privileged command must start with nmap"]

    def test_disallowed_script_category(self):
        errors = validate_privileged_command(["nmap", "--script", "exploit", "-oX", "-", "target"])
        assert any("not allowed" in e for e in errors)

    def test_disallowed_inline_script_category(self):
        errors = validate_privileged_command(["nmap", "--script=exploit", "-oX", "-", "target"])
        assert any("not allowed" in e for e in errors)

    def test_mixed_valid_invalid_script_categories(self):
        errors = validate_privileged_command(["nmap", "--script", "safe,exploit", "-oX", "-", "target"])
        assert any("exploit" in e for e in errors)

    def test_oX_without_dash(self):
        errors = validate_privileged_command(["nmap", "-oX", "/tmp/out.xml", "target"])
        assert any("stdout" in e for e in errors)

    def test_unknown_flag(self):
        errors = validate_privileged_command(["nmap", "--foo", "-oX", "-", "target"])
        assert any("'--foo'" in e for e in errors)

    def test_flag_value_missing(self):
        errors = validate_privileged_command(["nmap", "-p"])
        assert any("requires a value" in e for e in errors)

    def test_traceroute_allowed(self):
        errors = validate_privileged_command(["nmap", "--traceroute", "-oX", "-", "target"])
        assert errors == []

    def test_os_detection_allowed(self):
        errors = validate_privileged_command(["nmap", "-O", "-oX", "-", "target"])
        assert errors == []

    def test_aggressive_allowed(self):
        errors = validate_privileged_command(["nmap", "-A", "-oX", "-", "target"])
        assert errors == []
