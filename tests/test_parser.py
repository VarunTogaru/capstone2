import pytest
from app.connect.parser import parse_nmap_xml

MINIMAL_XML = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -oX - scanme.nmap.org"
         start="1234567890" startstr="Tue Feb 13 23:31:30 2009"
         version="7.94" xmloutputversion="1.05">
  <scaninfo type="connect" protocol="tcp" numservices="1" services="80"/>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="45.33.32.156" addrtype="ipv4"/>
    <hostnames><hostname name="scanme.nmap.org" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1234567900" elapsed="10" timestr="Tue Feb 13 23:31:40 2009"
              summary="Nmap done at Tue Feb 13 23:31:40 2009; 1 IP address (1 host up)"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
"""

TWO_HOSTS_XML = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" xmloutputversion="1.05">
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1234567900"/>
    <hosts up="2" down="0" total="2"/>
  </runstats>
</nmaprun>
"""

OS_DETECTION_XML = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" xmloutputversion="1.05">
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.4" accuracy="95">
        <osclass vendor="Linux" osfamily="Linux" osgen="5.X" type="general purpose"/>
      </osmatch>
    </os>
  </host>
  <runstats><finished/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""

SCRIPT_XML = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" xmloutputversion="1.05">
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http"/>
        <script id="http-title" output="Test Page"/>
      </port>
    </ports>
  </host>
  <runstats><finished/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""

EMPTY_HOSTS_XML = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" xmloutputversion="1.05">
  <runstats>
    <finished time="1234567900"/>
    <hosts up="0" down="1" total="1"/>
  </runstats>
</nmaprun>
"""


class TestParseNmapXml:
    def test_minimal_xml(self):
        result = parse_nmap_xml(MINIMAL_XML)
        assert "metadata" in result
        assert "runstats" in result
        assert "hosts" in result
        assert len(result["hosts"]) == 1

        host = result["hosts"][0]
        assert host["address"] == "45.33.32.156"
        assert len(host["ports"]) == 1
        assert host["ports"][0]["port"] == "80"
        assert host["ports"][0]["proto"] == "tcp"
        assert host["ports"][0]["state"] == "open"
        assert host["ports"][0]["service"] == "http"

    def test_metadata(self):
        result = parse_nmap_xml(MINIMAL_XML)
        meta = result["metadata"]
        assert meta["scanner"] == "nmap"
        assert meta["version"] == "7.94"
        assert len(meta["scaninfo"]) == 1
        assert meta["scaninfo"][0]["type"] == "connect"

    def test_runstats(self):
        result = parse_nmap_xml(MINIMAL_XML)
        stats = result["runstats"]
        assert stats["hosts"]["up"] == "1"
        assert stats["hosts"]["total"] == "1"
        assert "summary" in stats["finished"]

    def test_two_hosts(self):
        result = parse_nmap_xml(TWO_HOSTS_XML)
        assert len(result["hosts"]) == 2
        assert result["hosts"][0]["address"] == "10.0.0.1"
        assert result["hosts"][1]["address"] == "10.0.0.2"

    def test_os_detection(self):
        result = parse_nmap_xml(OS_DETECTION_XML)
        host = result["hosts"][0]
        assert len(host["os"]["matches"]) == 1
        assert host["os"]["matches"][0]["name"] == "Linux 5.4"
        assert host["os"]["matches"][0]["accuracy"] == "95"
        assert len(host["os"]["classes"]) == 1
        assert host["os"]["classes"][0]["vendor"] == "Linux"

    def test_script_output(self):
        result = parse_nmap_xml(SCRIPT_XML)
        port = result["hosts"][0]["ports"][0]
        assert len(port["scripts"]) == 1
        assert port["scripts"][0]["id"] == "http-title"
        assert port["scripts"][0]["output"] == "Test Page"

    def test_empty_host_list(self):
        result = parse_nmap_xml(EMPTY_HOSTS_XML)
        assert result["hosts"] == []

    def test_invalid_xml_raises(self):
        with pytest.raises(RuntimeError, match="Invalid Nmap XML output"):
            parse_nmap_xml("this is not xml")

    def test_hostnames(self):
        result = parse_nmap_xml(MINIMAL_XML)
        host = result["hosts"][0]
        assert len(host["hostnames"]) == 1
        assert host["hostnames"][0]["name"] == "scanme.nmap.org"

    def test_host_status(self):
        result = parse_nmap_xml(MINIMAL_XML)
        host = result["hosts"][0]
        assert host["status"]["state"] == "up"
