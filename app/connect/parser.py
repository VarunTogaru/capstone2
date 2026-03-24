from typing import Any, Dict, List, Optional
import xml.etree.ElementTree as ET


def _attrs(node: Optional[ET.Element]) -> Dict[str, str]:
    return dict(node.attrib) if node is not None else {}


def _parse_script_detail(node: ET.Element) -> Dict[str, Any]:
    detail: Dict[str, Any] = {
        "tag": node.tag,
        **dict(node.attrib),
    }
    text = (node.text or "").strip()
    if text:
        detail["text"] = text
    children = [_parse_script_detail(child) for child in list(node)]
    if children:
        detail["children"] = children
    return detail


def _parse_script_nodes(parent: Optional[ET.Element]) -> List[Dict[str, Any]]:
    if parent is None:
        return []
    scripts: List[Dict[str, Any]] = []
    for script in parent.findall("script"):
        entry: Dict[str, Any] = {
            "id": script.attrib.get("id"),
            "output": script.attrib.get("output"),
        }
        details = [_parse_script_detail(child) for child in list(script)]
        if details:
            entry["details"] = details
        scripts.append(entry)
    return scripts


def _parse_port_node(port_node: ET.Element) -> Dict[str, Any]:
    state_node = port_node.find("state")
    service_node = port_node.find("service")

    state = _attrs(state_node)
    service = _attrs(service_node)
    if service_node is not None:
        cpe_values = [(node.text or "").strip() for node in service_node.findall("cpe")]
        cpe_values = [value for value in cpe_values if value]
        if cpe_values:
            service["cpe"] = cpe_values

    return {
        # Backward-compatible keys used by current table renderer.
        "port": port_node.attrib.get("portid"),
        "proto": port_node.attrib.get("protocol"),
        "state": state.get("state"),
        "service": service.get("name"),
        # Extended detail keys.
        "state_detail": state,
        "service_detail": service,
        "scripts": _parse_script_nodes(port_node),
    }


def _parse_os_node(host_node: ET.Element) -> Dict[str, Any]:
    os_node = host_node.find("os")
    if os_node is None:
        return {}

    matches: List[Dict[str, Any]] = []
    classes: List[Dict[str, Any]] = []
    for osmatch in os_node.findall("osmatch"):
        match = dict(osmatch.attrib)
        osclasses = [dict(osclass.attrib) for osclass in osmatch.findall("osclass")]
        if osclasses:
            match["classes"] = osclasses
            classes.extend(osclasses)
        matches.append(match)

    ports_used = [dict(node.attrib) for node in os_node.findall("portused")]
    fingerprint = os_node.find("osfingerprint")
    fingerprint_value = fingerprint.attrib.get("fingerprint") if fingerprint is not None else None

    out: Dict[str, Any] = {
        "matches": matches,
        "classes": classes,
        "ports_used": ports_used,
    }
    if fingerprint_value:
        out["fingerprint"] = fingerprint_value
    return out


def _parse_trace_node(host_node: ET.Element) -> tuple[Dict[str, str], List[Dict[str, Any]]]:
    trace_node = host_node.find("trace")
    if trace_node is None:
        return {}, []
    hops: List[Dict[str, Any]] = []
    for hop in trace_node.findall("hop"):
        hops.append(dict(hop.attrib))
    return dict(trace_node.attrib), hops


def _parse_host_node(host_node: ET.Element) -> Dict[str, Any]:
    addresses = [dict(address.attrib) for address in host_node.findall("address")]
    primary_address = None
    for address in addresses:
        if address.get("addrtype") == "ipv4":
            primary_address = address.get("addr")
            break
    if primary_address is None and addresses:
        primary_address = addresses[0].get("addr")

    hostnames_node = host_node.find("hostnames")
    hostnames = []
    if hostnames_node is not None:
        for hostname in hostnames_node.findall("hostname"):
            hostnames.append(dict(hostname.attrib))

    ports_out: List[Dict[str, Any]] = []
    extraports_out: List[Dict[str, Any]] = []
    ports_node = host_node.find("ports")
    if ports_node is not None:
        for extra in ports_node.findall("extraports"):
            extra_out = dict(extra.attrib)
            reasons = [dict(reason.attrib) for reason in extra.findall("extrareasons")]
            if reasons:
                extra_out["reasons"] = reasons
            extraports_out.append(extra_out)
        for port in ports_node.findall("port"):
            ports_out.append(_parse_port_node(port))

    status = _attrs(host_node.find("status"))
    uptime = _attrs(host_node.find("uptime"))
    distance = _attrs(host_node.find("distance"))
    times = _attrs(host_node.find("times"))
    tcpsequence = _attrs(host_node.find("tcpsequence"))
    ipidsequence = _attrs(host_node.find("ipidsequence"))
    tcptssequence = _attrs(host_node.find("tcptssequence"))

    hostscripts = _parse_script_nodes(host_node.find("hostscript"))
    trace_meta, trace_hops = _parse_trace_node(host_node)
    os_info = _parse_os_node(host_node)

    output: Dict[str, Any] = {
        # Backward-compatible keys.
        "address": primary_address,
        "ports": ports_out,
        # Extended host data.
        "status": status,
        "addresses": addresses,
        "hostnames": hostnames,
        "extraports": extraports_out,
        "os": os_info,
        "uptime": uptime,
        "distance": distance,
        "times": times,
        "sequence": {
            "tcp": tcpsequence,
            "ipid": ipidsequence,
            "tcpts": tcptssequence,
        },
        "hostscripts": hostscripts,
        "trace_meta": trace_meta,
        "trace": trace_hops,
    }
    return output


def parse_nmap_xml(xml_text: str) -> Dict[str, Any]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise RuntimeError("Invalid Nmap XML output") from exc

    scaninfo = [dict(node.attrib) for node in root.findall("scaninfo")]
    runstats_node = root.find("runstats")
    runstats = {
        "finished": _attrs(runstats_node.find("finished")) if runstats_node is not None else {},
        "hosts": _attrs(runstats_node.find("hosts")) if runstats_node is not None else {},
    }

    metadata = {
        "scanner": root.attrib.get("scanner"),
        "args": root.attrib.get("args"),
        "start": root.attrib.get("start"),
        "startstr": root.attrib.get("startstr"),
        "version": root.attrib.get("version"),
        "xmloutputversion": root.attrib.get("xmloutputversion"),
        "scaninfo": scaninfo,
    }

    hosts = [_parse_host_node(host) for host in root.findall("host")]

    return {
        "metadata": metadata,
        "runstats": runstats,
        "hosts": hosts,
    }
