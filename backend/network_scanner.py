import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, Any

def run_network_sweep(cidr: str) -> Dict[str, Any]:
    """
    Runs an Nmap Fast Scan (-F) across a CIDR block or comma-separated IPs.
    Outputs as XML, then parses it into a JSON topology structure.
    """
    cmd = [
        "docker", "run", "--rm",
        "--network=host",
        "instrumentisto/nmap",
        "-n", "-F", "-T4", "--min-rate", "1000", "--max-retries", "1", "-oX", "-", 
        cidr
    ]
    
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0 and '<nmaprun' not in proc.stdout:
            return {"error": "Failed to run Nmap network sweep.", "details": proc.stderr}
            
        xml_output = proc.stdout
        return parse_nmap_xml(xml_output, cidr)
    except subprocess.TimeoutExpired:
        return {"error": "Network sweep timed out after 300 seconds. The target subnet might be too large or heavily rate-limiting."}
    except Exception as e:
        return {"error": f"Error during sweep: {str(e)}"}

def parse_nmap_xml(xml_output: str, target: str) -> Dict[str, Any]:
    hosts_up_count = 0
    hosts_list = []
    
    try:
        # Find the start of the XML
        start = xml_output.find("<?xml")
        if start != -1:
            xml_output = xml_output[start:]
            
        root = ET.fromstring(xml_output)
        for host in root.findall("host"):
            status_elem = host.find("status")
            if status_elem is not None and status_elem.get("state") == "up":
                hosts_up_count += 1
                
                # Get IP
                ip_addr = ""
                for address in host.findall("address"):
                    if address.get("addrtype") == "ipv4" or address.get("addrtype") == "ipv6":
                        ip_addr = address.get("addr", "")
                        break
                
                # Get hostname mapped from ptr if exists
                hostname = ""
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    for hname in hostnames.findall("hostname"):
                        hostname = hname.get("name", "")
                        if hostname: break
                
                # Get open ports
                open_ports = []
                ports = host.find("ports")
                if ports is not None:
                    for port in ports.findall("port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            port_id = port.get("portid", "")
                            proto = port.get("protocol", "")
                            svc = port.find("service")
                            svc_name = svc.get("name", "unknown") if svc is not None else "unknown"
                            open_ports.append({"port": port_id, "protocol": proto, "service": svc_name})
                            
                hosts_list.append({
                    "ip": ip_addr,
                    "hostname": hostname,
                    "open_ports": open_ports
                })
                
    except ET.ParseError:
        return {"error": "Failed to parse Nmap XML output."}
        
    return {
        "target": target,
        "scan_tool": "nmap_network_sweep",
        "hosts_up": hosts_up_count,
        "hosts": hosts_list
    }
