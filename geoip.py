import json
import os
import re
from typing import List, Set, Tuple, Dict
from urllib.request import urlopen
from urllib.error import URLError
import ipaddress

def fetch_content(url: str) -> List[str]:
    """Fetch content from a given URL."""
    try:
        with urlopen(url) as response:
            return response.read().decode('utf-8').splitlines()
    except URLError as e:
        print(f"Error downloading {url}: {e}")
        return []

def parse_line(line: str) -> Tuple[Set[str], Set[str]]:
    """Parse a single line and extract IPv4 and IPv6 CIDR."""
    ipv4_cidrs = set()
    ipv6_cidrs = set()
    
    patterns = {
        'ip_cidr': re.compile(r'^IP-CIDR,(.+)$'),
        'ip_cidr6': re.compile(r'^IP-CIDR6,(.+)$'),
        'plain_cidr': re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}|[0-9a-fA-F:]+/\d{1,3})$'),
    }
    
    line = line.strip()
    
    if patterns['ip_cidr'].match(line):
        cidr = patterns['ip_cidr'].match(line).group(1)
        ipv4_cidrs.add(cidr)
    elif patterns['ip_cidr6'].match(line):
        cidr = patterns['ip_cidr6'].match(line).group(1)
        ipv6_cidrs.add(cidr)
    elif patterns['plain_cidr'].match(line):
        try:
            ip_network = ipaddress.ip_network(line)
            if ip_network.version == 4:
                ipv4_cidrs.add(str(ip_network))
            else:
                ipv6_cidrs.add(str(ip_network))
        except ValueError:
            # Invalid IP network, skip this line
            pass
    
    return ipv4_cidrs, ipv6_cidrs

def extract_ip_cidrs(urls: List[str]) -> Tuple[List[str], List[str]]:
    """Extract IPv4 and IPv6 CIDRs from given URLs or content."""
    all_ipv4_cidrs = set()
    all_ipv6_cidrs = set()
    
    for url in urls:
        lines = fetch_content(url) if url.startswith('http') else url.splitlines()
        for line in lines:
            ipv4_cidrs, ipv6_cidrs = parse_line(line)
            all_ipv4_cidrs.update(ipv4_cidrs)
            all_ipv6_cidrs.update(ipv6_cidrs)
    
    return sorted(all_ipv4_cidrs), sorted(all_ipv6_cidrs)

def write_json(ipv4_cidrs: List[str], ipv6_cidrs: List[str], filename: str) -> None:
    """Write IPv4 and IPv6 CIDRs to a JSON file."""
    data = {
        "version": 1,
        "rules": [
            {
                "ip_cidr": ipv4_cidrs,
                "ip_cidr6": ipv6_cidrs
            }
        ]
    }
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

def write_list(ipv4_cidrs: List[str], ipv6_cidrs: List[str], filename: str) -> None:
    """Write IPv4 and IPv6 CIDRs to a list file."""
    with open(filename, 'w') as f:
        for cidr in ipv4_cidrs:
            f.write(f"IP-CIDR,{cidr}\n")
        for cidr in ipv6_cidrs:
            f.write(f"IP-CIDR6,{cidr}\n")

def write_txt(ipv4_cidrs: List[str], ipv6_cidrs: List[str], filename: str) -> None:
    """Write IPv4 and IPv6 CIDRs to a text file."""
    with open(filename, 'w') as f:
        for cidr in ipv4_cidrs:
            f.write(f"{cidr}\n")
        for cidr in ipv6_cidrs:
            f.write(f"{cidr}\n")

def write_yaml(ipv4_cidrs: List[str], ipv6_cidrs: List[str], filename: str) -> None:
    """Write IPv4 and IPv6 CIDRs to a YAML file."""
    with open(filename, 'w') as f:
        f.write("payload:\n")
        for cidr in ipv4_cidrs:
            f.write(f"  - '{cidr}'\n")
        for cidr in ipv6_cidrs:
            f.write(f"  - '{cidr}'\n")

def process_urls(config: Dict[str, List[str]]) -> None:
    """Process URLs and generate output files."""
    for output_base, urls in config.items():
        ipv4_cidrs, ipv6_cidrs = extract_ip_cidrs(urls)
        
        directory = os.path.dirname(output_base)
        os.makedirs(directory, exist_ok=True)
        
        base_name = output_base
        write_json(ipv4_cidrs, ipv6_cidrs, f"{base_name}.json")
        write_list(ipv4_cidrs, ipv6_cidrs, f"{base_name}.list")
        write_txt(ipv4_cidrs, ipv6_cidrs, f"{base_name}.txt")
        write_yaml(ipv4_cidrs, ipv6_cidrs, f"{base_name}.yaml")

def main() -> None:
    """Main function to run the IP CIDR extractor and formatter."""
    config = {
        "rule-set/geoip-private": [
            "https://ruleset.skk.moe/List/ip/lan.conf"
        ],
        "rule-set/geoip-telegram": [
            "https://core.telegram.org/resources/cidr.txt"
        ]
    }
    
    process_urls(config)

if __name__ == "__main__":
    main()
