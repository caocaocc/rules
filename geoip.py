import json
import os
import re
import time
from typing import List, Set, Tuple, Dict
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import ipaddress
import subprocess
import glob

def fetch_content(url: str, max_retries: int = 3) -> List[str]:
    """Fetch content from a given URL with retries."""
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    for attempt in range(max_retries):
        try:
            req = Request(url, headers=headers)
            with urlopen(req) as response:
                return response.read().decode('utf-8').splitlines()
        except (HTTPError, URLError) as e:
            print(f"Error downloading {url}: {e}")
            if attempt == max_retries - 1:
                print(f"Max retries reached. Skipping {url}")
                return []
        time.sleep(2 ** attempt)  # Exponential backoff
    return []

def remove_comments(lines: List[str]) -> List[str]:
    """Remove comments and empty lines."""
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith(('#', ';'))]

def parse_ip_line(line: str) -> Tuple[Set[str], Set[str]]:
    """Parse a single line and extract IPv4 and IPv6 CIDRs."""
    ipv4_cidrs = set()
    ipv6_cidrs = set()
    
    ipv4_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})\b'
    ipv6_pattern = r'\b([0-9a-fA-F:]+/\d{1,3})\b'
    
    ipv4_matches = re.findall(ipv4_pattern, line)
    ipv6_matches = re.findall(ipv6_pattern, line)
    
    for match in ipv4_matches:
        try:
            ipaddress.IPv4Network(match)
            ipv4_cidrs.add(match)
        except ValueError:
            print(f"Invalid IPv4 CIDR: {match}")
    
    for match in ipv6_matches:
        try:
            ipaddress.IPv6Network(match)
            ipv6_cidrs.add(match)
        except ValueError:
            print(f"Invalid IPv6 CIDR: {match}")
    
    return ipv4_cidrs, ipv6_cidrs

def extract_ip_cidrs(urls: List[str]) -> Tuple[List[str], List[str]]:
    """Extract IPv4 and IPv6 CIDRs from given URLs or content."""
    all_ipv4_cidrs = set()
    all_ipv6_cidrs = set()
    
    for url in urls:
        lines = fetch_content(url) if url.startswith('http') else url.splitlines()
        lines = remove_comments(lines)
        for line in lines:
            ipv4_cidrs, ipv6_cidrs = parse_ip_line(line)
            all_ipv4_cidrs.update(ipv4_cidrs)
            all_ipv6_cidrs.update(ipv6_cidrs)
    
    return sort_ip_cidrs(list(all_ipv4_cidrs)), sort_ip_cidrs(list(all_ipv6_cidrs))

def sort_ip_cidrs(cidrs: List[str]) -> List[str]:
    """Sort IP CIDRs."""
    return sorted(cidrs, key=lambda x: (ipaddress.ip_network(x).network_address, ipaddress.ip_network(x).prefixlen))

def write_json(ipv4_cidrs: List[str], ipv6_cidrs: List[str], filename: str) -> None:
    """Write IP CIDRs to a JSON file."""
    data = {
        "version": 1,
        "rules": [
            {
                "ip_cidr": ipv4_cidrs + ipv6_cidrs
            }
        ]
    }
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

def write_list(ipv4_cidrs: List[str], ipv6_cidrs: List[str], filename: str) -> None:
    """Write IP CIDRs to a list file."""
    with open(filename, 'w') as f:
        for cidr in ipv4_cidrs:
            f.write(f"IP-CIDR,{cidr}\n")
        for cidr in ipv6_cidrs:
            f.write(f"IP-CIDR6,{cidr}\n")

def write_txt(ipv4_cidrs: List[str], ipv6_cidrs: List[str], filename: str) -> None:
    """Write IP CIDRs to a text file."""
    with open(filename, 'w') as f:
        for cidr in ipv4_cidrs + ipv6_cidrs:
            f.write(f"{cidr}\n")

def write_yaml(ipv4_cidrs: List[str], ipv6_cidrs: List[str], filename: str) -> None:
    """Write IP CIDRs to a YAML file."""
    with open(filename, 'w') as f:
        f.write("payload:\n")
        for cidr in ipv4_cidrs + ipv6_cidrs:
            f.write(f"  - '{cidr}'\n")

def convert_files() -> None:
    """Convert JSON files to SRS and YAML files to MRS."""
    for json_file in glob.glob('rule-set/**/*.json', recursive=True):
        srs_file = json_file.rsplit('.', 1)[0] + '.srs'
        try:
            subprocess.run(f"sing-box rule-set compile {json_file} -o {srs_file}", shell=True, check=True)
            print(f"Converted {json_file} to {srs_file}")
        except subprocess.CalledProcessError as e:
            print(f"Error converting {json_file} to SRS: {e}")

    for yaml_file in glob.glob('rule-set/**/*.yaml', recursive=True):
        mrs_file = yaml_file.rsplit('.', 1)[0] + '.mrs'
        try:
            subprocess.run(f"mihomo convert-ruleset ipcidr yaml {yaml_file} {mrs_file}", shell=True, check=True)
            print(f"Converted {yaml_file} to {mrs_file}")
        except subprocess.CalledProcessError as e:
            print(f"Error converting {yaml_file} to MRS: {e}")

def process_urls(config: Dict[str, List[str]]) -> None:
    """Process URLs and generate output files."""
    for output_base, urls in config.items():
        ipv4_cidrs, ipv6_cidrs = extract_ip_cidrs(urls)
        
        if not ipv4_cidrs and not ipv6_cidrs:
            print(f"Warning: No valid CIDRs found for {output_base}")
            continue
        
        directory = os.path.dirname(output_base)
        os.makedirs(directory, exist_ok=True)
        
        base_name = output_base
        write_json(ipv4_cidrs, ipv6_cidrs, f"{base_name}.json")
        write_list(ipv4_cidrs, ipv6_cidrs, f"{base_name}.list")
        write_txt(ipv4_cidrs, ipv6_cidrs, f"{base_name}.txt")
        write_yaml(ipv4_cidrs, ipv6_cidrs, f"{base_name}.yaml")
        print(f"Successfully generated files for {output_base}")

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
    convert_files()

if __name__ == "__main__":
    main()
