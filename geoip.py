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
        time.sleep(2 ** attempt)
    return []

def remove_comments(lines: List[str]) -> List[str]:
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith(('#', ';'))]

def parse_ip_line(line: str) -> Tuple[Set[str], Set[str]]:
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
            if ':' in match:
                ipaddress.IPv6Network(match)
                ipv6_cidrs.add(match)
            else:
                print(f"Skipping potential IPv4 address in IPv6 parsing: {match}")
        except ValueError:
            print(f"Invalid IPv6 CIDR: {match}")
    
    return ipv4_cidrs, ipv6_cidrs

def extract_ip_cidrs(urls: List[str]) -> Tuple[List[str], List[str]]:
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
    return sorted(cidrs, key=lambda x: (ipaddress.ip_network(x).network_address, ipaddress.ip_network(x).prefixlen))

def write_json(ipv4_cidrs: List[str], ipv6_cidrs: List[str], filename: str) -> None:
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
    with open(filename, 'w') as f:
        for cidr in ipv4_cidrs:
            f.write(f"IP-CIDR,{cidr}\n")
        for cidr in ipv6_cidrs:
            f.write(f"IP-CIDR6,{cidr}\n")

def write_txt(ipv4_cidrs: List[str], ipv6_cidrs: List[str], filename: str) -> None:
    with open(filename, 'w') as f:
        for cidr in ipv4_cidrs + ipv6_cidrs:
            f.write(f"{cidr}\n")

def write_yaml(ipv4_cidrs: List[str], ipv6_cidrs: List[str], filename: str) -> None:
    with open(filename, 'w') as f:
        f.write("payload:\n")
        for cidr in ipv4_cidrs + ipv6_cidrs:
            f.write(f"  - '{cidr}'\n")

def convert_to_srs(json_file: str) -> None:
    if 'geoip' in json_file:
        srs_file = json_file.rsplit('.', 1)[0] + '.srs'
        try:
            subprocess.run(["sing-box", "rule-set", "compile", json_file, "-o", srs_file], check=True)
            print(f"Converted {json_file} to {srs_file}")
        except subprocess.CalledProcessError as e:
            print(f"Error converting {json_file} to SRS: {e}")
        except FileNotFoundError:
            print("Error: 'sing-box' command not found. Make sure it's installed and in your PATH.")

def convert_to_mrs(yaml_file: str) -> None:
    if 'geoip' in yaml_file:
        mrs_file = yaml_file.rsplit('.', 1)[0] + '.mrs'
        try:
            subprocess.run(["mihomo", "convert-ruleset", "ipcidr", "yaml", yaml_file, mrs_file], check=True)
            print(f"Converted {yaml_file} to {mrs_file}")
        except subprocess.CalledProcessError as e:
            print(f"Error converting {yaml_file} to MRS: {e}")
        except FileNotFoundError:
            print("Error: 'mihomo' command not found. Make sure it's installed and in your PATH.")

def process_urls(config: Dict[str, List[str]]) -> None:
    for output_base, urls in config.items():
        ipv4_cidrs, ipv6_cidrs = extract_ip_cidrs(urls)
        
        if not ipv4_cidrs and not ipv6_cidrs:
            print(f"Warning: No valid CIDRs found for {output_base}")
            continue
        
        directory = os.path.dirname(output_base)
        os.makedirs(directory, exist_ok=True)
        
        write_json(ipv4_cidrs, ipv6_cidrs, f"{output_base}.json")
        write_list(ipv4_cidrs, ipv6_cidrs, f"{output_base}.list")
        write_txt(ipv4_cidrs, ipv6_cidrs, f"{output_base}.txt")
        write_yaml(ipv4_cidrs, ipv6_cidrs, f"{output_base}.yaml")
        
        print(f"Successfully generated files for {output_base}")
        
        convert_to_srs(f"{output_base}.json")
        convert_to_mrs(f"{output_base}.yaml")

def main() -> None:
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
