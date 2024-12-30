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

def process_lines(lines: List[str]) -> List[str]:
    ip_list = []
    for line in lines:
        line = line.split('#')[0].strip()
        if not line:
            continue
        line = re.sub(r'^(IP-CIDR,|IP-CIDR6,)', '', line)
        try:
            ip_network = ipaddress.ip_network(line)
            ip_list.append(str(ip_network))
        except ValueError:
            continue
    return ip_list

def sort_ip_list(ip_list: List[str]) -> List[str]:
    ipv4_list = []
    ipv6_list = []
    for ip in ip_list:
        if ':' in ip:
            ipv6_list.append(ip)
        else:
            ipv4_list.append(ip)
    
    sorted_ipv4 = sorted(ipv4_list, key=lambda x: ipaddress.IPv4Network(x))
    sorted_ipv6 = sorted(ipv6_list, key=lambda x: ipaddress.IPv6Network(x))
    
    return sorted_ipv4 + sorted_ipv6

def extract_ip_cidrs(urls: List[str]) -> Tuple[List[str], List[str]]:
    all_ip_cidrs = []
    
    for url in urls:
        lines = fetch_content(url) if url.startswith('http') else url.splitlines()
        all_ip_cidrs.extend(process_lines(lines))
    
    sorted_cidrs = sort_ip_list(all_ip_cidrs)
    ipv4_cidrs = [cidr for cidr in sorted_cidrs if ':' not in cidr]
    ipv6_cidrs = [cidr for cidr in sorted_cidrs if ':' in cidr]
    
    return ipv4_cidrs, ipv6_cidrs

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
