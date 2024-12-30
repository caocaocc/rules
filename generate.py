import json
import os
import re
from urllib.request import urlopen
from urllib.error import URLError

def download_content(url):
    try:
        with urlopen(url) as response:
            return response.read().decode('utf-8').splitlines()
    except URLError as e:
        print(f"Error downloading {url}: {e}")
        return []

def extract_domains(urls):
    domains = set()
    domain_suffixes = set()
    
    domain_pattern = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    domain_suffix_pattern = re.compile(r'^(\.|(\+\.))')
    domain_line_pattern = re.compile(r'^DOMAIN,(.+)$')
    domain_suffix_line_pattern = re.compile(r'^DOMAIN-SUFFIX,(.+)$')

    for url in urls:
        lines = download_content(url) if url.startswith('http') else url.splitlines()
        for line in lines:
            line = line.strip()
            
            if domain_pattern.match(line):
                domains.add(line)
            elif domain_suffix_pattern.match(line):
                domain_suffixes.add(line.lstrip('.+'))
            elif domain_line_pattern.match(line):
                domains.add(domain_line_pattern.match(line).group(1))
            elif domain_suffix_line_pattern.match(line):
                domain_suffixes.add(domain_suffix_line_pattern.match(line).group(1))
    
    return sorted(domains), sorted(domain_suffixes)

def process_urls(config):
    for output_base, urls in config.items():
        domains, domain_suffixes = extract_domains(urls)
        
        directory = os.path.dirname(output_base)
        os.makedirs(directory, exist_ok=True)
        
        base_name = output_base
        write_json(domains, domain_suffixes, f"{base_name}.json")
        write_list(domains, domain_suffixes, f"{base_name}.list")
        write_txt(domains, domain_suffixes, f"{base_name}.txt")
        write_yaml(domains, domain_suffixes, f"{base_name}.yaml")

def write_json(domains, domain_suffixes, filename):
    data = {
        "version": 1,
        "rules": [
            {
                "domain": domains,
                "domain_suffix": domain_suffixes
            }
        ]
    }
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

def write_list(domains, domain_suffixes, filename):
    with open(filename, 'w') as f:
        for domain in domains:
            f.write(f"DOMAIN,{domain}\n")
        for suffix in domain_suffixes:
            f.write(f"DOMAIN-SUFFIX,{suffix}\n")

def write_txt(domains, domain_suffixes, filename):
    with open(filename, 'w') as f:
        for domain in domains:
            f.write(f"{domain}\n")
        for suffix in domain_suffixes:
            f.write(f"+.{suffix}\n")

def write_yaml(domains, domain_suffixes, filename):
    with open(filename, 'w') as f:
        f.write("payload:\n")
        for domain in domains:
            f.write(f"  - '{domain}'\n")
        for suffix in domain_suffixes:
            f.write(f"  - '+.{suffix}'\n")

def main():
    config = {
        "rule-set/geosite-cdn": [
            "https://raw.githubusercontent.com/SukkaW/Surge/refs/heads/master/Source/domainset/cdn.conf",
            "https://raw.githubusercontent.com/SukkaW/Surge/refs/heads/master/Source/non_ip/cdn.conf"
        ],
        "rule-set/geosite-apple-cn": [
            "https://raw.githubusercontent.com/SukkaW/Surge/refs/heads/master/Source/non_ip/apple_cn.conf"
        ]
    }
    
    process_urls(config)

if __name__ == "__main__":
    main()
