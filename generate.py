import json
import os
from urllib.request import urlopen
from urllib.error import URLError
from urllib.parse import urlparse

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
    
    for url in urls:
        lines = download_content(url)
        for line in lines:
            line = line.strip()
            if line.startswith('DOMAIN,'):
                domains.add(line.split(',')[1])
            elif line.startswith('DOMAIN-SUFFIX,'):
                domain_suffixes.add(line.split(',')[1])
            elif line.startswith('.'):
                domain_suffixes.add(line[1:])
            else:
                parsed = urlparse(line)
                if parsed.netloc:
                    domains.add(parsed.netloc)
                elif parsed.path:
                    domains.add(parsed.path)
    
    return sorted(domains), sorted(domain_suffixes)

def process_urls(config):
    for output_base, urls in config.items():
        domains, domain_suffixes = extract_domains(urls)
        
        # Create full path including any subdirectories
        directory = os.path.dirname(output_base)
        
        # Create subdirectories if they don't exist
        os.makedirs(directory, exist_ok=True)
        
        # Generate files for each supported format
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
    # Configuration: output base path as key, list of URLs as value
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
