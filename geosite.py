import json
import os
import re
import time
from typing import List, Set, Tuple, Dict
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
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

def parse_domain_line(line: str) -> Tuple[Set[str], Set[str]]:
    domains = set()
    domain_suffixes = set()
    
    patterns = {
        'domain': re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'),
        'domain_suffix': re.compile(r'^(\.|(\+\.))'),
        'domain_line': re.compile(r'^DOMAIN,(.+)$'),
        'domain_suffix_line': re.compile(r'^DOMAIN-SUFFIX,(.+)$'),
        'server_line': re.compile(r'^server=/([^/]+)/'),
    }
    
    line = line.strip()
    
    if patterns['domain'].match(line):
        domains.add(line)
    elif patterns['domain_suffix'].match(line):
        domain_suffixes.add(line.lstrip('.+'))
    elif patterns['domain_line'].match(line):
        domains.add(patterns['domain_line'].match(line).group(1))
    elif patterns['domain_suffix_line'].match(line):
        domain_suffixes.add(patterns['domain_suffix_line'].match(line).group(1))
    elif patterns['server_line'].match(line):
        domains.add(patterns['server_line'].match(line).group(1))
    
    return domains, domain_suffixes

def extract_domains(urls: List[str]) -> Tuple[List[str], List[str]]:
    all_domains = set()
    all_domain_suffixes = set()
    
    for url in urls:
        lines = fetch_content(url) if url.startswith('http') else url.splitlines()
        for line in lines:
            domains, domain_suffixes = parse_domain_line(line)
            all_domains.update(domains)
            all_domain_suffixes.update(domain_suffixes)
    
    return sorted(all_domains), sorted(all_domain_suffixes)

def write_json(domains: List[str], domain_suffixes: List[str], filename: str) -> None:
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

def write_list(domains: List[str], domain_suffixes: List[str], filename: str) -> None:
    with open(filename, 'w') as f:
        for domain in domains:
            f.write(f"DOMAIN,{domain}\n")
        for suffix in domain_suffixes:
            f.write(f"DOMAIN-SUFFIX,{suffix}\n")

def write_txt(domains: List[str], domain_suffixes: List[str], filename: str) -> None:
    with open(filename, 'w') as f:
        for domain in domains:
            f.write(f"{domain}\n")
        for suffix in domain_suffixes:
            f.write(f"+.{suffix}\n")

def write_yaml(domains: List[str], domain_suffixes: List[str], filename: str) -> None:
    with open(filename, 'w') as f:
        f.write("payload:\n")
        for domain in domains:
            f.write(f"  - '{domain}'\n")
        for suffix in domain_suffixes:
            f.write(f"  - '+.{suffix}'\n")
def write_snippet(domains: List[str], domain_suffixes: List[str], filename: str) -> None:
    with open(filename, 'w') as f:
        for domain in domains:
            f.write(f"host, {domain}\n")
        for suffix in domain_suffixes:
            f.write(f"host-suffix, {suffix}\n")
            
def convert_to_srs(json_file: str) -> None:
    if 'geosite' in json_file:
        srs_file = json_file.rsplit('.', 1)[0] + '.srs'
        try:
            subprocess.run(['sing-box', 'rule-set', 'compile', json_file, '-o', srs_file], check=True)
            print(f"Converted {json_file} to {srs_file}")
        except subprocess.CalledProcessError as e:
            print(f"Error converting {json_file} to SRS: {e}")
        except FileNotFoundError:
            print("Error: 'sing-box' command not found. Make sure it's installed and in your PATH.")

def convert_to_mrs(yaml_file: str) -> None:
    if 'geosite' in yaml_file:
        mrs_file = yaml_file.rsplit('.', 1)[0] + '.mrs'
        try:
            subprocess.run(['mihomo', 'convert-ruleset', 'domain', 'yaml', yaml_file, mrs_file], check=True)
            print(f"Converted {yaml_file} to {mrs_file}")
        except subprocess.CalledProcessError as e:
            print(f"Error converting {yaml_file} to MRS: {e}")
        except FileNotFoundError:
            print("Error: 'mihomo' command not found. Make sure it's installed and in your PATH.")

def process_urls(config: Dict[str, List[str]]) -> None:
    for output_base, urls in config.items():
        domains, domain_suffixes = extract_domains(urls)
        
        if not domains and not domain_suffixes:
            print(f"Warning: No valid domains found for {output_base}")
            continue
        
        directory = os.path.dirname(output_base)
        os.makedirs(directory, exist_ok=True)
        
        write_json(domains, domain_suffixes, f"{output_base}.json")
        write_list(domains, domain_suffixes, f"{output_base}.list")
        write_txt(domains, domain_suffixes, f"{output_base}.txt")
        write_yaml(domains, domain_suffixes, f"{output_base}.yaml")
        write_snippet(domains, domain_suffixes, f"{output_base}.snippet")

        convert_to_srs(f"{output_base}.json")
        convert_to_mrs(f"{output_base}.yaml")
        
        print(f"Successfully generated files for {output_base}")

def download_geosite_files(base_url: str, base_names: List[str], output_dir: str, extensions: List[str] = ['.json', '.txt', '.yaml', '.list', '.snippet', '.srs', '.mrs']) -> None:
    """
    Download multiple geoip files from a given base URL using wget and save them to the specified output directory.
    
    :param base_url: The base URL where the files are located
    :param base_names: A list of base file names (without extensions)
    :param output_dir: The directory where the downloaded files will be saved
    :param extensions: A list of file extensions to download (default includes all common extensions)
    """
    os.makedirs(output_dir, exist_ok=True)
    
    for base_name in base_names:
        for ext in extensions:
            file_name = f"{base_name}{ext}"
            url = f"{base_url}/{file_name}"
            output_path = os.path.join(output_dir, file_name)
            
            try:
                # Using wget to download the file
                subprocess.run(["wget", "-q", "--show-progress", "-O", output_path, url], check=True)
                print(f"Successfully downloaded: {file_name}")
            
            except subprocess.CalledProcessError as e:
                print(f"Error downloading {file_name}: {e}")
            except Exception as e:
                print(f"Unexpected error while downloading {file_name}: {e}")
                
def main() -> None:
    config = {
        "rule-set/geosite-cdn": [
            "https://raw.githubusercontent.com/SukkaW/Surge/refs/heads/master/Source/domainset/cdn.conf",
            "https://raw.githubusercontent.com/SukkaW/Surge/refs/heads/master/Source/non_ip/cdn.conf"
        ]
    }
    
    process_urls(config)

    # Add the new functionality
    base_url = "https://raw.githubusercontent.com/caocaocc/geosite/rule-set"
    base_names = ["geosite-private", "geosite-cn", "geosite-geolocation-!cn", "geosite-netflix", "geosite-openai", "geosite-paypal", "geosite-category-remote-control"]
    output_dir = "rule-set"
    
    download_geosite_files(base_url, base_names, output_dir)

if __name__ == "__main__":
    main()
