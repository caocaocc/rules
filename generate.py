import urllib.request
import re
import os
import json
import logging
import subprocess
from urllib.error import HTTPError, URLError
import ipaddress

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def fetch_content(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.read().decode('utf-8').splitlines()
    except HTTPError as e:
        logging.error(f"HTTP Error {e.code} while fetching {url}: {e.reason}")
    except URLError as e:
        logging.error(f"URL Error while fetching {url}: {e.reason}")
    except Exception as e:
        logging.error(f"Unexpected error while fetching {url}: {str(e)}")
    return []

def is_valid_domain(domain):
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return re.match(pattern, domain) is not None

def is_valid_ip_cidr(ip_cidr):
    try:
        ipaddress.ip_network(ip_cidr, strict=False)
        return True
    except ValueError:
        return False

def process_line(line):
    line = line.strip()
    
    if line.startswith('#') or not line:
        return None, None

    if line.startswith('DOMAIN,'):
        parts = line.split(',', 1)
        if len(parts) > 1:
            domain = parts[1].strip()
            if is_valid_domain(domain):
                return 'DOMAIN', domain

    if line.startswith('DOMAIN-SUFFIX,'):
        parts = line.split(',', 1)
        if len(parts) > 1:
            domain_suffix = parts[1].strip()
            if is_valid_domain(domain_suffix):
                return 'DOMAIN-SUFFIX', domain_suffix

    if line.startswith('IP-CIDR,') or line.startswith('IP-CIDR6,'):
        parts = line.split(',', 1)
        if len(parts) > 1:
            ip_cidr = parts[1].strip()
            if is_valid_ip_cidr(ip_cidr):
                return 'IP-CIDR', ip_cidr

    if is_valid_ip_cidr(line):
        return 'IP-CIDR', line

    logging.debug(f"Unrecognized line format: {line}")
    return None, None

def process_urls(urls):
    ip_cidrs = set()
    domains = set()
    domain_suffixes = set()

    for url in urls:
        logging.info(f"Processing URL: {url}")
        content = fetch_content(url)
        for line in content:
            rule_type, value = process_line(line)
            if rule_type == 'IP-CIDR':
                ip_cidrs.add(value)
            elif rule_type == 'DOMAIN':
                domains.add(value)
            elif rule_type == 'DOMAIN-SUFFIX':
                domain_suffixes.add(value)

    return sorted(ip_cidrs), sorted(domains), sorted(domain_suffixes)

def write_txt(items, filename):
    try:
        with open(filename, 'w') as f:
            f.write('\n'.join(items))
        logging.info(f"Wrote TEXT format to {filename}")
    except IOError as e:
        logging.error(f"Error writing to file {filename}: {e}")

def write_list(domains, domain_suffixes, ip_cidrs, filename):
    try:
        content = []
        content.extend(f"DOMAIN,{domain}" for domain in domains)
        content.extend(f"DOMAIN-SUFFIX,{suffix}" for suffix in domain_suffixes)
        content.extend(f"IP-CIDR,{ip_cidr}" for ip_cidr in ip_cidrs)
        with open(filename, 'w') as f:
            f.write('\n'.join(content))
        logging.info(f"Wrote LIST format to {filename}")
    except IOError as e:
        logging.error(f"Error writing to file {filename}: {e}")

def write_yaml(items, filename):
    try:
        content = ["payload:"]
        content.extend(f"  - '{item}'" for item in items)
        with open(filename, 'w') as f:
            f.write('\n'.join(content))
        logging.info(f"Wrote YAML format to {filename}")
    except IOError as e:
        logging.error(f"Error writing to file {filename}: {e}")

def write_json(items, filename, key):
    data = {
        "version": 1,
        "rules": [
            {
                key: list(items)
            }
        ]
    }
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logging.info(f"Wrote JSON format to {filename}")
    except IOError as e:
        logging.error(f"Error writing to file {filename}: {e}")

def write_files(ip_cidrs, domains, domain_suffixes, base_filename, item_type):
    if item_type == 'ip_cidr':
        if not ip_cidrs:
            logging.warning(f"No valid IP CIDRs found for {base_filename}")
            return
        logging.info(f"Found {len(ip_cidrs)} unique IP CIDRs for {base_filename}")
        write_txt(ip_cidrs, f'rule-set/{base_filename}.txt')
        write_list([], [], ip_cidrs, f'rule-set/{base_filename}.list')
        write_yaml(ip_cidrs, f'rule-set/{base_filename}.yaml')
        write_json(ip_cidrs, f'rule-set/{base_filename}.json', 'ip_cidr')
    elif item_type == 'domain':
        if not domains and not domain_suffixes:
            logging.warning(f"No valid domains or domain suffixes found for {base_filename}")
            return
        logging.info(f"Found {len(domains)} unique domains and {len(domain_suffixes)} unique domain suffixes for {base_filename}")
        write_txt(domains + domain_suffixes, f'rule-set/{base_filename}.txt')
        write_list(domains, domain_suffixes, [], f'rule-set/{base_filename}.list')
        write_yaml(domains + domain_suffixes, f'rule-set/{base_filename}.yaml')
        write_json(domains + domain_suffixes, f'rule-set/{base_filename}.json', 'domain')

def is_command_available(command):
    try:
        subprocess.run([command, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except FileNotFoundError:
        return False

def compile_sing_box_rules():
    if not is_command_available("sing-box"):
        logging.error("sing-box is not installed or not in PATH")
        return
    try:
        json_files = [f for f in os.listdir('rule-set') if f.endswith('.json')]
        if json_files:
            json_files_str = ' '.join([f"rule-set/{f}" for f in json_files])
            output_file = 'rule-set/geosite.srs'
            subprocess.run(f'sing-box rule-set compile {json_files_str} -o {output_file}', shell=True, check=True)
            logging.info(f"Sing-box rules compiled successfully to {output_file}")
        else:
            logging.warning("No JSON files found in rule-set directory for sing-box compilation")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error compiling sing-box rules: {e}")

def convert_mihomo_rules():
    if not is_command_available("mihomo"):
        logging.error("mihomo is not installed or not in PATH")
        return
    try:
        yaml_files = [f for f in os.listdir('rule-set') if f.endswith('.yaml')]
        if yaml_files:
            yaml_files_str = ' '.join([f"rule-set/{f}" for f in yaml_files])
            output_file = 'rule-set/geosite.dat'
            subprocess.run(f'mihomo convert-ruleset domain yaml {yaml_files_str} {output_file}', shell=True, check=True)
            logging.info(f"Mihomo rules converted successfully to {output_file}")
        else:
            logging.warning("No YAML files found in rule-set directory for mihomo conversion")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error converting mihomo rules: {e}")

def process_and_write_files(config):
    urls = config["urls"]
    base_filename = config["base_filename"]
    data_type = config["type"]

    ip_cidrs, domains, domain_suffixes = process_urls(urls)

    write_files(ip_cidrs, domains, domain_suffixes, base_filename, data_type)

def main():
    # 确保 rule-set 目录存在
    os.makedirs('rule-set', exist_ok=True)

    # 配置 URL 和对应的基础文件名
    configs = [
        {
            "urls": ["https://ruleset.skk.moe/List/ip/lan.conf"],
            "base_filename": "geoip-private",
            "type": "ip_cidr"
        },
        {
            "urls": [
                "https://raw.githubusercontent.com/SukkaW/Surge/refs/heads/master/Source/domainset/cdn.conf",
                "https://raw.githubusercontent.com/SukkaW/Surge/refs/heads/master/Source/non_ip/cdn.conf"
            ],
            "base_filename": "geosite-cdn",
            "type": "domain"
        },
        {
            "urls": ["https://core.telegram.org/resources/cidr.txt"],
            "base_filename": "geoip-telegram",
            "type": "ip_cidr"
        },
    ]

    for config in configs:
        process_and_write_files(config)

    # 编译和转换规则
    compile_sing_box_rules()
    convert_mihomo_rules()

if __name__ == "__main__":
    main()
