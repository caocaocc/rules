import urllib.request
import re
import os
import json
import logging
import subprocess
from urllib.error import URLError

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def fetch_content(url):
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return response.read().decode('utf-8').splitlines()
    except URLError as e:
        logging.error(f"Error fetching content from {url}: {e}")
        return []

def is_valid_domain(domain):
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return re.match(pattern, domain) is not None

def process_line(line):
    line = line.strip()
    
    # 移除注释
    line = re.split(r'[#；]', line)[0].strip()
    
    if not line:
        return None, None

    # 处理 DOMAIN
    if line.startswith('DOMAIN,'):
        parts = line.split(',', 1)
        if len(parts) > 1:
            domain = parts[1].strip()
            return 'domain', domain if is_valid_domain(domain) else None
    
    # 处理 DOMAIN-SUFFIX
    elif line.startswith('DOMAIN-SUFFIX,'):
        parts = line.split(',', 1)
        if len(parts) > 1:
            domain = parts[1].strip()
            return 'domain-suffix', domain if is_valid_domain(domain) else None
    
    # 处理以点开头的域名后缀
    elif line.startswith('.'):
        domain = line.lstrip('.')
        return 'domain-suffix', domain if is_valid_domain(domain) else None
    
    # 处理普通域名
    elif is_valid_domain(line):
        return 'domain', line

    logging.warning(f"Unrecognized line format: {line}")
    return None, None

def process_urls(urls):
    domains = set()
    domain_suffixes = set()

    for url in urls:
        logging.info(f"Processing URL: {url}")
        content = fetch_content(url)
        for line in content:
            domain_type, processed = process_line(line)
            if processed:
                if domain_type == 'domain':
                    domains.add(processed)
                elif domain_type == 'domain-suffix':
                    domain_suffixes.add(processed)
            else:
                logging.debug(f"Skipped line: {line}")

    return sorted(domains), sorted(domain_suffixes)

def write_txt(domains, domain_suffixes, filename):
    try:
        content = []
        content.extend(domains)
        content.extend(f"+.{suffix}" for suffix in domain_suffixes)
        with open(filename, 'w') as f:
            f.write('\n'.join(content))
        logging.info(f"Wrote TEXT format to {filename}")
    except IOError as e:
        logging.error(f"Error writing to file {filename}: {e}")

def write_list(domains, domain_suffixes, filename):
    try:
        content = []
        content.extend(f"DOMAIN,{domain}" for domain in domains)
        content.extend(f"DOMAIN-SUFFIX,{suffix}" for suffix in domain_suffixes)
        with open(filename, 'w') as f:
            f.write('\n'.join(content))
        logging.info(f"Wrote LIST format to {filename}")
    except IOError as e:
        logging.error(f"Error writing to file {filename}: {e}")

def write_yaml(domains, domain_suffixes, filename):
    try:
        content = ["payload:"]
        content.extend(f"  - '{domain}'" for domain in domains)
        content.extend(f"  - '+.{suffix}'" for suffix in domain_suffixes)
        with open(filename, 'w') as f:
            f.write('\n'.join(content))
        logging.info(f"Wrote YAML format to {filename}")
    except IOError as e:
        logging.error(f"Error writing to file {filename}: {e}")

def write_json(domains, domain_suffixes, filename):
    data = {
        "version": 1,
        "rules": [
            {
                "domain": list(domains),
                "domain_suffix": list(domain_suffixes)
            }
        ]
    }
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logging.info(f"Wrote JSON format to {filename}")
    except IOError as e:
        logging.error(f"Error writing to file {filename}: {e}")

def install_sing_box():
    try:
        cmd = 'curl -fsSL "https://raw.githubusercontent.com/caocaocc/scripts/main/sing-box-install.sh" | bash'
        subprocess.run(cmd, shell=True, check=True, executable='/bin/bash')
        logging.info("Sing-box installed successfully")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error installing sing-box: {e}")

def install_mihomo():
    try:
        cmd = 'curl -fsSL "https://raw.githubusercontent.com/caocaocc/scripts/main/mihomo-install.sh" | bash'
        subprocess.run(cmd, shell=True, check=True, executable='/bin/bash')
        logging.info("Mihomo installed successfully")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error installing mihomo: {e}")

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
            output_file = 'rule-set/geosite-cdn.srs'
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
            output_file = 'rule-set/geosite-cdn.mrs'
            subprocess.run(f'mihomo convert-ruleset domain yaml {yaml_files_str} {output_file}', shell=True, check=True)
            logging.info(f"Mihomo rules converted successfully to {output_file}")
        else:
            logging.warning("No YAML files found in rule-set directory for mihomo conversion")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error converting mihomo rules: {e}")

def main():
    # 确保 rule-set 目录存在
    os.makedirs('rule-set', exist_ok=True)

    urls = [
        "https://raw.githubusercontent.com/SukkaW/Surge/refs/heads/master/Source/domainset/cdn.conf",
        "https://raw.githubusercontent.com/SukkaW/Surge/refs/heads/master/Source/non_ip/cdn.conf"
    ]

    domains, domain_suffixes = process_urls(urls)

    if not domains and not domain_suffixes:
        logging.error("No valid domains found. Check the source URLs and their content.")
        return

    # 写入 rule-set 目录下的文件
    write_txt(domains, domain_suffixes, 'rule-set/geosite-cdn.txt')
    write_list(domains, domain_suffixes, 'rule-set/geosite-cdn.list')
    write_yaml(domains, domain_suffixes, 'rule-set/geosite-cdn.yaml')
    write_json(domains, domain_suffixes, 'rule-set/geosite-cdn.json')

    # 安装 sing-box 和 mihomo
    install_sing_box()
    install_mihomo()

    # 编译和转换规则
    compile_sing_box_rules()
    convert_mihomo_rules()

if __name__ == "__main__":
    main()
