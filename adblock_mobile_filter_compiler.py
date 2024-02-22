import re
import requests
from datetime import datetime
from typing import List, Set, Tuple


def is_valid_domain_name(domain: str) -> bool:
    """Checks if a string is a valid domain name."""
    domain_regex = re.compile(
        r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
    )
    return bool(domain_regex.match(domain))


def filter_content_by_allowlist_domains(filter_content: List[str], allowlist_domains: Set[str]) -> List[str]:
    """Removes allowed domains from the filter_content."""
    filtered_content = [
        '\n'.join(set(parse_filter_content(content)) - allowlist_domains)
        for content in filter_content
    ]
    return filtered_content


def parse_filter_content(content: str) -> Set[str]:
    """Parses a filter content into AdBlock rules."""
    adblock_rules = set()
    for line in content.split('\n'):
        if line.strip() and line[0] not in ('#', '!') and not line.startswith('||www.'):
            # Check if line follows AdBlock syntax, else create new rule
            if line.startswith('||') and line.endswith('^'):
                adblock_rules.add(line)
            else:
                parts = line.split()
                domain = parts[-1]
                if is_valid_domain_name(domain):
                    adblock_rules.add(f'||{domain}^')
    return adblock_rules


def generate_combined_filter_content(filter_content: List[str]) -> Tuple[str, int, int, int]:
    """Generates combined filter content by eliminating duplicates and redundant rules."""
    adblock_rules_set = set()
    base_domain_set = set()
    duplicates_removed = 0
    redundant_rules_removed = 0

    for content in filter_content:
        adblock_rules = parse_filter_content(content)
        for rule in adblock_rules:
            domain = rule[2:-1]  # Remove '||' and '^'
            base_domain = '.'.join(domain.split('.')[-3:])  # Get the base domain (last three parts)
            if rule not in adblock_rules_set and base_domain not in base_domain_set:
                adblock_rules_set.add(rule)
                base_domain_set.add(base_domain)
            else:
                if rule in adblock_rules_set:
                    duplicates_removed += 1
                else:
                    redundant_rules_removed += 1

    sorted_rules = sorted(adblock_rules_set)
    header = generate_filter_header(len(sorted_rules), duplicates_removed, redundant_rules_removed)
    return '\n'.join([header, '', *sorted_rules]), duplicates_removed, redundant_rules_removed


def generate_filter_header(domain_count: int, duplicates_removed: int, redundant_rules_removed: int) -> str:
    """Generates header with specific domain count, removed duplicates, and compressed domains information."""
    date_time = datetime.now().strftime('%d-%m-%Y %H:%M:%S %Z')  # Includes date, time, and timezone
    return f"""# Title: sagittaurius's Blocklist
# Description: Python script that generates adblock filters by combining blocklists, host files, and domain lists.
# Last Modified: {date_time}
# Expires: 1 day
# Domain Count: {domain_count}
# Duplicates Removed: {duplicates_removed}
# Domains Compressed: {redundant_rules_removed}
#=================================================================="""


def process_filter_content_with_allowlist_domains(filter_content: List[str], allowlist_domains: List[str]) -> List[str]:
    """Processes the allowed domains before filtering the content."""
    filtered_content = filter_content_by_allowlist_domains(filter_content, set(allowlist_domains))
    return filtered_content

def generate_combined_filter_file():
    """Main function to fetch blocklists and generate a combined filter."""
    blocklist_urls = [
        "https://hostfiles.frogeye.fr/firstparty-only-trackers.txt",
        "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
        "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Malware",
        "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Scam",
        "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Tracking"
    ]
    allowlist_urls = ["https://raw.githubusercontent.com/sagittaurius/main/main/whitelist"]

    filter_content = [requests.get(url).text for url in blocklist_urls]
    allowlist_domains = requests.get(allowlist_urls[0]).text.split('\n')

    filtered_content = process_filter_content_with_allowlist_domains(filter_content, allowlist_domains)
    filtered_content, _, _, = generate_combined_filter_content(filtered_content)

    # Write the filter content to a file
    with open('mobile.blocklist.txt', 'w') as f:
        f.write(filtered_content)


if __name__ == "__main__":
    generate_combined_filter_file()
