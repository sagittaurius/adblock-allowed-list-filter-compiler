import re
import requests
import json
from datetime import datetime


def is_valid_domain(domain):
    """Checks if a string is a valid domain."""
    domain_regex = re.compile(
        r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
    )
    return bool(domain_regex.match(domain))


def remove_allowlist(filter_content, allowlist_domains):
    """Removes allowed domains from the filter_content."""
    filtered_content = []

    for content in filter_content:
        adblock_rules = parse_hosts_file(content)
        filtered_rules = set()

        for rule in adblock_rules:
            domain = rule[2:-1]  # Remove '||' and '^'
            if domain not in allowlist_domains:
                filtered_rules.add(rule)

        filtered_content.append('\n'.join(filtered_rules))

    return filtered_content


def parse_hosts_file(content):
    """Parses a host file content into AdBlock rules."""
    adblock_rules = set()

    for line in content.split('\n'):
        line = line.strip()

        # Ignore comments and empty lines
        if not line or line[0] in ('#', '!'):
            continue

        # Check if line follows AdBlock syntax, else create new rule
        if line.startswith('||') and line.endswith('^'):
            adblock_rules.add(line)
        else:
            parts = line.split()
            domain = parts[-1]
            if is_valid_domain(domain):
                adblock_rules.add(f'||{domain}^')

    return adblock_rules


def generate_filter_content(filter_content):
    """Generates filter content from filter_content by eliminating duplicates and redundant rules."""
    filtered_rules = set()
    adblock_rules_set = set()
    base_domain_set = set()
    duplicates_removed = 0
    redundant_rules_removed = 0
    allowed_domains = 0

    for content in filter_content:
        adblock_rules = parse_hosts_file(content)
        for rule in adblock_rules:
            domain = rule[2:-1]  # Remove '||' and '^'
            base_domain = '.'.join(domain.split('.')[-3:])  # Get the base domain (last two parts)
            if rule not in adblock_rules_set and base_domain not in base_domain_set:
                adblock_rules_set.add(rule)
                base_domain_set.add(base_domain)
            else:
                if rule in adblock_rules_set:
                    duplicates_removed += 1
                else:
                    redundant_rules_removed += 1
                if rule in filtered_rules:
                    allowed_domains += 1

    sorted_rules = sorted(adblock_rules_set)
    header = generate_header(len(sorted_rules), duplicates_removed, redundant_rules_removed, allowed_domains)
    return '\n'.join([header, '', *sorted_rules]), duplicates_removed, redundant_rules_removed, allowed_domains


def generate_header(domain_count, duplicates_removed, redundant_rules_removed, allowed_domains):
    """Generates header with specific domain count, removed duplicates, and compressed domains information."""
    date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')  # Includes date, time, and timezone
    return f"""# Title: sagittaurius's Blocklist
# Description: Python script that generates adblock filters by combining blocklists, host files, and domain lists.
# Last Modified: {date_time}
# Expires: 1 day
# Domain Count: {domain_count}
# Duplicates Removed: {duplicates_removed}
# Domains Compressed: {redundant_rules_removed}
# Allowed Domain: {allowed_domains}
#=================================================================="""


def process_allowlist(filter_content, allowlist_domains):
    """Processes the allowed domains before filtering the content."""
    filtered_content = remove_allowlist(filter_content, allowlist_domains)
    return filtered_content


def main():
    # Main function to fetch blocklists and generate a combined filter.
    with open('config.json') as f:
        config = json.load(f)

    blocklist_urls = config['blocklist_urls']
    allowlist_urls = config['allowlist_urls']

    filter_content = [requests.get(url).text for url in blocklist_urls]
    allowlist_domains = [requests.get(url).text for url in allowlist_urls]

    filtered_content = process_allowlist(filter_content, allowlist_domains)
    filtered_content, _, _, _ = generate_filter_content(filtered_content)

    # Write the filter content to a file
    with open('blocklist.txt', 'w') as f:
        f.write(filtered_content)


if __name__ == "__main__":
    main()
