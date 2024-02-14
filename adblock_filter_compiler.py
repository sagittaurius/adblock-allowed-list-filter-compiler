import re
import requests
from datetime import datetime


def is_valid_domain(domain):
    """Checks if a string is a valid domain."""
    domain_regex = re.compile(
        r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
    )
    return bool(domain_regex.match(domain))


def parse_hosts_file(content):
    """Parses a host file content into AdBlock rules."""
    allowlist_domains = set()
    blocklist_domains = set()
    adblock_rules = set()
    for line in content.split("\n"):
        line = line.strip()

        # Ignore comments and empty lines
        if not line or line[0] in ("#", "!"):
            continue

        # Check if line follows AdBlock syntax, else create new rule
        if line.startswith("||") and line.endswith("^"):
            allowlist_domains.add(line)
            blocklist_domains.add(line)
            adblock_rules.add(line)
        else:
            parts = line.split()
            domain = parts[-1]
            if is_valid_domain(domain):
                allowlist_domains.add(f"||{domain}^")
                blocklist_domains.add(f"||{domain}^")
                adblock_rules.add(f'||{domain}^')
    return allowlist_domains, blocklist_domains,adblock_rules


def generate_filter(file_contents):
    """Generates filter content from file_contents by eliminating duplicates and redundant rules."""
    adblock_rules_set = set()
    base_domain_set = set()
    duplicates_removed = 0
    redundant_rules_removed = 0

    for content in file_contents:
        adblock_rules = parse_hosts_file(content)
        for rule in adblock_rules:
            domain = rule[2:-1]  # Remove '||' and '^'
            base_domain = ".".join(domain.split(".")[-3:])  # Get the base domain (last two parts)
            if rule not in adblock_rules_set and base_domain not in base_domain_set:
                adblock_rules_set.add(rule)
                base_domain_set.add(base_domain)
            else:
                if rule in adblock_rules_set:
                    duplicates_removed += 1
                else:
                    redundant_rules_removed += 1

    sorted_rules = sorted(adblock_rules_set)
    header = generate_header(len(sorted_rules), duplicates_removed, redundant_rules_removed)
    return "\n".join([header, "", *sorted_rules]), duplicates_removed, redundant_rules_removed


def generate_header(domain_count, duplicates_removed, redundant_rules_removed):
    """Generates header with specific domain count, removed duplicates, and compressed domains information."""
    date_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")  # Includes date, time, and timezone
    return f"""# Title: sagittaurius's Blocklist
# Description: Python script that generates adblock filters by combining blocklists, host files, and domain lists.
# Last Modified: {date_time}
# Expires: 1 day
# Domain Count: {domain_count}
# Duplicates Removed: {duplicates_removed}
# Domains Compressed: {redundant_rules_removed}
#=================================================================="""


def generate_blocklist():
    blocklist_urls = [
        "https://v.firebog.net/hosts/Prigent-Crypto.txt",
        "https://v.firebog.net/hosts/Prigent-Malware.txt",
        "https://hostfiles.frogeye.fr/firstparty-only-trackers.txt",
        "https://hblock.molinero.dev/hosts_adblock.txt",
        "https://gitlab.com/quidsup/notrack-blocklists/-/raw/master/trackers.hosts",
        "https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt",
        "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt",
        "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt",
        "https://raw.githubusercontent.com/neodevpro/neodevhost/master/adblocker",
        "https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild2_big.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt",
        "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Malware",
        "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Scam",
        "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Tracking",
        "https://raw.githubusercontent.com/mitchellkrogza/Ultimate.Hosts.Blacklist/master/domains/domains2.list",
        "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
        "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/malware",
        "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Phishing-Angriffe",
        "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Formats/GoodbyeAds-AdBlock-Filter.txt",
        "https://raw.githubusercontent.com/AdroitAdorKhan/antipopads-re/master/formats/domains.txt",
        "https://raw.githubusercontent.com/bongochong/CombinedPrivacyBlockLists/master/NoFormatting/cpbl-ctld.txt",
    ]
    allowlist_urls = ["https://raw.githubusercontent.com/sagittaurius/main/main/whitelist"]

    # Fetch allowlist domains
allowlist_domains = [requests.get(url).text for url in allowlist_urls]
    # Fetch blocklist domains
blocklist_domains = [requests.get(url).text for url in blocklist_urls]


    # Write the filter content to a file
    with open("blocklist.txt", "w") as f:
        f.write(filtered_content)


file_contents = blocklist_domains - allowlist_domains


filter_content, _, _ = generate_filter(file_contents)


if __name__ == "__main__":
    generate_blocklist()
