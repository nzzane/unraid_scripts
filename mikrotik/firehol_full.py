#!/usr/bin/env python3
"""
FireHOL IPv4 Incremental Updater
---------------------------------
Fetches FireHOL blocklist IPs from multiple URLs, merges and deduplicates them,
compares with your previously stored IP list, and outputs a RouterOS (.rsc) script
that only adds newly discovered IPs and removes IPs that no longer appear in the lists.

Also sends a Discord webhook message with stats about the update.

Usage:
  1) pip install requests
  2) python firehol_full.py [--dry-run]
  3) Import 'fire_update.rsc' on MikroTik.
"""

import argparse
import ipaddress
import json
import os
import stat
import time
from datetime import datetime

import requests

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------

# Directory where final RSC files and previous IP records live
FINAL_DIR = "/path/to/output"

RSC_FILE_FULL   = os.path.join(FINAL_DIR, "firehol_full.rsc")
RSC_FILE_UPDATE = os.path.join(FINAL_DIR, "fire_update.rsc")
PREV_IPS_FILE   = os.path.join(FINAL_DIR, "fire_prev_ipsV2.txt")

# Discord webhook
DISCORD_WEBHOOK_URL = "YOUR_DISCORD_WEBHOOK_URL"

# Excluded networks — uses proper overlap checking, so e.g. 10.1.2.3 is caught by 10.0.0.0/8
EXCLUDED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),        # This network
    ipaddress.ip_network("10.0.0.0/8"),        # RFC1918 private
    ipaddress.ip_network("100.64.0.0/10"),     # Shared address space (RFC6598)
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local
    ipaddress.ip_network("172.16.0.0/12"),     # RFC1918 private
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1 (documentation)
    ipaddress.ip_network("192.168.0.0/16"),    # RFC1918 private
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2 (documentation)
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3 (documentation)
    ipaddress.ip_network("224.0.0.0/3"),       # Multicast + reserved
    # Cloudflare public DNS — avoid accidental blocking
    ipaddress.ip_network("1.1.1.1/32"),
    ipaddress.ip_network("1.0.0.1/32"),
    # Uncomment to exclude all Cloudflare IP ranges:
    ipaddress.ip_network("103.21.244.0/22"),
    ipaddress.ip_network("103.22.200.0/22"),
    ipaddress.ip_network("104.16.0.0/13"),
    ipaddress.ip_network("104.24.0.0/14"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("173.245.48.0/20"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("198.41.128.0/17"),
]

# Blocklist sources: (url, display_name)
BLOCKLISTS = [
    ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "FireHOL_L1"),
    ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset", "FireHOL_L2"),
    # ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset", "FireHOL_L3"),
    ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_webclient.netset", "FireHOL_WebClient"),
    ("https://iplists.firehol.org/files/iblocklist_ciarmy_malicious.netset", "CINS_Malicious"),
    ("https://iplists.firehol.org/files/bruteforceblocker.ipset", "BruteForceBlocker"),
    ("https://iplists.firehol.org/files/et_compromised.ipset", "ET_Compromised"),
    ("https://iplists.firehol.org/files/et_dshield.netset", "ET_dshield"),
    ("https://iplists.firehol.org/files/blocklist_de_strongips.ipset", "DE_StrongIP"),
    ("https://iplists.firehol.org/files/cybercrime.ipset", "Cybercrime"),
    ("https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "ET_Compromised_Extra"),
    ("https://cinsscore.com/list/ci-badguys.txt", "CINS_Army"),
    ("https://www.binarydefense.com/banlist.txt", "BD_Artillery"),
]

FETCH_RETRIES = 3
FETCH_TIMEOUT = 60

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


# ------------------------------------------------------------------------------
# Fetch helpers
# ------------------------------------------------------------------------------

def fetch_url(url):
    """Fetch URL text with retry/backoff. Returns text or None on failure."""
    for attempt in range(FETCH_RETRIES):
        try:
            resp = requests.get(url, timeout=FETCH_TIMEOUT)
            resp.raise_for_status()
            return resp.text
        except requests.exceptions.RequestException as exc:
            if attempt < FETCH_RETRIES - 1:
                wait = 2 ** attempt
                log(f"  Attempt {attempt + 1} failed, retrying in {wait}s ({exc})")
                time.sleep(wait)
            else:
                log(f"  All {FETCH_RETRIES} attempts failed: {exc}")
    return None


def parse_ipv4_entries(text):
    """
    Extract valid IPv4 addresses/CIDRs from raw text.
    Skips comment lines and inline comments.
    """
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        # Strip inline comments
        for sep in ("#", ";"):
            if sep in line:
                line = line[:line.index(sep)].strip()
        if not line:
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                results.append(str(net))  # normalise (e.g. 1.2.3.4/32 not 1.2.3.4)
        except ValueError:
            pass
    return results


# ------------------------------------------------------------------------------
# Exclusion checking
# ------------------------------------------------------------------------------

def is_excluded(entry):
    """Return True if the entry overlaps with any excluded network."""
    try:
        net = ipaddress.ip_network(entry, strict=False)
        return any(net.overlaps(excl) for excl in EXCLUDED_NETWORKS)
    except ValueError:
        return True  # Unparseable — skip


# ------------------------------------------------------------------------------
# File I/O
# ------------------------------------------------------------------------------

def load_previous_ips(filename):
    """Load {ip: comment} from a previous-run file."""
    if not os.path.exists(filename):
        return {}
    ip_dict = {}
    with open(filename) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(" ", 1)
            if len(parts) == 2:
                ip_dict[parts[0]] = parts[1]
    return ip_dict


def save_ips_to_file(filename, ip_dict):
    """Write {ip: comment} atomically."""
    tmp = filename + ".tmp"
    with open(tmp, "w") as f:
        for ip, comment in sorted(ip_dict.items()):
            f.write(f"{ip} {comment}\n")
    os.replace(tmp, filename)


# ------------------------------------------------------------------------------
# RSC writers
# ------------------------------------------------------------------------------

def _safe_comment(comment):
    return comment.replace('"', "").replace(" ", "_")


def write_full_rsc(rsc_file, ip_dict):
    """Full reset script — removes all firehol entries then re-adds everything."""
    tmp = rsc_file + ".tmp"
    with open(tmp, "w") as f:
        f.write("/ip firewall address-list remove [find list=firehol]\n")
        for ip, comment in sorted(ip_dict.items()):
            f.write(
                f'/ip firewall address-list add list=firehol'
                f' address={ip} comment="{_safe_comment(comment)}"\n'
            )
    os.replace(tmp, rsc_file)


def write_incremental_rsc(rsc_file, old_ip_dict, new_ip_dict):
    """Write only the add/remove delta between old and new IP sets."""
    old_ips = set(old_ip_dict)
    new_ips = set(new_ip_dict)

    to_add    = sorted(new_ips - old_ips)
    to_remove = sorted(old_ips - new_ips)

    tmp = rsc_file + ".tmp"
    with open(tmp, "w") as f:
        for ip in to_add:
            comment = _safe_comment(new_ip_dict[ip])
            f.write(
                f'/ip firewall address-list add list=firehol'
                f' address={ip} comment="{comment}"\n'
            )
        for ip in to_remove:
            f.write(f'/ip firewall address-list remove [find list=firehol address={ip}]\n')
    os.replace(tmp, rsc_file)

    return len(to_add), len(to_remove)


# ------------------------------------------------------------------------------
# Discord
# ------------------------------------------------------------------------------

def send_discord_message(webhook_url, message):
    try:
        requests.post(
            webhook_url,
            data=json.dumps({"content": message}),
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
    except requests.exceptions.RequestException as exc:
        log(f"Discord notification failed: {exc}")


# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="FireHOL IPv4 incremental updater")
    parser.add_argument("--dry-run", action="store_true",
                        help="Fetch and process lists but do not write any files or send Discord message")
    args = parser.parse_args()

    os.makedirs(FINAL_DIR, exist_ok=True)

    # 1) Load previous run
    old_ip_dict = load_previous_ips(PREV_IPS_FILE)
    log(f"Loaded {len(old_ip_dict)} IPs from previous run.")

    # 2) Fetch and build new IP dict
    new_ip_dict = {}
    fetch_failures = []

    for url, list_name in BLOCKLISTS:
        log(f"Fetching {list_name} ...")
        text = fetch_url(url)
        if text is None:
            fetch_failures.append(list_name)
            continue

        entries = parse_ipv4_entries(text)
        added = 0
        skipped = 0
        for entry in entries:
            if is_excluded(entry):
                skipped += 1
                continue
            if entry not in new_ip_dict:
                new_ip_dict[entry] = list_name
            else:
                new_ip_dict[entry] += f",{list_name}"
            added += 1

        log(f"  {added} entries added, {skipped} excluded.")

    log(f"Total unique IPv4 entries: {len(new_ip_dict)}")

    if args.dry_run:
        old_ips = set(old_ip_dict)
        new_ips = set(new_ip_dict)
        log(f"[DRY RUN] Would add {len(new_ips - old_ips)}, remove {len(old_ips - new_ips)} IPs.")
        log("[DRY RUN] No files written.")
        return

    # 3) Write full reset script
    write_full_rsc(RSC_FILE_FULL, new_ip_dict)
    log(f"Full RSC written: {RSC_FILE_FULL}")

    # 4) Write incremental update script
    added_count, removed_count = write_incremental_rsc(RSC_FILE_UPDATE, old_ip_dict, new_ip_dict)
    log(f"Incremental RSC written: {RSC_FILE_UPDATE}")
    log(f"Delta — Added: {added_count}, Removed: {removed_count}")

    # 5) Save new state for next run
    save_ips_to_file(PREV_IPS_FILE, new_ip_dict)

    # 6) Stats for Discord
    update_size_kb = os.stat(RSC_FILE_UPDATE)[stat.ST_SIZE] // 1024
    with open(RSC_FILE_UPDATE) as f:
        line_count = sum(1 for _ in f)

    failures_note = ""
    if fetch_failures:
        failures_note = f"\nFailed sources ({len(fetch_failures)}): {', '.join(fetch_failures)}"

    discord_message = (
        f"**FireHOL IPv4 update complete**\n"
        f"Total IPs: {len(new_ip_dict):,} | Update: {update_size_kb} KB, {line_count} lines\n"
        f"Added: {added_count:,} | Removed: {removed_count:,}{failures_note}"
    )
    send_discord_message(DISCORD_WEBHOOK_URL, discord_message)
    log("Discord notification sent.")


if __name__ == "__main__":
    main()
