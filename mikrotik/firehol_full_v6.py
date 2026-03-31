#!/usr/bin/env python3
"""
FireHOL IPv6 Incremental Updater
----------------------------------
Fetches IPv6 blocklist entries from FireHOL and supplementary sources, merges and
deduplicates them, compares with your previously stored list, and outputs a
RouterOS (.rsc) script that only adds newly discovered entries and removes those
that no longer appear.

MikroTik uses '/ipv6 firewall address-list' for IPv6 — handled automatically.

Also sends a Discord webhook message with stats about the update.

Usage:
  1) pip install requests
  2) python firehol_full_v6.py [--dry-run]
  3) Import 'fire6_update.rsc' on MikroTik.

Notes:
  - Most FireHOL .netset/.ipset files are IPv4-only; this script filters them for
    any IPv6 entries they may contain and skips files with none.
  - The Spamhaus DROPv6 and Team Cymru fullbogons-ipv6 lists are the primary
    dedicated IPv6 sources.
  - The bogon list (Team Cymru) covers unallocated/reserved IPv6 space that should
    never appear as legitimate traffic. Comment it out if you find it too aggressive.
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

FINAL_DIR = "/path/to/output"

RSC_FILE_FULL   = os.path.join(FINAL_DIR, "firehol6_full.rsc")
RSC_FILE_UPDATE = os.path.join(FINAL_DIR, "fire6_update.rsc")
PREV_IPS_FILE   = os.path.join(FINAL_DIR, "fire6_prev_ips.txt")

DISCORD_WEBHOOK_URL = "YOUR_DISCORD_WEBHOOK_URL"

# Excluded IPv6 networks — reserved, private, and infrastructure ranges.
# Proper overlap checking is used, so any subnet of these will be caught.
EXCLUDED_NETWORKS = [
    ipaddress.ip_network("::/128"),            # Unspecified address
    ipaddress.ip_network("::1/128"),           # Loopback
    ipaddress.ip_network("::ffff:0:0/96"),     # IPv4-mapped addresses
    ipaddress.ip_network("::ffff:0:0:0/96"),   # IPv4-translated addresses
    ipaddress.ip_network("64:ff9b::/96"),      # NAT64 (RFC6052)
    ipaddress.ip_network("64:ff9b:1::/48"),    # NAT64 (RFC8215)
    ipaddress.ip_network("100::/64"),          # Discard prefix (RFC6666)
    ipaddress.ip_network("2001::/23"),         # IETF Protocol Assignments (includes Teredo 2001::/32)
    ipaddress.ip_network("2001:db8::/32"),     # Documentation (TEST-NET)
    ipaddress.ip_network("2002::/16"),         # 6to4 relay anycast
    ipaddress.ip_network("fc00::/7"),          # Unique-local (fd00::/8 etc.)
    ipaddress.ip_network("fe80::/10"),         # Link-local
    ipaddress.ip_network("ff00::/8"),          # Multicast
    # Cloudflare public DNS IPv6 — avoid accidental blocking
    ipaddress.ip_network("2606:4700:4700::1111/128"),
    ipaddress.ip_network("2606:4700:4700::1001/128"),
    # Uncomment to exclude all Cloudflare IPv6 ranges:
    # ipaddress.ip_network("2606:4700::/32"),
    # ipaddress.ip_network("2803:f800::/32"),
    # ipaddress.ip_network("2405:b500::/32"),
    # ipaddress.ip_network("2405:8100::/32"),
    # ipaddress.ip_network("2a06:98c0::/29"),
    # ipaddress.ip_network("2c0f:f248::/32"),
]

# Blocklist sources: (url, display_name)
#
# Sources are a mix of:
#   - Dedicated IPv6 threat lists (primary data)
#   - General FireHOL lists filtered for IPv6 content (usually sparse but future-proof)
#
BLOCKLISTS = [
    # --- Spamhaus ---
    # Don't Route Or Peer list for IPv6 — high-confidence hijacked/malicious prefixes
    ("https://www.spamhaus.org/drop/dropv6.txt", "Spamhaus_DROPv6"),

    # --- Tor exit nodes ---
    # Official Tor Project bulk exit list (includes IPv6 exit nodes)
    ("https://check.torproject.org/torbulkexitlist", "Tor_Exit"),
    # dan.me.uk mirror — often has IPv6 exit nodes not in the bulk list
    ("https://www.dan.me.uk/torlist/?exit", "Tor_Exit_DAN"),

    # --- abuse.ch ---
    # Feodo Tracker — botnet C&C IPs (primarily IPv4 but occasionally IPv6)
    ("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "Feodo_CnC"),
    # SSL Blacklist — IPs associated with malicious SSL certificates
    ("https://sslbl.abuse.ch/blacklist/sslipblacklist.txt", "SSLBL"),

    # --- Team Cymru bogons ---
    # Full IPv6 unallocated/reserved space (~155k prefixes).
    # Blocks traffic from space that should never appear on the internet.
    # Comment out if the size is too large for your MikroTik hardware.
    #("https://www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt", "Cymru_Bogons_v6"),
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


def parse_ipv6_entries(text):
    """
    Extract valid IPv6 addresses/CIDRs from raw text.
    Skips comment lines, inline comments, and any IPv4 entries.
    Normalises each entry to its canonical network string (e.g. 2001:db8::/32).
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
            if isinstance(net, ipaddress.IPv6Network):
                results.append(str(net))  # canonical form
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
# RSC writers  (MikroTik IPv6 uses /ipv6 firewall address-list)
# ------------------------------------------------------------------------------

def _safe_comment(comment):
    return comment.replace('"', "").replace(" ", "_")


def write_full_rsc(rsc_file, ip_dict):
    """Full reset script — removes all firehol6 entries then re-adds everything."""
    tmp = rsc_file + ".tmp"
    with open(tmp, "w") as f:
        f.write("/ipv6 firewall address-list remove [find list=firehol6]\n")
        for ip, comment in sorted(ip_dict.items()):
            f.write(
                f'/ipv6 firewall address-list add list=firehol6'
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
                f'/ipv6 firewall address-list add list=firehol6'
                f' address={ip} comment="{comment}"\n'
            )
        for ip in to_remove:
            f.write(
                f'/ipv6 firewall address-list remove [find list=firehol6 address={ip}]\n'
            )
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
    parser = argparse.ArgumentParser(description="FireHOL IPv6 incremental updater")
    parser.add_argument("--dry-run", action="store_true",
                        help="Fetch and process lists but do not write any files or send Discord message")
    args = parser.parse_args()

    os.makedirs(FINAL_DIR, exist_ok=True)

    # 1) Load previous run
    old_ip_dict = load_previous_ips(PREV_IPS_FILE)
    log(f"Loaded {len(old_ip_dict)} IPv6 entries from previous run.")

    # 2) Fetch and build new IP dict
    new_ip_dict = {}
    fetch_failures = []

    for url, list_name in BLOCKLISTS:
        log(f"Fetching {list_name} ...")
        text = fetch_url(url)
        if text is None:
            fetch_failures.append(list_name)
            continue

        entries = parse_ipv6_entries(text)
        if not entries:
            log(f"  No IPv6 entries found (likely an IPv4-only list).")
            continue

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

    log(f"Total unique IPv6 entries: {len(new_ip_dict)}")

    if args.dry_run:
        old_ips = set(old_ip_dict)
        new_ips = set(new_ip_dict)
        log(f"[DRY RUN] Would add {len(new_ips - old_ips)}, remove {len(old_ips - new_ips)} entries.")
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
        f"**FireHOL IPv6 update complete**\n"
        f"Total entries: {len(new_ip_dict):,} | Update: {update_size_kb} KB, {line_count} lines\n"
        f"Added: {added_count:,} | Removed: {removed_count:,}{failures_note}"
    )
    send_discord_message(DISCORD_WEBHOOK_URL, discord_message)
    log("Discord notification sent.")


if __name__ == "__main__":
    main()
