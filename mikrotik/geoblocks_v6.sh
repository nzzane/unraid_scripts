#!/bin/bash
set -euo pipefail

# GeoBlock IPv6 List Generator
# Generates MikroTik IPv6 address-list for blocked country IP ranges.
# Uses GeoLite2-Country-Blocks-IPv6.csv from the same MaxMind download.
#
# Usage: ./geoblocks_v6.sh [--dry-run]

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------

MAXMIND_LICENSE_KEY="YOUR_MAXMIND_LICENSE_KEY"
GEOIP_CSV_URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=${MAXMIND_LICENSE_KEY}&suffix=zip"
OUTPUT_DIR="/path/to/output"                        # SSD — SWAG-served, written only on change
RAM_DIR="/dev/shm/mikrotik"                         # RAM — state files, temp RSC generation
DISCORD_WEBHOOK_URL="YOUR_DISCORD_WEBHOOK_URL"
DISCORD_USER_ID="YOUR_DISCORD_USER_ID"

ADDRESS_LIST_NAME="GeoBlock6"

declare -A COUNTRY_GEONAMES=(
    ["CN"]="1814991"   # China         — largest source of automated attacks/APT activity
    ["RU"]="2017370"   # Russia        — state-sponsored hacking, ransomware groups
    ["HK"]="1819730"   # Hong Kong     — significant PRC-linked traffic since 2020 handover
    ["KP"]="1873107"   # North Korea   — state-sponsored theft, Lazarus Group etc.
    ["IR"]="130758"    # Iran          — state-sponsored attacks, infrastructure targeting
    ["BY"]="630336"    # Belarus       — close Russian ally, shared threat actor infrastructure
    ["IL"]="294640"    # Israel        — significant offensive cyber capability
    ["PK"]="1168579"   # Pakistan      — APT36 and other state-linked groups
    ["NG"]="2328926"   # Nigeria       — large-scale fraud and BEC operations
    ["VN"]="1562822"   # Vietnam       — APT32/OceanLotus and related groups
    ["IN"]="1269750"   # India         — increasing attack origin volume
)

# State file lives in RAM — lost on reboot, triggers a full sync on next run (acceptable)
PREV_IPS_FILE="$RAM_DIR/geoblock6_prev_ips.txt"
FULL_SCRIPT="$OUTPUT_DIR/geoblock6.rsc"
UPDATE_SCRIPT="$OUTPUT_DIR/geoblock6_update.rsc"

# ------------------------------------------------------------------------------
# Argument parsing
# ------------------------------------------------------------------------------

DRY_RUN=false
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        *) echo "Unknown option: $arg"; exit 1 ;;
    esac
done

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

log() { echo "[$(date +%H:%M:%S)] $*"; }

send_discord() {
    local message="<@${DISCORD_USER_ID}> $1"
    python3 -c "import json,sys; print(json.dumps({'content': sys.argv[1]}))" "$message" \
        | curl -s -H "Content-Type: application/json" -X POST -d @- "$DISCORD_WEBHOOK_URL" || true
}

# Write add-commands for a CSV file (format: network,COUNTRY_CODE) to stdout.
# Uses /ipv6 firewall address-list for IPv6 entries.
generate_add_commands() {
    local input_file="$1"
    [[ -s "$input_file" ]] || return 0
    awk -F',' -v list="$ADDRESS_LIST_NAME" '
    {
        if ($1 in comments) {
            comments[$1] = comments[$1] "," $2
        } else {
            order[NR] = $1
            comments[$1] = $2
        }
    }
    END {
        for (i = 1; i <= length(order); i++) {
            ip = order[i]
            if (ip != "") {
                printf "/ipv6 firewall address-list add list=%s address=%s comment=\"%s\"\n", list, ip, comments[ip]
            }
        }
    }' "$input_file"
}

# Copy src to dst only if content differs — avoids unnecessary SSD writes.
copy_if_changed() {
    local src="$1" dst="$2"
    if ! cmp -s "$src" "$dst" 2>/dev/null; then
        cp "$src" "$dst"
        log "  Written to SSD: $(basename "$dst")"
    else
        log "  Unchanged: $(basename "$dst") — skipped SSD write"
    fi
}

# ------------------------------------------------------------------------------
# Setup
# ------------------------------------------------------------------------------

mkdir -p "$RAM_DIR" "$OUTPUT_DIR"
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

CURRENT_IPS_FILE="$TEMP_DIR/cur_ips.txt"

# ------------------------------------------------------------------------------
# Download & extract
# ------------------------------------------------------------------------------

log "Downloading GeoLite2-Country CSV..."
if ! curl -sL -o "$TEMP_DIR/geoip.zip" "$GEOIP_CSV_URL"; then
    send_discord "GeoBlock6: Failed to download GeoLite2. Check license key or network."
    exit 1
fi

log "Extracting archive..."
if ! unzip -q "$TEMP_DIR/geoip.zip" -d "$TEMP_DIR"; then
    send_discord "GeoBlock6: Failed to unzip GeoLite2."
    exit 1
fi

CSV_FOLDER=$(find "$TEMP_DIR" -type d -name "GeoLite2-Country-CSV_*" | sort | tail -n 1)
if [[ -z "$CSV_FOLDER" ]]; then
    send_discord "GeoBlock6: Could not find extracted CSV folder."
    exit 1
fi

# ------------------------------------------------------------------------------
# Extract IPv6 networks for each country
# ------------------------------------------------------------------------------

: > "$CURRENT_IPS_FILE"
for country_code in "${!COUNTRY_GEONAMES[@]}"; do
    geoname_id="${COUNTRY_GEONAMES[$country_code]}"
    log "  Extracting $country_code (geoname_id=$geoname_id)..."
    awk -F',' -v id="$geoname_id" -v cc="$country_code" \
        '$2 == id { print $1 "," cc }' \
        "$CSV_FOLDER/GeoLite2-Country-Blocks-IPv6.csv" >> "$CURRENT_IPS_FILE"
done

sort -u "$CURRENT_IPS_FILE" -o "$CURRENT_IPS_FILE"
TOTAL_NETWORKS=$(wc -l < "$CURRENT_IPS_FILE")
log "Total IPv6 networks: $TOTAL_NETWORKS"

# ------------------------------------------------------------------------------
# Diff against previous run
# ------------------------------------------------------------------------------

if [[ -f "$PREV_IPS_FILE" ]]; then
    sort -u "$PREV_IPS_FILE" -o "$PREV_IPS_FILE"
    comm -13 "$PREV_IPS_FILE" "$CURRENT_IPS_FILE" > "$TEMP_DIR/added.txt"
    comm -23 "$PREV_IPS_FILE" "$CURRENT_IPS_FILE" > "$TEMP_DIR/removed.txt"
else
    log "No previous state found (first run or post-reboot) — full sync."
    cp "$CURRENT_IPS_FILE" "$TEMP_DIR/added.txt"
    : > "$TEMP_DIR/removed.txt"
fi

ADDED_COUNT=$(wc -l < "$TEMP_DIR/added.txt")
REMOVED_COUNT=$(wc -l < "$TEMP_DIR/removed.txt")
log "Delta — Added: $ADDED_COUNT, Removed: $REMOVED_COUNT"

# ------------------------------------------------------------------------------
# Dry run
# ------------------------------------------------------------------------------

if [[ "$DRY_RUN" == true ]]; then
    log "[DRY RUN] Would write $FULL_SCRIPT and $UPDATE_SCRIPT — no files written."
    exit 0
fi

# ------------------------------------------------------------------------------
# Generate RSC files in RAM, write to SSD only if changed
# ------------------------------------------------------------------------------

{
    echo "/ipv6 firewall address-list remove [find list=$ADDRESS_LIST_NAME]"
    generate_add_commands "$CURRENT_IPS_FILE"
} > "$TEMP_DIR/full.rsc"
copy_if_changed "$TEMP_DIR/full.rsc" "$FULL_SCRIPT"

{
    generate_add_commands "$TEMP_DIR/added.txt"
    while IFS=',' read -r network _; do
        echo "/ipv6 firewall address-list remove [find list=$ADDRESS_LIST_NAME address=$network]"
    done < "$TEMP_DIR/removed.txt"
} > "$TEMP_DIR/update.rsc"
copy_if_changed "$TEMP_DIR/update.rsc" "$UPDATE_SCRIPT"

# ------------------------------------------------------------------------------
# Save state to RAM for next run
# ------------------------------------------------------------------------------

cp "$CURRENT_IPS_FILE" "$PREV_IPS_FILE"

# ------------------------------------------------------------------------------
# Discord notification
# ------------------------------------------------------------------------------

FULL_KB=$(( $(stat -c %s "$FULL_SCRIPT") / 1024 ))
FULL_LINES=$(wc -l < "$FULL_SCRIPT")
UPDATE_KB=$(( $(stat -c %s "$UPDATE_SCRIPT") / 1024 ))
UPDATE_LINES=$(wc -l < "$UPDATE_SCRIPT")

send_discord "GeoBlock6 updated. Networks: $TOTAL_NETWORKS | Added: $ADDED_COUNT, Removed: $REMOVED_COUNT | Full: ${FULL_KB}KB/${FULL_LINES} lines | Update: ${UPDATE_KB}KB/${UPDATE_LINES} lines"
log "Done."
