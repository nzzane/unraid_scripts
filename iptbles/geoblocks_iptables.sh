#!/bin/bash
set -euo pipefail

# GeoBlock IPv4 ipset Generator
# Downloads MaxMind GeoLite2-Country CSV, extracts IPv4 networks for blocked
# countries, and writes shell scripts to apply/update an ipset on Linux.
#
# Wire up once (run manually or in a bootstrap script):
#   ipset create GeoBlock hash:net maxelem 500000
#   iptables -I INPUT   -m set --match-set GeoBlock src -j DROP
#   iptables -I FORWARD -m set --match-set GeoBlock src -j DROP
#
# Usage: ./geoblocks_iptables.sh [--dry-run]

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------

MAXMIND_LICENSE_KEY="YOUR_MAXMIND_LICENSE_KEY"
GEOIP_CSV_URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=${MAXMIND_LICENSE_KEY}&suffix=zip"
OUTPUT_DIR="/path/to/output"
RAM_DIR="/dev/shm/mikrotik"
DISCORD_WEBHOOK_URL="YOUR_DISCORD_WEBHOOK_URL"
DISCORD_USER_ID="YOUR_DISCORD_USER_ID"

ADDRESS_LIST_NAME="GeoBlock"
IPSET_MAXELEM=500000

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

PREV_IPS_FILE="$RAM_DIR/geoblock_prev_ips.txt"
FULL_SCRIPT="$OUTPUT_DIR/geoblock.sh"
UPDATE_SCRIPT="$OUTPUT_DIR/geoblock_update.sh"

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

# Write ipset add-commands for a CSV file (format: network,COUNTRY_CODE) to stdout.
generate_add_commands() {
    local input_file="$1"
    [[ -s "$input_file" ]] || return 0
    awk -F',' -v list="$ADDRESS_LIST_NAME" '
    !seen[$1]++ { printf "ipset add %s %s\n", list, $1 }
    ' "$input_file"
}

# Write ipset add-commands for incremental additions (-exist flag to be idempotent).
generate_add_commands_incremental() {
    local input_file="$1"
    [[ -s "$input_file" ]] || return 0
    awk -F',' -v list="$ADDRESS_LIST_NAME" '
    !seen[$1]++ { printf "ipset add %s %s -exist\n", list, $1 }
    ' "$input_file"
}

copy_if_changed() {
    local src="$1" dst="$2"
    if ! cmp -s "$src" "$dst" 2>/dev/null; then
        cp "$src" "$dst"
        chmod 755 "$dst"
        log "  Written: $(basename "$dst")"
    else
        log "  Unchanged: $(basename "$dst") — skipped write"
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
    send_discord "GeoBlock: Failed to download GeoLite2. Check license key or network."
    exit 1
fi

log "Extracting archive..."
if ! unzip -q "$TEMP_DIR/geoip.zip" -d "$TEMP_DIR"; then
    send_discord "GeoBlock: Failed to unzip GeoLite2."
    exit 1
fi

CSV_FOLDER=$(find "$TEMP_DIR" -type d -name "GeoLite2-Country-CSV_*" | sort | tail -n 1)
if [[ -z "$CSV_FOLDER" ]]; then
    send_discord "GeoBlock: Could not find extracted CSV folder."
    exit 1
fi

# ------------------------------------------------------------------------------
# Extract IPv4 networks for each country
# ------------------------------------------------------------------------------

: > "$CURRENT_IPS_FILE"
for country_code in "${!COUNTRY_GEONAMES[@]}"; do
    geoname_id="${COUNTRY_GEONAMES[$country_code]}"
    log "  Extracting $country_code (geoname_id=$geoname_id)..."
    awk -F',' -v id="$geoname_id" -v cc="$country_code" \
        '$2 == id { print $1 "," cc }' \
        "$CSV_FOLDER/GeoLite2-Country-Blocks-IPv4.csv" >> "$CURRENT_IPS_FILE"
done

sort -u "$CURRENT_IPS_FILE" -o "$CURRENT_IPS_FILE"
TOTAL_NETWORKS=$(wc -l < "$CURRENT_IPS_FILE")
log "Total networks: $TOTAL_NETWORKS"

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
# Generate shell scripts, write only if changed
# ------------------------------------------------------------------------------

TS=$(date '+%Y-%m-%d %H:%M:%S')

{
    echo "#!/bin/bash"
    echo "# GeoBlock IPv4 full ipset reset — generated $TS"
    echo "# Wire up once if not already done:"
    echo "#   ipset create $ADDRESS_LIST_NAME hash:net maxelem $IPSET_MAXELEM"
    echo "#   iptables -I INPUT   -m set --match-set $ADDRESS_LIST_NAME src -j DROP"
    echo "#   iptables -I FORWARD -m set --match-set $ADDRESS_LIST_NAME src -j DROP"
    echo "set -euo pipefail"
    echo ""
    echo "ipset create $ADDRESS_LIST_NAME hash:net maxelem $IPSET_MAXELEM 2>/dev/null || ipset flush $ADDRESS_LIST_NAME"
    echo ""
    generate_add_commands "$CURRENT_IPS_FILE"
} > "$TEMP_DIR/full.sh"
copy_if_changed "$TEMP_DIR/full.sh" "$FULL_SCRIPT"

{
    echo "#!/bin/bash"
    echo "# GeoBlock IPv4 incremental ipset update — generated $TS"
    echo "# Added: $ADDED_COUNT  Removed: $REMOVED_COUNT"
    echo "set -euo pipefail"
    echo ""
    if [[ -s "$TEMP_DIR/added.txt" ]]; then
        echo "# New entries"
        generate_add_commands_incremental "$TEMP_DIR/added.txt"
    fi
    if [[ -s "$TEMP_DIR/removed.txt" ]]; then
        echo ""
        echo "# Stale entries"
        while IFS=',' read -r network _; do
            echo "ipset del $ADDRESS_LIST_NAME $network 2>/dev/null || true"
        done < "$TEMP_DIR/removed.txt"
    fi
} > "$TEMP_DIR/update.sh"
copy_if_changed "$TEMP_DIR/update.sh" "$UPDATE_SCRIPT"

# ------------------------------------------------------------------------------
# Save state for next run
# ------------------------------------------------------------------------------

cp "$CURRENT_IPS_FILE" "$PREV_IPS_FILE"

# ------------------------------------------------------------------------------
# Discord notification
# ------------------------------------------------------------------------------

FULL_KB=$(( $(stat -c %s "$FULL_SCRIPT") / 1024 ))
FULL_LINES=$(wc -l < "$FULL_SCRIPT")
UPDATE_KB=$(( $(stat -c %s "$UPDATE_SCRIPT") / 1024 ))
UPDATE_LINES=$(wc -l < "$UPDATE_SCRIPT")

send_discord "GeoBlock (ipset) updated. Networks: $TOTAL_NETWORKS | Added: $ADDED_COUNT, Removed: $REMOVED_COUNT | Full: ${FULL_KB}KB/${FULL_LINES} lines | Update: ${UPDATE_KB}KB/${UPDATE_LINES} lines"
log "Done."
