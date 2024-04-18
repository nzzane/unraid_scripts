import subprocess
import time
import json
import requests
import os
import re

# Configuration
TARGET_HOST = "1.1.1.1"  # Target host to traceroute
DISCORD_WEBHOOK_URL = "WEBHOOKURL"
LOG_FILE_PATH = "traceroute_log.json"
HIGH_PING_THRESHOLD = 0.20  # 20% increase from the average as high ping threshold
CHECK_INTERVAL = 43200  # Check every 60 seconds


def send_discord_notification(content):
    """Send a notification to the configured Discord channel via webhook."""
    data = {"content": content}
    response = requests.post(DISCORD_WEBHOOK_URL, json=data)
    print(f"Notification sent, status code: {response.status_code}, content: {content}")


def run_traceroute():
    """Run the traceroute command and return the output."""
    command = ["traceroute", TARGET_HOST]
    result = subprocess.run(command, text=True, capture_output=True)
    print("Raw traceroute output:\n", result.stdout)  # Debug print to help see what is captured
    return result.stdout

def load_previous_hops():
    """Load previous hop data from a file."""
    if os.path.exists(LOG_FILE_PATH):
        with open(LOG_FILE_PATH, 'r') as file:
            return json.load(file)
    return {}

def save_hops(hops):
    """Save the current hop data to a file."""
    with open(LOG_FILE_PATH, 'w') as file:
        json.dump(hops, file, indent=4)

def parse_traceroute_output(output):
    """Parse traceroute output to extract hops and pings, handling cases where the first ping may fail."""
    lines = output.strip().split("\n")[1:]  # Skip the first line which is the host
    hops = {}
    # This regex finds the first valid IP address in the line, even if the first ping fails
    ip_regex = re.compile(r'\s+(\d+\.\d+\.\d+\.\d+)\s+')
    for line in lines:
        parts = line.split()
        hop_num = int(parts[0])
        ip_match = ip_regex.search(line)
        ip = ip_match.group(1) if ip_match else "unknown"
        # This filters all ping results, converts them to floats, and ignores '*'
        pings = [float(p[:-2]) for p in parts if p.endswith('ms')]
        average_ping = sum(pings) / len(pings) if pings else float('inf')
        hops[str(hop_num)] = {'ip': ip, 'average_ping': average_ping}
    return hops


def monitor_traceroute():
    """Monitor traceroute, log changes, and alert on new or high pings."""
    previous_hops = load_previous_hops()
    output = run_traceroute()
    current_hops = parse_traceroute_output(output)

    for hop_num, hop_info in current_hops.items():
        ip, average_ping = hop_info['ip'], hop_info['average_ping']
        hop_num_str = str(hop_num)
        formatted_ping = f"{average_ping:.2f}"  # Format ping to 2 decimal places

        if hop_num_str not in previous_hops:
            message = f"```New hop detected: Hop {hop_num}, IP {ip}, Ping {formatted_ping} ms```"
            send_discord_notification(message)
        elif ip != previous_hops[hop_num_str]['ip']:
            message = f"```Hop {hop_num} IP change from {previous_hops[hop_num_str]['ip']} to {ip}, New Ping: {formatted_ping} ms```"
            send_discord_notification(message)
        # Optionally add conditions for high ping notifications here as well, using formatted_ping

    save_hops(current_hops)
    print("Sleeping for interval...")
    time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    while True:
        monitor_traceroute()
