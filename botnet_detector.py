import json
import requests
from collections import defaultdict
from datetime import datetime
import csv

# CONFIG
KNOWN_C2_PORTS = {4444, 8080, 9001, 1337}
BEACON_THRESHOLD = 3  # How many repeated connections to same IP?
INTERVAL_TOLERANCE = 2  # Seconds
LOG_FILE = "sample_traffic_logs.json"
CSV_OUTPUT = "c2_detection_report.csv"

# GeoIP via ip-api (Free, no key needed)
def resolve_ip_geolocation(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        if res["status"] == "success":
            return f"{res['country']}, {res.get('city', 'N/A')} (ISP: {res['isp']})"
        return "Unknown"
    except:
        return "Error"

# Parse timestamp format from logs
def parse_ts(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")

# Analyze traffic patterns
def analyze_logs(data):
    contact_log = defaultdict(list)
    beacon_alerts = []
    report = []

    for log in data:
        src = log.get("src_ip")
        dst = log.get("dst_ip")
        port = int(log.get("dst_port", 0))
        ts = parse_ts(log.get("timestamp"))

        contact_log[(src, dst)].append(ts)

        # Flag known C2 port
        if port in KNOWN_C2_PORTS:
            geo = resolve_ip_geolocation(dst)
            report.append({
                "src_ip": src,
                "dst_ip": dst,
                "port": port,
                "geo": geo,
                "timestamp": ts,
                "type": "C2 Port"
            })

    # Beaconing detection
    for (src, dst), timestamps in contact_log.items():
        if len(timestamps) >= BEACON_THRESHOLD:
            timestamps.sort()
            intervals = [(timestamps[i+1] - timestamps[i]).seconds for i in range(len(timestamps)-1)]
            if all(abs(i - intervals[0]) <= INTERVAL_TOLERANCE for i in intervals):
                geo = resolve_ip_geolocation(dst)
                report.append({
                    "src_ip": src,
                    "dst_ip": dst,
                    "port": "varies",
                    "geo": geo,
                    "timestamp": timestamps[0],
                    "type": "Beaconing"
                })

    return report

# Save report to CSV
def write_csv(records):
    keys = ["src_ip", "dst_ip", "port", "geo", "timestamp", "type"]
    with open(CSV_OUTPUT, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for r in records:
            writer.writerow(r)
    print(f"[+] Report saved as {CSV_OUTPUT}")

# MAIN
if __name__ == "__main__":
    with open(LOG_FILE) as f:
        log_data = json.load(f)
    results = analyze_logs(log_data)
    write_csv(results)
