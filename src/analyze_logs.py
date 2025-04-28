import json
from datetime import datetime, timedelta
from collections import defaultdict
import os

def analyze_honeypot_logs(
    logfile="logs/honeypot_log.json",
    bf_threshold=5,
    bf_window=5,    
    dt_threshold=10,    
    lst_threshold=20
):
    entries = []
    with open(logfile) as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    for e in entries:
        e['dt'] = datetime.strptime(e['timestamp'], "%Y-%m-%d %H:%M:%S")

    # 1) Brute-force detection
    failed_logins = defaultdict(list)
    for e in entries:
        if e.get("event") == "login_failed":
            failed_logins[e["client"]].append(e['dt'])
    brute_force_ips = []
    for ip, times in failed_logins.items():
        times.sort()
        start = 0
        for end in range(len(times)):
            while times[end] - times[start] > timedelta(minutes=bf_window):
                start += 1
            if (end - start + 1) >= bf_threshold:
                brute_force_ips.append(ip)
                break

    # 2) Directory traversal scan (cố gắng cwd vào thư mục không tồn tại)
    dt_counts = defaultdict(int)
    for e in entries:
        if e.get("event") == "cwd_failed":
            dt_counts[e["client"]] += 1
    dt_ips = [ip for ip, cnt in dt_counts.items() if cnt >= dt_threshold]

    # 3) Port-scan style PASV without data connect
    pasv_counts = defaultdict(int)
    data_conn_counts = defaultdict(int)
    for e in entries:
        if e.get("event") == "pasv":
            pasv_counts[e["client"]] += 1
        if e.get("event") == "list_start":
            data_conn_counts[e["client"]] += 1
    scan_ips = []
    for ip in pasv_counts:
        if pasv_counts[ip] >= bf_threshold and data_conn_counts.get(ip,0) < pasv_counts[ip]//2:
            scan_ips.append(ip)

    # 4) File enumeration (LIST sau login)
    list_counts = defaultdict(int)
    for e in entries:
        if e.get("event") == "list_done":
            list_counts[e["client"]] += 1
    enum_ips = [ip for ip, cnt in list_counts.items() if cnt >= lst_threshold]

    # 5) Các sự kiện CWD và MKD/RMD để kiểm tra hành vi tấn công kiểu directory traversal hoặc thao tác với thư mục
    mkdir_rmdir_counts = defaultdict(int)
    for e in entries:
        if e.get("event") in ["mkd", "rmd"]:
            mkdir_rmdir_counts[e["client"]] += 1
    mkdir_rmdir_ips = [ip for ip, cnt in mkdir_rmdir_counts.items() if cnt >= 5]  # Threshold 5 thao tác

    result = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "brute_force": sorted(set(brute_force_ips)),
        "dir_traversal": sorted(set(dt_ips)),
        "pasv_scan": sorted(set(scan_ips)),
        "file_enum": sorted(set(enum_ips)),
        "mkdir_rmdir": sorted(set(mkdir_rmdir_ips)),  # Thêm danh sách IP tấn công thư mục
    }
    return result

def write_analysis_report(results, filename="logs/analysis_report.json"):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    try:
        with open(filename, "w") as f:
            json.dump(results, f, indent=2)
        print(f"Analysis report written to {filename}")
    except Exception as e:
        print(f"Error writing analysis report: {e}")

