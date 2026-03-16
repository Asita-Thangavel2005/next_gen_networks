import subprocess
import platform
import threading
import time
from datetime import datetime
from collections import deque

# Store last 60 readings per target
MAX_HISTORY = 60

monitoring_active = False
monitor_thread = None

targets = {
    "Google DNS": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "OpenDNS": "208.67.222.222",
}

stats = {}  # target_name -> { latency_history, packet_loss, jitter, status }

for name in targets:
    stats[name] = {
        "latency_history": deque(maxlen=MAX_HISTORY),
        "timestamps": deque(maxlen=MAX_HISTORY),
        "packet_loss": 0,
        "jitter": 0.0,
        "avg_latency": 0.0,
        "min_latency": 0.0,
        "max_latency": 0.0,
        "status": "Idle",
        "total_sent": 0,
        "total_lost": 0,
    }


def ping_host(host):
    """Ping a host once and return latency in ms or None if failed."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
    timeout_val = "1000" if platform.system().lower() == "windows" else "2"

    cmd = ["ping", param, "1", timeout_param, timeout_val, host]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        output = result.stdout

        # Parse latency from ping output
        if platform.system().lower() == "windows":
            # Windows: "Average = 20ms"
            import re
            match = re.search(r"Average = (\d+)ms", output)
            if match:
                return float(match.group(1))
            # Also try "time=20ms" or "time<1ms"
            match = re.search(r"time[=<](\d+)ms", output)
            if match:
                return float(match.group(1))
        else:
            import re
            match = re.search(r"time=([\d.]+) ms", output)
            if match:
                return float(match.group(1))

        return None
    except Exception:
        return None


def calculate_jitter(latency_list):
    """Calculate jitter as average deviation between consecutive pings."""
    if len(latency_list) < 2:
        return 0.0
    diffs = [abs(latency_list[i] - latency_list[i-1]) for i in range(1, len(latency_list))]
    return round(sum(diffs) / len(diffs), 2)


def monitor_loop():
    """Continuously ping all targets and update stats."""
    global monitoring_active
    while monitoring_active:
        for name, host in targets.items():
            latency = ping_host(host)
            now = datetime.now().strftime("%H:%M:%S")

            stats[name]["total_sent"] += 1

            if latency is not None:
                stats[name]["latency_history"].append(latency)
                stats[name]["timestamps"].append(now)
                stats[name]["status"] = "Online"

                history = list(stats[name]["latency_history"])
                stats[name]["avg_latency"] = round(sum(history) / len(history), 2)
                stats[name]["min_latency"] = round(min(history), 2)
                stats[name]["max_latency"] = round(max(history), 2)
                stats[name]["jitter"] = calculate_jitter(history)
            else:
                stats[name]["total_lost"] += 1
                stats[name]["status"] = "Offline"
                stats[name]["latency_history"].append(None)
                stats[name]["timestamps"].append(now)

            # Calculate packet loss %
            sent = stats[name]["total_sent"]
            lost = stats[name]["total_lost"]
            stats[name]["packet_loss"] = round((lost / sent) * 100, 1) if sent > 0 else 0

        time.sleep(3)  # ping every 3 seconds


def start_monitoring():
    """Start the monitoring thread."""
    global monitoring_active, monitor_thread
    if not monitoring_active:
        monitoring_active = True
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
        return {"status": "started"}
    return {"status": "already running"}


def stop_monitoring():
    """Stop the monitoring thread."""
    global monitoring_active
    monitoring_active = False
    return {"status": "stopped"}


def get_stats():
    """Return current stats as JSON-serializable dict."""
    result = {}
    for name in targets:
        s = stats[name]
        history = list(s["latency_history"])
        timestamps = list(s["timestamps"])

        # Replace None with 0 for chart display
        clean_history = [v if v is not None else 0 for v in history]

        result[name] = {
            "host": targets[name],
            "latency_history": clean_history,
            "timestamps": timestamps,
            "avg_latency": s["avg_latency"],
            "min_latency": s["min_latency"],
            "max_latency": s["max_latency"],
            "jitter": s["jitter"],
            "packet_loss": s["packet_loss"],
            "status": s["status"],
        }
    return result


def add_target(name, host):
    """Add a new target to monitor."""
    targets[name] = host
    stats[name] = {
        "latency_history": deque(maxlen=MAX_HISTORY),
        "timestamps": deque(maxlen=MAX_HISTORY),
        "packet_loss": 0,
        "jitter": 0.0,
        "avg_latency": 0.0,
        "min_latency": 0.0,
        "max_latency": 0.0,
        "status": "Idle",
        "total_sent": 0,
        "total_lost": 0,
    }


def get_qos_score(name):
    """Return a QoS score 0-100 based on latency, jitter, packet loss."""
    s = stats.get(name)
    if not s or s["status"] == "Idle":
        return 0
    latency_score = max(0, 100 - s["avg_latency"])
    jitter_score = max(0, 100 - s["jitter"] * 2)
    loss_score = max(0, 100 - s["packet_loss"] * 5)
    return round((latency_score + jitter_score + loss_score) / 3, 1)