from flask import Flask, render_template, jsonify, request
import scanner
import qos_monitor
import threading

app = Flask(__name__)

# ─── ROUTES ───────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ─── SCANNER ROUTES ───────────────────────────────────────

@app.route("/api/scan")
def api_scan():
    try:
        devices = scanner.scan_network()
        return jsonify({"success": True, "devices": devices, "count": len(devices)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/whitelist_all", methods=["POST"])
def api_whitelist_all():
    macs = scanner.whitelist_all_current()
    return jsonify({"success": True, "whitelisted": len(macs)})


@app.route("/api/alerts")
def api_alerts():
    alerts = scanner.get_rogue_alerts()
    return jsonify({"alerts": alerts, "count": len(alerts)})


@app.route("/api/clear_alerts", methods=["POST"])
def api_clear_alerts():
    scanner.clear_alerts()
    return jsonify({"success": True})


# ─── QoS ROUTES ───────────────────────────────────────────

@app.route("/api/qos/start", methods=["POST"])
def api_qos_start():
    result = qos_monitor.start_monitoring()
    return jsonify(result)


@app.route("/api/qos/stop", methods=["POST"])
def api_qos_stop():
    result = qos_monitor.stop_monitoring()
    return jsonify(result)


@app.route("/api/qos/stats")
def api_qos_stats():
    stats = qos_monitor.get_stats()
    # Add QoS scores
    for name in stats:
        stats[name]["qos_score"] = qos_monitor.get_qos_score(name)
    return jsonify(stats)


@app.route("/api/qos/add_target", methods=["POST"])
def api_add_target():
    data = request.get_json()
    name = data.get("name")
    host = data.get("host")
    if name and host:
        qos_monitor.add_target(name, host)
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Name and host required"})


# ─── MAIN ─────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print("  Network Monitor & QoS Analyser")
    print("  Open browser: http://127.0.0.1:5000")
    print("  Run as Administrator for full scanning!")
    print("=" * 50)
    app.run(debug=True, host="0.0.0.0", port=5000)