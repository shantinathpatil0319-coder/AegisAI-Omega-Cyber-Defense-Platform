import os
import sys
import random
import time
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

# Add root directory to sys.path so we can import darkweb_intel if needed
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db_manager import (
    init_db, log_security_event, log_login_attempt,
    get_security_logs, get_login_attempts, get_ip_rules,
    add_ip_rule, delete_ip_rule, get_system_summary
)
from threat_engine import classifier
from ai_assistant import secops_assistant

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)

# Initialize Database
init_db()

@app.route("/")
def serve_frontend():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/api/summary")
def api_summary():
    """Returns top telemetry metrics, active threat count, system health."""
    summary = get_system_summary()
    return jsonify(summary)

@app.route("/api/classify", methods=["POST"])
def api_classify():
    """Classifies live packet features with ML engine and logs event if threat."""
    data = request.json or {}
    packet_rate = float(data.get("packet_rate", 100))
    byte_size = float(data.get("byte_size", 500))
    entropy = float(data.get("entropy", 3.2))
    failed_attempts = int(data.get("failed_attempts", 0))
    port_count = int(data.get("port_count", 1))
    source_ip = data.get("source_ip", f"192.168.1.{random.randint(10, 250)}")

    result = classifier.classify(packet_rate, byte_size, entropy, failed_attempts, port_count)

    # Automatically log if it's a threat
    if result["threat_type"] != "Normal":
        threat_level = "CRITICAL" if result["severity"] >= 9 else ("HIGH" if result["severity"] >= 7 else "MEDIUM")
        log_security_event(
            source_ip=source_ip,
            event_type=result["threat_type"],
            threat_level=threat_level,
            severity=result["severity"],
            description=f"AI Engine flagged packet batch with risk score {result['risk_score']}%. {result['mitigation']}",
            status="Unresolved"
        )

    return jsonify(result)

@app.route("/api/login-monitoring", methods=["GET", "POST"])
def api_login_monitoring():
    if request.method == "POST":
        data = request.json or {}
        username = data.get("username", "guest_user")
        ip = data.get("ip", f"185.220.{random.randint(1,255)}.{random.randint(1,255)}")
        location = data.get("location", "Unknown Geo")
        device = data.get("device", "Custom Client")
        status = data.get("status", "FAILED")
        
        # Calculate anomaly score
        failed_count = random.randint(1, 15) if status == "FAILED" else 0
        anomaly_score = min(99, failed_count * 12 + random.randint(5, 20))
        risk_flag = "CRITICAL" if anomaly_score > 80 else ("HIGH" if anomaly_score > 60 else "LOW")
        
        log_login_attempt(username, ip, location, device, status, anomaly_score, risk_flag)
        
        if risk_flag in ["CRITICAL", "HIGH"]:
            log_security_event(
                source_ip=ip,
                event_type="Anomalous Login Attempt",
                threat_level=risk_flag,
                severity=8 if risk_flag == "CRITICAL" else 6,
                description=f"Suspicious login for '{username}' from {location} ({ip}). Anomaly rating: {anomaly_score}%",
                status="Unresolved"
            )

        return jsonify({"success": True, "anomaly_score": anomaly_score, "risk_flag": risk_flag})
    else:
        attempts = get_login_attempts(limit=30)
        return jsonify(attempts)

@app.route("/api/ip-rules", methods=["GET", "POST", "DELETE"])
def api_ip_rules():
    if request.method == "POST":
        data = request.json or {}
        ip = data.get("ip_address")
        rule_type = data.get("rule_type", "BLACKLIST")
        reason = data.get("reason", "Manual Security Administrator Action")
        if not ip:
            return jsonify({"error": "IP Address required"}), 400
        success = add_ip_rule(ip, rule_type, reason)
        return jsonify({"success": success})

    elif request.method == "DELETE":
        ip = request.args.get("ip")
        if not ip:
            return jsonify({"error": "IP parameter missing"}), 400
        delete_ip_rule(ip)
        return jsonify({"success": True})

    else:
        rules = get_ip_rules()
        return jsonify(rules)

@app.route("/api/logs")
def api_logs():
    search = request.args.get("q", None)
    logs = get_security_logs(limit=50, search_query=search)
    return jsonify(logs)

@app.route("/api/darkweb-intel")
def api_darkweb():
    """Returns threat intelligence feeds & IOC indicators."""
    try:
        from darkweb_intel import fetch_darkweb
        intel = fetch_darkweb()
    except Exception:
        intel = [
            {"ioc": "185.220.101.5", "malware": "Emotet Botnet"},
            {"ioc": "45.146.164.110", "malware": "Mirai Variant"},
            {"ioc": "198.51.100.42", "malware": "Qakbot Loader"},
            {"ioc": "103.253.144.12", "malware": "Cobalt Strike C2"}
        ]
    return jsonify(intel)

@app.route("/api/chat", methods=["POST"])
def api_chat():
    """Handles AI Assistant chat queries and returns natural language security guidance."""
    data = request.json or {}
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"error": "Message required"}), 400
    
    response = secops_assistant.query(message)
    return jsonify(response)

@app.route("/api/radar-feed")
def api_radar_feed():
    """Generates real-time threat radar sweep coordinates for visualization."""
    targets = []
    for _ in range(random.randint(3, 7)):
        angle = random.randint(0, 360)
        distance = random.randint(20, 95)
        severity = random.choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        targets.append({
            "ip": f"{random.randint(10, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
            "angle": angle,
            "distance": distance,
            "severity": severity
        })
    return jsonify({"targets": targets, "timestamp": time.time()})

if __name__ == "__main__":
    print("[AEGIS.AI] AegisAI Cyber Defense Platform API running on http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)