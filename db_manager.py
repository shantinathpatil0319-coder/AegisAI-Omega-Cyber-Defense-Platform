import sqlite3
import os
import time
import json

DB_PATH = os.path.join(os.path.dirname(__file__), "aegis_security.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # Security Logs Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            threat_level TEXT NOT NULL,
            severity INTEGER NOT NULL,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'Unresolved'
        )
    """)

    # Login Attempt Monitoring Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_monitoring (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            location TEXT NOT NULL,
            device TEXT NOT NULL,
            status TEXT NOT NULL,
            anomaly_score INTEGER NOT NULL,
            risk_flag TEXT NOT NULL
        )
    """)

    # IP Firewall Rules Table (Blacklist / Whitelist)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            rule_type TEXT NOT NULL, -- 'BLACKLIST' or 'WHITELIST'
            reason TEXT NOT NULL,
            added_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # System Metrics / Statistics Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            metric_key TEXT UNIQUE NOT NULL,
            metric_value INTEGER NOT NULL
        )
    """)

    # Seed Initial Data if empty
    cursor.execute("SELECT COUNT(*) FROM ip_rules")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("""
            INSERT INTO ip_rules (ip_address, rule_type, reason) VALUES (?, ?, ?)
        """, [
            ("192.168.1.1", "WHITELIST", "Internal Admin Gateway"),
            ("10.0.0.45", "WHITELIST", "Trusted Database Server"),
            ("185.220.101.5", "BLACKLIST", "Known Tor Exit Node / Malicious Scanner"),
            ("45.146.164.110", "BLACKLIST", "Brute-force Botnet Node"),
            ("198.51.100.42", "BLACKLIST", "Credential Stuffing Source")
        ])

    cursor.execute("SELECT COUNT(*) FROM login_monitoring")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("""
            INSERT INTO login_monitoring (username, ip_address, location, device, status, anomaly_score, risk_flag) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, [
            ("admin_sec", "192.168.1.1", "New York, USA", "Chrome / Win11", "SUCCESS", 5, "LOW"),
            ("user_dev", "10.0.0.45", "London, UK", "Firefox / Ubuntu", "SUCCESS", 12, "LOW"),
            ("root", "185.220.101.5", "Moscow, RU", "Unknown / Linux", "FAILED", 92, "CRITICAL"),
            ("admin_sec", "45.146.164.110", "Beijing, CN", "Python-urllib/3.9", "FAILED", 88, "HIGH"),
            ("finance_mgr", "198.51.100.42", "Frankfurt, DE", "Curl/7.68.0", "FAILED", 76, "HIGH")
        ])

    cursor.execute("SELECT COUNT(*) FROM security_logs")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("""
            INSERT INTO security_logs (source_ip, event_type, threat_level, severity, description, status) VALUES (?, ?, ?, ?, ?, ?)
        """, [
            ("185.220.101.5", "SYN Flood DoS Attack", "CRITICAL", 9, "High-volume packet flood detected targeting port 443", "Mitigated"),
            ("45.146.164.110", "Brute-Force Login", "HIGH", 7, "50+ failed login attempts within 60 seconds", "Blocked"),
            ("198.51.100.42", "SQL Injection Probe", "HIGH", 8, "Malicious payload detected in login POST body: UNION SELECT", "Blocked"),
            ("10.0.0.45", "Port Scan Activity", "MEDIUM", 4, "Sequential port scan detected on ports 21-1024", "Monitored"),
            ("192.168.1.100", "Ransomware Signature", "CRITICAL", 10, "Suspicious file encryption activity flagged by host agent", "Isolated")
        ])

    conn.commit()
    conn.close()

def log_security_event(source_ip, event_type, threat_level, severity, description, status="Unresolved"):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO security_logs (source_ip, event_type, threat_level, severity, description, status)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (source_ip, event_type, threat_level, severity, description, status))
    conn.commit()
    log_id = cursor.lastrowid
    conn.close()
    return log_id

def log_login_attempt(username, ip_address, location, device, status, anomaly_score, risk_flag):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO login_monitoring (username, ip_address, location, device, status, anomaly_score, risk_flag)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (username, ip_address, location, device, status, anomaly_score, risk_flag))
    conn.commit()
    conn.close()

def get_security_logs(limit=50, search_query=None):
    conn = get_db()
    cursor = conn.cursor()
    if search_query:
        query = f"%{search_query}%"
        cursor.execute("""
            SELECT * FROM security_logs
            WHERE source_ip LIKE ? OR event_type LIKE ? OR description LIKE ? OR threat_level LIKE ?
            ORDER BY id DESC LIMIT ?
        """, (query, query, query, query, limit))
    else:
        cursor.execute("SELECT * FROM security_logs ORDER BY id DESC LIMIT ?", (limit,))
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return logs

def get_login_attempts(limit=50):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM login_monitoring ORDER BY id DESC LIMIT ?", (limit,))
    attempts = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return attempts

def get_ip_rules():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ip_rules ORDER BY id DESC")
    rules = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rules

def add_ip_rule(ip_address, rule_type, reason):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO ip_rules (ip_address, rule_type, reason)
            VALUES (?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET rule_type=excluded.rule_type, reason=excluded.reason
        """, (ip_address, rule_type.upper(), reason))
        conn.commit()
        success = True
    except Exception as e:
        success = False
    conn.close()
    return success

def delete_ip_rule(ip_address):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ip_rules WHERE ip_address = ?", (ip_address,))
    conn.commit()
    conn.close()
    return True

def get_system_summary():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE status='Unresolved' OR threat_level IN ('HIGH', 'CRITICAL')")
    active_threats = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM ip_rules WHERE rule_type='BLACKLIST'")
    blacklisted_ips = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM ip_rules WHERE rule_type='WHITELIST'")
    whitelisted_ips = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM login_monitoring WHERE status='FAILED'")
    failed_logins = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_logs")
    total_events = cursor.fetchone()[0]

    conn.close()
    return {
        "active_threats": active_threats,
        "blacklisted_ips": blacklisted_ips,
        "whitelisted_ips": whitelisted_ips,
        "failed_logins": failed_logins,
        "total_events": total_events,
        "system_status": "SECURE / ACTIVE MITIGATION",
        "threat_level": "ELEVATED" if active_threats > 2 else "NORMAL"
    }
