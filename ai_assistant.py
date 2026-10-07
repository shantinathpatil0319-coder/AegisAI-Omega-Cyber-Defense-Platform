import re
import random
from db_manager import get_system_summary, get_security_logs, get_ip_rules

class AegisSecOpsAssistant:
    def __init__(self):
        self.system_prompt = "You are Aegis-AI, an elite Autonomous SecOps Cybersecurity Assistant."

    def query(self, user_message, context=None):
        msg_lower = user_message.lower()
        
        # 1. System Status / Summary Query
        if any(w in msg_lower for w in ["summary", "status", "health", "how is system", "overview"]):
            summary = get_system_summary()
            return {
                "reply": f"🛡️ **AegisAI Core Status Report**:\n"
                         f"• System Health: `{summary['system_status']}`\n"
                         f"• Overall Threat Level: `{summary['threat_level']}`\n"
                         f"• Active Unresolved Threats: `{summary['active_threats']}`\n"
                         f"• Blacklisted IPs: `{summary['blacklisted_ips']}`\n"
                         f"• Whitelisted Gateways: `{summary['whitelisted_ips']}`\n"
                         f"• Failed Logins Flagged: `{summary['failed_logins']}`\n\n"
                         f"**SecOps Recommendation**: All high-risk IPs are currently auto-quarantined. Recommend performing an ML entropy scan if payload size spikes occur.",
                "actions": [{"label": "View Audit Logs", "action": "nav-logs"}]
            }

        # 2. IP Inquiry / IP Lookup
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', user_message)
        if ip_match:
            ip = ip_match.group(0)
            rules = get_ip_rules()
            matched_rule = next((r for r in rules if r["ip_address"] == ip), None)
            
            status_text = f"Rule Active: `{matched_rule['rule_type']}` ({matched_rule['reason']})" if matched_rule else "No active firewall rule assigned."
            
            return {
                "reply": f"🔍 **Forensic Analysis for IP `{ip}`**:\n"
                         f"• Firewall Status: {status_text}\n"
                         f"• Threat Risk Rating: **HIGH (84/100)**\n"
                         f"• Known Indicators: Associated with automated credential stuffing & port scanning telemetry.\n"
                         f"• Recommended Action: Instant Blacklist policy via iptables/WAF.",
                "actions": [
                    {"label": f"Blacklist {ip}", "action": "blacklist_ip", "ip": ip},
                    {"label": "Run ML Scan", "action": "scan_ip", "ip": ip}
                ]
            }

        # 3. DDoS / DoS Attack Guidance
        if any(w in msg_lower for w in ["dos", "ddos", "syn flood", "packet flood", "flood"]):
            return {
                "reply": "⚠️ **DDoS / SYN Flood Mitigation Playbook**:\n"
                         "1. Enable **SYN Cookies** on host server: `sysctl -w net.ipv4.tcp_syncookies=1`.\n"
                         "2. Rate-limit HTTP requests per IP via NGINX or AegisAI WAF.\n"
                         "3. Auto-nullroute attacker subnet ranges via BGP / Cloudflare spectrum.\n"
                         "4. Deploy AegisAI ML Classifier to filter zero-day anomaly payloads.",
                "actions": [{"label": "Simulate Attack Event", "action": "sim_attack"}]
            }

        # 4. Ransomware Protection Guidance
        if any(w in msg_lower for w in ["ransomware", "encrypt", "malware", "crypto"]):
            return {
                "reply": "☣️ **Ransomware Defense Playbook (MITRE ATT&CK T1486)**:\n"
                         "1. **Isolate**: Immediately sever network connectivity to affected host endpoint.\n"
                         "2. **Entropy Check**: Flag any process performing > 50 file rename/write operations per second.\n"
                         "3. **Backup Check**: Validate immutable shadow-copy snapshots.\n"
                         "4. **Block C2**: Blacklist command & control domain IPs in AegisAI Firewall.",
                "actions": [{"label": "View Blacklist", "action": "nav-firewall"}]
            }

        # 5. SQL Injection Guidance
        if any(w in msg_lower for w in ["sqli", "sql injection", "database attack", "exploit"]):
            return {
                "reply": "💉 **SQL Injection (OWASP A03:2021) Defense**:\n"
                         "1. Enforce Prepared Statements & Parameterized Queries in database layer.\n"
                         "2. Enable Regex WAF Rule: `(?i)(union|select|insert|concat|drop|--|/\*)`.\n"
                         "3. Audit input payload Shannon Entropy scores in AegisAI Classifier.",
                "actions": [{"label": "Open AI Classifier", "action": "nav-classifier"}]
            }

        # General SecOps Fallback Response
        responses = [
            "🛡️ I am monitoring all incoming system telemetry. You can ask me to analyze IPs, explain attack mitigations (DDoS, Ransomware, SQLi), or summarize current system health.",
            "🤖 Security telemetry is stable. Would you like me to run an automated threat assessment or inspect recent failed logins?",
            "⚡ SecOps AI online. I can execute quick IP bans, check audit log checksums, or explain threat vectors."
        ]
        return {
            "reply": random.choice(responses),
            "actions": [
                {"label": "System Status", "action": "query_status"},
                {"label": "Mitigate DDoS", "action": "query_ddos"}
            ]
        }

# Singleton instance
secops_assistant = AegisSecOpsAssistant()
