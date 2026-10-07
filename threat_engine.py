import numpy as np

# Try importing scikit-learn for ML model; if not available, use intelligent fallback heuristics
ML_AVAILABLE = False
try:
    from sklearn.ensemble import RandomForestClassifier
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

class AegisThreatClassifier:
    def __init__(self):
        self.labels = ["Normal", "DoS / DDoS", "Probe / PortScan", "Ransomware", "SQL Injection / Exploit"]
        self.severities = {
            "Normal": 1,
            "Probe / PortScan": 4,
            "DoS / DDoS": 8,
            "SQL Injection / Exploit": 9,
            "Ransomware": 10
        }
        self.colors = {
            "Normal": "#00ff88",
            "Probe / PortScan": "#ffb700",
            "DoS / DDoS": "#ff6600",
            "SQL Injection / Exploit": "#ff0055",
            "Ransomware": "#ff0000"
        }
        self.ml_model = None
        if ML_AVAILABLE:
            self._train_dummy_model()

    def _train_dummy_model(self):
        # Synthetic dataset for cyber threat classification
        # Features: [packet_rate_per_sec, byte_size, entropy, failed_attempts, port_range_count]
        X = np.array([
            [15, 250, 2.1, 0, 1],       # Normal
            [25, 450, 3.0, 0, 1],       # Normal
            [50, 120, 1.8, 0, 1],       # Normal
            [1200, 64, 0.5, 0, 1],      # DoS / DDoS
            [2500, 128, 0.8, 2, 1],     # DoS / DDoS
            [800, 50, 0.4, 0, 1],       # DoS / DDoS
            [150, 40, 1.2, 0, 50],      # Probe / PortScan
            [300, 60, 1.5, 0, 150],     # Probe / PortScan
            [200, 32, 1.1, 0, 80],      # Probe / PortScan
            [30, 8500, 7.8, 1, 2],      # Ransomware (High entropy file payload)
            [15, 14000, 7.9, 0, 1],     # Ransomware
            [40, 9200, 7.6, 3, 2],      # Ransomware
            [5, 1200, 4.5, 5, 1],       # SQL Injection / Exploit
            [8, 2100, 4.8, 12, 1],      # SQL Injection / Exploit
            [12, 1800, 4.2, 8, 1]       # SQL Injection / Exploit
        ])
        y = np.array([0, 0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4])
        self.ml_model = RandomForestClassifier(n_estimators=10, random_state=42)
        self.ml_model.fit(X, y)

    def classify(self, packet_rate, byte_size, entropy, failed_attempts=0, port_count=1):
        """
        Classifies incoming network payload parameters.
        Returns dict with threat_type, severity, confidence, risk_score, color, recommended_action.
        """
        features = [packet_rate, byte_size, entropy, failed_attempts, port_count]

        if self.ml_model is not None:
            try:
                probs = self.ml_model.predict_proba([features])[0]
                idx = np.argmax(probs)
                confidence = float(probs[idx] * 100)
                threat_name = self.labels[idx]
            except Exception:
                threat_name, confidence = self._rule_based_fallback(features)
        else:
            threat_name, confidence = self._rule_based_fallback(features)

        severity = self.severities.get(threat_name, 5)
        color = self.colors.get(threat_name, "#ffb700")

        # Dynamic mitigation action
        mitigations = {
            "Normal": "No action required. Traffic authenticated.",
            "Probe / PortScan": "Enable Rate-limiting and dynamic port-hiding firewall policy.",
            "DoS / DDoS": "Trigger SYN Proxy & Auto-nullroute attacker IP range.",
            "SQL Injection / Exploit": "Block IP instantly and trigger Web Application Firewall (WAF) rule.",
            "Ransomware": "Isolate target endpoint from network & trigger automated snapshot backup."
        }

        risk_score = min(100, int((severity * 9.5) + (confidence * 0.05)))

        return {
            "threat_type": threat_name,
            "severity": severity,
            "confidence": round(confidence, 1),
            "risk_score": risk_score,
            "color": color,
            "mitigation": mitigations.get(threat_name, "Apply standard security sandbox rule."),
            "features_analyzed": {
                "packet_rate": packet_rate,
                "byte_size": byte_size,
                "entropy": entropy,
                "failed_attempts": failed_attempts,
                "port_count": port_count
            }
        }

    def _rule_based_fallback(self, features):
        packet_rate, byte_size, entropy, failed_attempts, port_count = features
        if packet_rate > 500:
            return "DoS / DDoS", 95.0
        elif port_count > 20:
            return "Probe / PortScan", 91.0
        elif entropy > 7.0:
            return "Ransomware", 94.0
        elif failed_attempts > 4 or byte_size > 1000:
            return "SQL Injection / Exploit", 88.0
        else:
            return "Normal", 98.0

# Singleton instance
classifier = AegisThreatClassifier()
