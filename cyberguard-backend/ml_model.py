"""
CyberGuard-AI Machine Learning Models
Random Forest classifier + Isolation Forest anomaly detector.
"""

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np
import joblib
import os
import logging

logger = logging.getLogger(__name__)

MODEL_DIR = os.path.join(os.path.dirname(__file__), 'models')


class ThreatDetectionModel:
    """Combined threat detection using Random Forest + Isolation Forest."""

    def __init__(self):
        os.makedirs(MODEL_DIR, exist_ok=True)
        self.rf_path = os.path.join(MODEL_DIR, 'random_forest.pkl')
        self.iso_path = os.path.join(MODEL_DIR, 'isolation_forest.pkl')
        self.scaler_path = os.path.join(MODEL_DIR, 'scaler.pkl')

        self.scaler = StandardScaler()
        self.rf_model = None
        self.iso_model = None
        self.is_trained = False

        # Try loading existing models
        if all(os.path.exists(p) for p in [self.rf_path, self.iso_path, self.scaler_path]):
            self._load_models()
        else:
            self._init_models()

    def _init_models(self):
        """Initialize fresh models."""
        self.rf_model = RandomForestClassifier(
            n_estimators=150,
            max_depth=18,
            min_samples_split=4,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
        )
        self.iso_model = IsolationForest(
            n_estimators=100,
            contamination=0.15,
            random_state=42,
            n_jobs=-1,
        )

    def train(self, X, y):
        """Train both models on labeled data."""
        logger.info(f"Training on {len(X)} samples...")

        # Fit scaler
        X_scaled = self.scaler.fit_transform(X)

        # Train Random Forest (supervised)
        self.rf_model.fit(X_scaled, y)

        # Train Isolation Forest (unsupervised — learns normal patterns)
        normal_mask = y == 0
        if normal_mask.sum() > 50:
            self.iso_model.fit(X_scaled[normal_mask])
        else:
            self.iso_model.fit(X_scaled)

        self.is_trained = True
        self._save_models()

        # Report accuracy on training data
        rf_acc = self.rf_model.score(X_scaled, y)
        logger.info(f"Training complete — RF accuracy: {rf_acc:.3f}")
        return rf_acc

    def predict(self, X):
        """Predict threat class: 0=benign, 1=malicious."""
        if not self.is_trained or len(X) == 0:
            return np.zeros(len(X))
        X_scaled = self.scaler.transform(X)
        return self.rf_model.predict(X_scaled)

    def predict_proba(self, X):
        """Get threat probability [P(benign), P(malicious)]."""
        if not self.is_trained or len(X) == 0:
            return np.column_stack([np.ones(len(X)), np.zeros(len(X))])
        X_scaled = self.scaler.transform(X)
        return self.rf_model.predict_proba(X_scaled)

    def detect_anomalies(self, X):
        """Use Isolation Forest to detect anomalies. Returns -1 for anomalies, 1 for normal."""
        if not self.is_trained or len(X) == 0:
            return np.ones(len(X))
        X_scaled = self.scaler.transform(X)
        return self.iso_model.predict(X_scaled)

    def anomaly_scores(self, X):
        """Get anomaly scores. Lower = more anomalous."""
        if not self.is_trained or len(X) == 0:
            return np.zeros(len(X))
        X_scaled = self.scaler.transform(X)
        return self.iso_model.decision_function(X_scaled)

    def get_feature_importance(self):
        """Get Random Forest feature importances."""
        if not self.is_trained:
            return {}
        names = [
            'src_port', 'dst_port', 'packet_size', 'is_tcp', 'is_udp',
            'is_icmp', 'tcp_flags', 'packets_per_sec', 'bytes_per_sec',
            'unique_dst_ports', 'port_diversity', 'syn_ratio',
            'burst_rate', 'port_entropy', 'suspicious_port',
        ]
        importances = self.rf_model.feature_importances_
        result = dict(zip(names, [round(float(v), 4) for v in importances]))
        return dict(sorted(result.items(), key=lambda x: x[1], reverse=True))

    def _save_models(self):
        """Persist models to disk."""
        joblib.dump(self.rf_model, self.rf_path)
        joblib.dump(self.iso_model, self.iso_path)
        joblib.dump(self.scaler, self.scaler_path)
        logger.info("Models saved to disk")

    def _load_models(self):
        """Load models from disk."""
        try:
            self.rf_model = joblib.load(self.rf_path)
            self.iso_model = joblib.load(self.iso_path)
            self.scaler = joblib.load(self.scaler_path)
            self.is_trained = True
            logger.info("Models loaded from disk")
        except Exception as e:
            logger.warning(f"Failed to load models: {e}. Re-initializing.")
            self._init_models()


def generate_training_data(n_samples=15000):
    """Generate realistic synthetic training data with labeled attack patterns.

    Creates data for 15 features matching the DataProcessor output.
    Labels: 0 = benign, 1 = malicious
    """
    rng = np.random.RandomState(42)

    # === BENIGN TRAFFIC (70%) ===
    n_benign = int(n_samples * 0.7)
    benign = np.zeros((n_benign, 15))

    # Normal web browsing
    benign[:, 0] = rng.randint(1024, 65535, n_benign)       # src_port: ephemeral
    benign[:, 1] = rng.choice([80, 443, 8080, 8443], n_benign)  # dst_port: HTTP/HTTPS
    benign[:, 2] = rng.normal(500, 200, n_benign).clip(64, 1500)  # packet_size
    benign[:, 3] = rng.choice([0, 1], n_benign, p=[0.2, 0.8])  # is_tcp
    benign[:, 4] = rng.choice([0, 1], n_benign, p=[0.8, 0.2])  # is_udp
    benign[:, 5] = 0                                         # is_icmp
    benign[:, 6] = rng.choice([0x10, 0x18, 0x11], n_benign)  # tcp_flags: ACK, PSH+ACK, FIN+ACK
    benign[:, 7] = rng.uniform(0.5, 15, n_benign)            # packets_per_sec
    benign[:, 8] = rng.uniform(100, 5000, n_benign)          # bytes_per_sec
    benign[:, 9] = rng.randint(1, 5, n_benign)               # unique_dst_ports
    benign[:, 10] = rng.uniform(0.01, 0.15, n_benign)        # port_diversity
    benign[:, 11] = rng.uniform(0.0, 0.15, n_benign)         # syn_ratio
    benign[:, 12] = rng.uniform(0.1, 5, n_benign)            # burst_rate
    benign[:, 13] = rng.uniform(0, 2, n_benign)              # port_entropy
    benign[:, 14] = 0                                         # suspicious_port

    y_benign = np.zeros(n_benign)

    # === ATTACK TRAFFIC (30%) ===
    n_attack = n_samples - n_benign
    attacks = []
    y_attack = []

    # --- SYN Flood (8%) ---
    n_syn = int(n_samples * 0.08)
    syn = np.zeros((n_syn, 15))
    syn[:, 0] = rng.randint(1024, 65535, n_syn)
    syn[:, 1] = rng.choice([80, 443, 22, 3389], n_syn)
    syn[:, 2] = 60  # SYN packets are small
    syn[:, 3] = 1   # TCP
    syn[:, 6] = 0x02  # SYN flag
    syn[:, 7] = rng.uniform(80, 500, n_syn)     # High pps
    syn[:, 8] = rng.uniform(4000, 30000, n_syn)
    syn[:, 9] = rng.randint(1, 3, n_syn)
    syn[:, 10] = rng.uniform(0.01, 0.05, n_syn)
    syn[:, 11] = rng.uniform(0.8, 1.0, n_syn)   # Very high SYN ratio
    syn[:, 12] = rng.uniform(20, 100, n_syn)     # High burst
    syn[:, 13] = rng.uniform(0, 1, n_syn)
    syn[:, 14] = 0
    attacks.append(syn)
    y_attack.extend([1] * n_syn)

    # --- Port Scan (7%) ---
    n_scan = int(n_samples * 0.07)
    scan = np.zeros((n_scan, 15))
    scan[:, 0] = rng.randint(1024, 65535, n_scan)
    scan[:, 1] = rng.randint(1, 1024, n_scan)    # Scanning low ports
    scan[:, 2] = rng.normal(60, 10, n_scan).clip(40, 120)  # Small probes
    scan[:, 3] = 1
    scan[:, 6] = 0x02  # SYN probes
    scan[:, 7] = rng.uniform(30, 200, n_scan)
    scan[:, 8] = rng.uniform(1500, 10000, n_scan)
    scan[:, 9] = rng.randint(20, 200, n_scan)     # Many unique ports
    scan[:, 10] = rng.uniform(0.5, 1.0, n_scan)   # High port diversity
    scan[:, 11] = rng.uniform(0.6, 0.95, n_scan)
    scan[:, 12] = rng.uniform(10, 50, n_scan)
    scan[:, 13] = rng.uniform(4, 8, n_scan)        # High entropy
    scan[:, 14] = rng.choice([0, 1], n_scan, p=[0.3, 0.7])
    attacks.append(scan)
    y_attack.extend([1] * n_scan)

    # --- Brute Force (5%) ---
    n_brute = int(n_samples * 0.05)
    brute = np.zeros((n_brute, 15))
    brute[:, 0] = rng.randint(1024, 65535, n_brute)
    brute[:, 1] = rng.choice([22, 3389, 21, 23, 5900], n_brute)  # SSH, RDP, etc.
    brute[:, 2] = rng.normal(200, 50, n_brute).clip(80, 400)
    brute[:, 3] = 1
    brute[:, 6] = rng.choice([0x02, 0x10, 0x18], n_brute)
    brute[:, 7] = rng.uniform(20, 80, n_brute)
    brute[:, 8] = rng.uniform(2000, 15000, n_brute)
    brute[:, 9] = 1  # Same port always
    brute[:, 10] = rng.uniform(0.01, 0.05, n_brute)
    brute[:, 11] = rng.uniform(0.1, 0.4, n_brute)
    brute[:, 12] = rng.uniform(5, 30, n_brute)
    brute[:, 13] = 0
    brute[:, 14] = 1  # Suspicious port
    attacks.append(brute)
    y_attack.extend([1] * n_brute)

    # --- DDoS volumetric (5%) ---
    n_ddos = int(n_samples * 0.05)
    ddos = np.zeros((n_ddos, 15))
    ddos[:, 0] = rng.randint(1024, 65535, n_ddos)
    ddos[:, 1] = rng.choice([80, 443, 53], n_ddos)
    ddos[:, 2] = rng.normal(1400, 100, n_ddos).clip(800, 1500)  # Max size
    ddos[:, 3] = rng.choice([0, 1], n_ddos, p=[0.4, 0.6])
    ddos[:, 4] = rng.choice([0, 1], n_ddos, p=[0.6, 0.4])
    ddos[:, 6] = rng.choice([0x02, 0x10], n_ddos)
    ddos[:, 7] = rng.uniform(150, 1000, n_ddos)   # Very high pps
    ddos[:, 8] = rng.uniform(20000, 100000, n_ddos)
    ddos[:, 9] = rng.randint(1, 5, n_ddos)
    ddos[:, 10] = rng.uniform(0.01, 0.1, n_ddos)
    ddos[:, 11] = rng.uniform(0.1, 0.5, n_ddos)
    ddos[:, 12] = rng.uniform(50, 200, n_ddos)
    ddos[:, 13] = rng.uniform(0, 2, n_ddos)
    ddos[:, 14] = 0
    attacks.append(ddos)
    y_attack.extend([1] * n_ddos)

    # --- DNS Amplification (3%) ---
    n_dns = int(n_samples * 0.03)
    dns = np.zeros((n_dns, 15))
    dns[:, 0] = 53
    dns[:, 1] = rng.randint(1024, 65535, n_dns)
    dns[:, 2] = rng.normal(3000, 500, n_dns).clip(512, 4096)  # Large DNS responses
    dns[:, 4] = 1  # UDP
    dns[:, 7] = rng.uniform(50, 300, n_dns)
    dns[:, 8] = rng.uniform(10000, 80000, n_dns)
    dns[:, 9] = 1
    dns[:, 10] = rng.uniform(0.01, 0.05, n_dns)
    dns[:, 12] = rng.uniform(15, 80, n_dns)
    dns[:, 13] = 0
    attacks.append(dns)
    y_attack.extend([1] * n_dns)

    # --- Remaining attacks (2%) — Xmas/Null scans ---
    n_xmas = n_attack - n_syn - n_scan - n_brute - n_ddos - n_dns
    if n_xmas > 0:
        xmas = np.zeros((n_xmas, 15))
        xmas[:, 0] = rng.randint(1024, 65535, n_xmas)
        xmas[:, 1] = rng.randint(1, 1024, n_xmas)
        xmas[:, 2] = 60
        xmas[:, 3] = 1
        xmas[:, 6] = rng.choice([0x29, 0x00], n_xmas)  # Xmas or Null
        xmas[:, 7] = rng.uniform(10, 60, n_xmas)
        xmas[:, 8] = rng.uniform(500, 3000, n_xmas)
        xmas[:, 9] = rng.randint(10, 100, n_xmas)
        xmas[:, 10] = rng.uniform(0.4, 0.9, n_xmas)
        xmas[:, 12] = rng.uniform(5, 20, n_xmas)
        xmas[:, 13] = rng.uniform(3, 6, n_xmas)
        xmas[:, 14] = rng.choice([0, 1], n_xmas, p=[0.5, 0.5])
        attacks.append(xmas)
        y_attack.extend([1] * n_xmas)

    # Combine and shuffle
    X = np.vstack([benign] + attacks)
    y = np.concatenate([y_benign, np.array(y_attack)])

    shuffle_idx = rng.permutation(len(X))
    return X[shuffle_idx], y[shuffle_idx]
