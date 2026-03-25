"""
CyberGuard-AI Data Processor
Extracts ML features from raw packet data and runs heuristic threat detection.
"""

import numpy as np
from collections import defaultdict
import time
import math


class DataProcessor:
    """Processes raw network packets into ML-ready feature vectors
    and runs rule-based anomaly detection."""

    def __init__(self):
        self.traffic_stats = defaultdict(lambda: {
            'packet_count': 0,
            'total_size': 0,
            'unique_src_ports': set(),
            'unique_dst_ports': set(),
            'protocols': defaultdict(int),
            'first_seen': time.time(),
            'last_seen': time.time(),
            'syn_count': 0,
            'burst_timestamps': [],
        })

        # Known suspicious ports
        self.suspicious_ports = {
            22: 'SSH', 23: 'Telnet', 135: 'MSRPC', 139: 'NetBIOS',
            445: 'SMB', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP',
            4444: 'Metasploit', 5900: 'VNC', 8080: 'HTTP-Alt',
            6667: 'IRC', 31337: 'Back Orifice',
        }

        # Known attack signatures
        self.attack_signatures = {
            'syn_flood': {'min_syn_rate': 50, 'score': 45},
            'port_scan': {'min_port_diversity': 0.6, 'score': 35},
            'brute_force': {'ports': [22, 3389, 21], 'min_count': 20, 'score': 30},
            'dns_amplification': {'port': 53, 'min_size': 512, 'score': 40},
        }

    def extract_features(self, packets):
        """Convert raw packets to ML feature vectors (15 features)."""
        if not packets:
            return np.array([])

        features = []
        for packet in packets:
            src_ip = packet.get('src_ip', '0.0.0.0')
            stats = self.traffic_stats[src_ip]

            # Update running statistics
            now = time.time()
            stats['packet_count'] += 1
            stats['total_size'] += packet.get('packet_size', 0)
            stats['protocols'][packet.get('protocol', 'TCP')] += 1
            stats['last_seen'] = now

            src_port = packet.get('src_port', 0)
            dst_port = packet.get('dst_port', 0)
            if src_port:
                stats['unique_src_ports'].add(src_port)
            if dst_port:
                stats['unique_dst_ports'].add(dst_port)

            flags = packet.get('flags', 0)
            if flags == 0x02:  # SYN flag
                stats['syn_count'] += 1

            # Track burst timestamps (keep last 100)
            stats['burst_timestamps'].append(now)
            if len(stats['burst_timestamps']) > 100:
                stats['burst_timestamps'] = stats['burst_timestamps'][-100:]

            # Compute derived features
            elapsed = max(0.1, now - stats['first_seen'])
            pkt_count = stats['packet_count']
            unique_dst = len(stats['unique_dst_ports'])

            packets_per_sec = pkt_count / elapsed
            bytes_per_sec = stats['total_size'] / elapsed
            port_diversity = unique_dst / max(1, pkt_count)
            syn_ratio = stats['syn_count'] / max(1, pkt_count)

            # Burst rate: packets in last 5 seconds
            recent = [t for t in stats['burst_timestamps'] if now - t < 5]
            burst_rate = len(recent) / 5.0

            # Entropy of port distribution
            port_entropy = self._calculate_entropy(stats['unique_dst_ports'], pkt_count)

            feature_vector = [
                src_port,                                           # 0: source port
                dst_port,                                           # 1: destination port
                packet.get('packet_size', 0),                       # 2: packet size
                1 if packet.get('protocol') == 'TCP' else 0,       # 3: is TCP
                1 if packet.get('protocol') == 'UDP' else 0,       # 4: is UDP
                1 if packet.get('protocol') == 'ICMP' else 0,      # 5: is ICMP
                flags,                                              # 6: TCP flags
                packets_per_sec,                                    # 7: packets/sec
                bytes_per_sec,                                      # 8: bytes/sec
                unique_dst,                                         # 9: unique dst ports
                port_diversity,                                     # 10: port diversity ratio
                syn_ratio,                                          # 11: SYN ratio
                burst_rate,                                         # 12: burst rate
                port_entropy,                                       # 13: port entropy
                1 if dst_port in self.suspicious_ports else 0,      # 14: suspicious port flag
            ]
            features.append(feature_vector)

        return np.array(features)

    def _calculate_entropy(self, port_set, total_packets):
        """Calculate Shannon entropy of unique ports."""
        if not port_set or total_packets == 0:
            return 0.0
        n = len(port_set)
        if n <= 1:
            return 0.0
        prob = 1.0 / n
        return -n * prob * math.log2(prob)

    def detect_anomalies_heuristic(self, packets):
        """Rule-based anomaly detection with attack classification."""
        anomalies = []

        for packet in packets:
            score = 0
            indicators = []
            attack_type = 'Unknown'
            src_ip = packet.get('src_ip', '')
            stats = self.traffic_stats.get(src_ip)

            if not stats:
                continue

            pkt_count = stats['packet_count']
            elapsed = max(0.1, stats['last_seen'] - stats['first_seen'])

            # --- DDoS / High volume detection ---
            pps = pkt_count / elapsed
            if pps > 100:
                score += 40
                indicators.append(f'High packet rate: {pps:.0f} pkt/s')
                attack_type = 'DDoS'
            elif pps > 50:
                score += 20
                indicators.append(f'Elevated traffic: {pps:.0f} pkt/s')

            # --- SYN flood detection ---
            if stats['syn_count'] > 50:
                syn_ratio = stats['syn_count'] / max(1, pkt_count)
                if syn_ratio > 0.8:
                    score += 45
                    indicators.append(f'SYN flood: {stats["syn_count"]} SYNs ({syn_ratio:.0%})')
                    attack_type = 'SYN Flood'

            # --- Port scanning ---
            unique_dst = len(stats['unique_dst_ports'])
            port_div = unique_dst / max(1, pkt_count)
            if port_div > 0.6 and unique_dst > 10:
                score += 35
                indicators.append(f'Port scan: {unique_dst} unique ports')
                attack_type = 'Port Scan'
            elif port_div > 0.4 and unique_dst > 5:
                score += 15
                indicators.append(f'Port diversity: {unique_dst} ports')

            # --- Brute force detection ---
            dst_port = packet.get('dst_port', 0)
            if dst_port in [22, 3389, 21, 23, 5900]:
                if pkt_count > 20:
                    score += 30
                    indicators.append(f'Brute force on port {dst_port}')
                    attack_type = 'Brute Force'

            # --- Suspicious port access ---
            if dst_port in self.suspicious_ports:
                port_name = self.suspicious_ports[dst_port]
                score += 15
                indicators.append(f'Suspicious port: {dst_port} ({port_name})')

            # --- DNS amplification ---
            if dst_port == 53 and packet.get('packet_size', 0) > 512:
                score += 40
                indicators.append('DNS amplification pattern')
                attack_type = 'DNS Amplification'

            # --- Large packets (potential exfiltration) ---
            pkt_size = packet.get('packet_size', 0)
            if pkt_size > 8000:
                score += 10
                indicators.append(f'Large packet: {pkt_size} bytes')

            # --- TCP flag anomalies ---
            flags = packet.get('flags', 0)
            if flags == 0x29:  # FIN+PSH+URG (Xmas scan)
                score += 35
                indicators.append('Xmas scan detected')
                attack_type = 'Xmas Scan'
            elif flags == 0x00 and packet.get('protocol') == 'TCP':  # Null scan
                score += 30
                indicators.append('Null scan detected')
                attack_type = 'Null Scan'

            if score > 20:
                anomalies.append({
                    'src_ip': src_ip,
                    'dst_ip': packet.get('dst_ip', ''),
                    'threat_score': min(100, score),
                    'indicators': indicators,
                    'attack_type': attack_type,
                    'timestamp': packet.get('timestamp'),
                    'protocol': packet.get('protocol', 'TCP'),
                    'src_port': packet.get('src_port', 0),
                    'dst_port': dst_port,
                    'packet_size': pkt_size,
                })

        return anomalies

    def get_ip_reputation(self, ip: str) -> dict:
        """Get accumulated stats for an IP address."""
        stats = self.traffic_stats.get(ip)
        if not stats:
            return {'ip': ip, 'risk': 'unknown', 'packet_count': 0}

        pkt_count = stats['packet_count']
        elapsed = max(0.1, stats['last_seen'] - stats['first_seen'])
        pps = pkt_count / elapsed

        risk = 'low'
        if pps > 100 or stats['syn_count'] > 50:
            risk = 'critical'
        elif pps > 50 or len(stats['unique_dst_ports']) > 20:
            risk = 'high'
        elif pps > 20:
            risk = 'medium'

        return {
            'ip': ip,
            'risk': risk,
            'packet_count': pkt_count,
            'packets_per_second': round(pps, 2),
            'unique_ports': len(stats['unique_dst_ports']),
            'syn_count': stats['syn_count'],
            'total_bytes': stats['total_size'],
            'duration_seconds': round(elapsed, 1),
        }

    def reset_stats(self):
        """Clear all accumulated traffic statistics."""
        self.traffic_stats.clear()
