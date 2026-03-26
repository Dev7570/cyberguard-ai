"""
CyberGuard-AI Network Monitor
Provides real-time network traffic data via simulation or live capture.
"""

import random
import time
import threading
import logging
import psutil
from datetime import datetime

logger = logging.getLogger(__name__)


# Realistic IP pools for simulation
INTERNAL_IPS = [
    '192.168.1.10', '192.168.1.15', '192.168.1.20', '192.168.1.25',
    '192.168.1.30', '192.168.1.50', '192.168.1.100', '192.168.1.105',
    '10.0.0.5', '10.0.0.12', '10.0.0.50', '10.0.0.100',
    '172.16.0.10', '172.16.0.25', '172.16.0.100',
]

EXTERNAL_IPS = [
    '8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9',                      # DNS
    '142.250.80.46', '142.250.185.238', '172.217.14.206',              # Google
    '157.240.1.35', '157.240.22.35',                                    # Facebook
    '104.244.42.1', '104.244.42.65',                                    # Twitter
    '52.94.236.248', '54.239.28.85', '13.35.0.1',                     # AWS
    '20.190.159.0', '13.107.42.14', '40.126.32.68',                   # Microsoft
    '151.101.1.140', '151.101.65.140',                                  # Reddit
]

ATTACKER_IPS = [
    '45.227.255.200', '185.220.101.33', '89.248.167.131',
    '92.63.197.48', '195.54.160.149', '141.98.11.105',
    '185.56.80.65', '193.106.191.50', '45.148.10.85',
    '103.203.57.100', '91.240.118.172', '179.43.175.50',
]

COMMON_PORTS = [80, 443, 8080, 8443, 53, 993, 587, 25, 3306, 5432]
SUSPICIOUS_PORTS = [22, 23, 135, 139, 445, 3389, 4444, 5900, 6667, 31337]


class SimulatedMonitor:
    """Generates realistic simulated network traffic for demo/development."""

    def __init__(self):
        self.is_running = False
        self._thread = None
        self._packet_buffer = []
        self._lock = threading.Lock()
        self._attack_mode = None
        self._attack_timer = 0
        self._packets_generated = 0

    def start(self):
        """Start generating simulated traffic."""
        self.is_running = True
        self._thread = threading.Thread(target=self._generate_loop, daemon=True)
        self._thread.start()
        logger.info("Simulated network monitor started")

    def stop(self):
        """Stop traffic generation."""
        self.is_running = False
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("Simulated network monitor stopped")

    def get_packets(self):
        """Retrieve and clear the packet buffer."""
        with self._lock:
            packets = list(self._packet_buffer)
            self._packet_buffer.clear()
            return packets

    def inject_packets(self, packets):
        """Programmatically inject packets into the monitor buffer."""
        with self._lock:
            if isinstance(packets, list):
                self._packet_buffer.extend(packets)
            else:
                self._packet_buffer.append(packets)

    def _generate_loop(self):
        """Continuously generate packets."""
        while self.is_running:
            batch = self._generate_batch()
            with self._lock:
                self._packet_buffer.extend(batch)
            time.sleep(random.uniform(0.8, 2.0))

    def _generate_batch(self):
        """Generate a batch of mixed traffic."""
        batch = []
        batch_size = random.randint(3, 12)

        # Randomly trigger attack phases
        self._attack_timer -= 1
        if self._attack_timer <= 0:
            if random.random() < 0.25:  # 25% chance to start an attack
                self._attack_mode = random.choice([
                    'syn_flood', 'port_scan', 'brute_force',
                    'ddos', 'dns_amplification', None
                ])
                self._attack_timer = random.randint(5, 20)
                if self._attack_mode:
                    logger.debug(f"Simulating attack: {self._attack_mode}")
            else:
                self._attack_mode = None
                self._attack_timer = random.randint(3, 10)

        for _ in range(batch_size):
            if self._attack_mode and random.random() < 0.6:
                packet = self._generate_attack_packet(self._attack_mode)
            else:
                packet = self._generate_normal_packet()

            self._packets_generated += 1
            batch.append(packet)

        return batch

    def _generate_normal_packet(self):
        """Generate a normal/benign packet."""
        protocol = random.choices(['TCP', 'UDP', 'ICMP'], weights=[70, 25, 5])[0]

        return {
            'src_ip': random.choice(INTERNAL_IPS),
            'dst_ip': random.choice(EXTERNAL_IPS),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice(COMMON_PORTS),
            'protocol': protocol,
            'packet_size': random.randint(64, 1500),
            'flags': random.choice([0x10, 0x18, 0x11, 0x02]) if protocol == 'TCP' else 0,
            'timestamp': datetime.now().isoformat(),
        }

    def _generate_attack_packet(self, attack_type):
        """Generate an attack packet based on pattern."""
        attacker = random.choice(ATTACKER_IPS)
        target = random.choice(INTERNAL_IPS)
        now = datetime.now().isoformat()

        if attack_type == 'syn_flood':
            return {
                'src_ip': attacker,
                'dst_ip': target,
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 8080]),
                'protocol': 'TCP',
                'packet_size': 60,
                'flags': 0x02,  # SYN
                'timestamp': now,
            }

        elif attack_type == 'port_scan':
            return {
                'src_ip': attacker,
                'dst_ip': target,
                'src_port': random.randint(1024, 65535),
                'dst_port': random.randint(1, 1024),
                'protocol': 'TCP',
                'packet_size': random.randint(40, 80),
                'flags': random.choice([0x02, 0x29, 0x00]),  # SYN, Xmas, Null
                'timestamp': now,
            }

        elif attack_type == 'brute_force':
            return {
                'src_ip': attacker,
                'dst_ip': target,
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([22, 3389, 21, 23]),
                'protocol': 'TCP',
                'packet_size': random.randint(100, 400),
                'flags': 0x18,  # PSH+ACK
                'timestamp': now,
            }

        elif attack_type == 'ddos':
            return {
                'src_ip': f'{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}',
                'dst_ip': target,
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443]),
                'protocol': random.choice(['TCP', 'UDP']),
                'packet_size': random.randint(800, 1500),
                'flags': 0x02 if random.random() > 0.5 else 0x10,
                'timestamp': now,
            }

        elif attack_type == 'dns_amplification':
            return {
                'src_ip': attacker,
                'dst_ip': target,
                'src_port': 53,
                'dst_port': random.randint(1024, 65535),
                'protocol': 'UDP',
                'packet_size': random.randint(512, 4096),
                'flags': 0,
                'timestamp': now,
            }

        return self._generate_normal_packet()

    @property
    def stats(self):
        """Get monitor statistics."""
        return {
            'type': 'simulated',
            'is_running': self.is_running,
            'packets_generated': self._packets_generated,
            'attack_mode': self._attack_mode,
            'buffer_size': len(self._packet_buffer),
        }


class LiveMonitor:
    """Real network monitoring using psutil (no Npcap required).
    Captures network connection data and converts to packet-like format."""

    def __init__(self):
        self.is_running = False
        self._thread = None
        self._packet_buffer = []
        self._lock = threading.Lock()
        self._seen_connections = set()
        self._packets_captured = 0

    def start(self):
        """Start monitoring real network connections."""
        self.is_running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("Live network monitor started (psutil mode)")

    def stop(self):
        """Stop monitoring."""
        self.is_running = False
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("Live network monitor stopped")

    def get_packets(self):
        """Retrieve and clear the packet buffer."""
        with self._lock:
            packets = list(self._packet_buffer)
            self._packet_buffer.clear()
            return packets

    def inject_packets(self, packets):
        """Programmatically inject packets into the monitor buffer."""
        with self._lock:
            if isinstance(packets, list):
                self._packet_buffer.extend(packets)
            else:
                self._packet_buffer.append(packets)

    def _monitor_loop(self):
        """Continuously poll for network connections."""
        while self.is_running:
            try:
                connections = psutil.net_connections(kind='inet')
                now = datetime.now().isoformat()
                new_packets = []

                for conn in connections:
                    if conn.status == 'NONE':
                        continue

                    # Build a connection key for deduplication
                    laddr = conn.laddr
                    raddr = conn.raddr
                    if not raddr:
                        continue

                    conn_key = (laddr.ip, laddr.port, raddr.ip, raddr.port)

                    # Only emit "new" connections or re-emit periodically
                    if conn_key not in self._seen_connections:
                        self._seen_connections.add(conn_key)

                        # Determine protocol
                        proto = 'TCP' if conn.type == 1 else 'UDP'

                        packet = {
                            'src_ip': raddr.ip if raddr.ip != '0.0.0.0' else '127.0.0.1',
                            'dst_ip': laddr.ip if laddr.ip != '0.0.0.0' else '127.0.0.1',
                            'src_port': raddr.port,
                            'dst_port': laddr.port,
                            'protocol': proto,
                            'packet_size': random.randint(64, 1500),
                            'flags': 0x10,  # ACK (established)
                            'timestamp': now,
                        }
                        new_packets.append(packet)
                        self._packets_captured += 1

                if new_packets:
                    with self._lock:
                        self._packet_buffer.extend(new_packets)

                # Clear old connections periodically
                if len(self._seen_connections) > 5000:
                    self._seen_connections.clear()

            except (psutil.AccessDenied, PermissionError):
                logger.warning("Access denied for network connections. Run as administrator.")
            except Exception as e:
                logger.error(f"Monitor error: {e}")

            time.sleep(2)

    @property
    def stats(self):
        """Get monitor statistics."""
        return {
            'type': 'live',
            'is_running': self.is_running,
            'packets_captured': self._packets_captured,
            'buffer_size': len(self._packet_buffer),
        }


def get_network_interfaces():
    """List available network interfaces with their addresses."""
    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for name, addr_list in addrs.items():
        iface = {
            'name': name,
            'is_up': stats[name].isup if name in stats else False,
            'speed': stats[name].speed if name in stats else 0,
            'addresses': [],
        }
        for addr in addr_list:
            if addr.family.name == 'AF_INET':
                iface['addresses'].append({
                    'ip': addr.address,
                    'netmask': addr.netmask,
                    'type': 'IPv4',
                })
        interfaces.append(iface)

    return interfaces


def get_system_network_stats():
    """Get current system network counters."""
    counters = psutil.net_io_counters()
    return {
        'bytes_sent': counters.bytes_sent,
        'bytes_recv': counters.bytes_recv,
        'packets_sent': counters.packets_sent,
        'packets_recv': counters.packets_recv,
        'errors_in': counters.errin,
        'errors_out': counters.errout,
        'drops_in': counters.dropin,
        'drops_out': counters.dropout,
    }


def create_monitor(mode='simulate'):
    """Factory function to create the appropriate monitor.

    Args:
        mode: 'simulate' for demo traffic, 'live' for real network monitoring
    """
    if mode == 'live':
        return LiveMonitor()
    return SimulatedMonitor()
