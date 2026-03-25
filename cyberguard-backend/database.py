"""
SQLite persistence layer for CyberGuard-AI threat intelligence data.
Stores threat logs, blocked IPs, and system settings.
"""

import sqlite3
import json
import os
from datetime import datetime
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), 'cyberguard.db')


@contextmanager
def get_db():
    """Context manager for database connections."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Initialize database tables."""
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                threat_score REAL NOT NULL,
                prediction INTEGER DEFAULT 0,
                indicators TEXT DEFAULT '[]',
                protocol TEXT DEFAULT 'TCP',
                src_port INTEGER DEFAULT 0,
                dst_port INTEGER DEFAULT 0,
                packet_size INTEGER DEFAULT 0,
                timestamp TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                reason TEXT DEFAULT '',
                blocked_at TEXT DEFAULT (datetime('now')),
                is_active INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_threats_level ON threats(threat_level);
            CREATE INDEX IF NOT EXISTS idx_threats_src_ip ON threats(src_ip);
            CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp);
            CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip);
        """)

        # Insert default settings
        defaults = {
            'simulation_mode': 'true',
            'scan_interval': '3',
            'auto_block_critical': 'false',
            'threat_retention_hours': '24',
            'max_threats_display': '200',
        }
        for key, value in defaults.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
                (key, value)
            )


def insert_threat(threat: dict):
    """Insert a single threat record."""
    with get_db() as conn:
        conn.execute("""
            INSERT INTO threats (src_ip, dst_ip, threat_level, threat_score,
                prediction, indicators, protocol, src_port, dst_port,
                packet_size, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            threat.get('src_ip', ''),
            threat.get('dst_ip', ''),
            threat.get('threat_level', 'NORMAL'),
            threat.get('threat_score', 0),
            threat.get('prediction', 0),
            json.dumps(threat.get('indicators', [])),
            threat.get('protocol', 'TCP'),
            threat.get('src_port', 0),
            threat.get('dst_port', 0),
            threat.get('packet_size', 0),
            threat.get('timestamp', datetime.now().isoformat()),
        ))


def insert_threats_batch(threats: list):
    """Insert multiple threat records efficiently."""
    with get_db() as conn:
        conn.executemany("""
            INSERT INTO threats (src_ip, dst_ip, threat_level, threat_score,
                prediction, indicators, protocol, src_port, dst_port,
                packet_size, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [(
            t.get('src_ip', ''),
            t.get('dst_ip', ''),
            t.get('threat_level', 'NORMAL'),
            t.get('threat_score', 0),
            t.get('prediction', 0),
            json.dumps(t.get('indicators', [])),
            t.get('protocol', 'TCP'),
            t.get('src_port', 0),
            t.get('dst_port', 0),
            t.get('packet_size', 0),
            t.get('timestamp', datetime.now().isoformat()),
        ) for t in threats])


def get_threats(limit=100, level=None, src_ip=None):
    """Retrieve threats with optional filtering."""
    with get_db() as conn:
        query = "SELECT * FROM threats"
        params = []
        conditions = []

        if level and level != 'ALL':
            conditions.append("threat_level = ?")
            params.append(level)
        if src_ip:
            conditions.append("src_ip = ?")
            params.append(src_ip)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]


def get_threat_stats():
    """Get aggregated threat statistics."""
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        critical = conn.execute(
            "SELECT COUNT(*) FROM threats WHERE threat_level='CRITICAL'"
        ).fetchone()[0]
        high = conn.execute(
            "SELECT COUNT(*) FROM threats WHERE threat_level='HIGH'"
        ).fetchone()[0]
        medium = conn.execute(
            "SELECT COUNT(*) FROM threats WHERE threat_level='MEDIUM'"
        ).fetchone()[0]
        normal = conn.execute(
            "SELECT COUNT(*) FROM threats WHERE threat_level='NORMAL'"
        ).fetchone()[0]
        blocked = conn.execute(
            "SELECT COUNT(*) FROM blocked_ips WHERE is_active=1"
        ).fetchone()[0]

        # Top attackers
        top_attackers = conn.execute("""
            SELECT src_ip, COUNT(*) as count,
                   AVG(threat_score) as avg_score,
                   MAX(threat_level) as max_level
            FROM threats
            WHERE threat_level != 'NORMAL'
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT 10
        """).fetchall()

        # Protocol distribution
        protocols = conn.execute("""
            SELECT protocol, COUNT(*) as count
            FROM threats
            GROUP BY protocol
            ORDER BY count DESC
        """).fetchall()

        # Threats per minute (last 10 minutes)
        timeline = conn.execute("""
            SELECT strftime('%H:%M', timestamp) as minute,
                   COUNT(*) as count,
                   SUM(CASE WHEN threat_level='CRITICAL' THEN 1 ELSE 0 END) as critical,
                   SUM(CASE WHEN threat_level='HIGH' THEN 1 ELSE 0 END) as high
            FROM threats
            GROUP BY minute
            ORDER BY minute DESC
            LIMIT 20
        """).fetchall()

        return {
            'total_packets_analyzed': total,
            'critical_threats': critical,
            'high_threats': high,
            'medium_threats': medium,
            'normal_packets': normal,
            'blocked_ips_count': blocked,
            'top_attackers': [dict(a) for a in top_attackers],
            'protocol_distribution': [dict(p) for p in protocols],
            'timeline': [dict(t) for t in reversed(list(timeline))],
        }


def block_ip(ip: str, reason: str = ''):
    """Block an IP address."""
    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip, reason, is_active) VALUES (?, ?, 1)",
            (ip, reason)
        )


def unblock_ip(ip: str):
    """Unblock an IP address."""
    with get_db() as conn:
        conn.execute(
            "UPDATE blocked_ips SET is_active = 0 WHERE ip = ?", (ip,)
        )


def get_blocked_ips():
    """Get all actively blocked IPs."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM blocked_ips WHERE is_active = 1 ORDER BY blocked_at DESC"
        ).fetchall()
        return [dict(row) for row in rows]


def is_ip_blocked(ip: str) -> bool:
    """Check if an IP is blocked."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT 1 FROM blocked_ips WHERE ip = ? AND is_active = 1", (ip,)
        ).fetchone()
        return row is not None


def get_setting(key: str, default: str = '') -> str:
    """Get a setting value."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
        return row['value'] if row else default


def update_setting(key: str, value: str):
    """Update a setting value."""
    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'))",
            (key, value)
        )


def get_all_settings() -> dict:
    """Get all settings as a dictionary."""
    with get_db() as conn:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        return {row['key']: row['value'] for row in rows}


def cleanup_old_threats(hours: int = 24):
    """Remove threats older than specified hours."""
    with get_db() as conn:
        conn.execute(
            "DELETE FROM threats WHERE created_at < datetime('now', ?)",
            (f'-{hours} hours',)
        )
