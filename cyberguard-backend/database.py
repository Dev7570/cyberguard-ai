"""
SQLite persistence layer for CyberGuard-AI threat intelligence data.
Stores threat logs, blocked IPs, and system settings.
"""

import sqlite3
import json
import os
import hashlib
import secrets
from datetime import datetime
from typing import Optional, Dict, List
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
                attack_type TEXT DEFAULT 'Normal',
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
                country TEXT DEFAULT 'Unknown',
                city TEXT DEFAULT 'Unknown',
                latitude REAL,
                longitude REAL,
                blocked_at TEXT DEFAULT (datetime('now')),
                is_active INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS blocked_countries (
                country_code TEXT PRIMARY KEY,
                country_name TEXT NOT NULL,
                blocked_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT DEFAULT 'admin',
                created_at TEXT DEFAULT (datetime('now'))
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

        # Migration: Add Geo-IP columns if missing
        for col, col_type in [('country', 'TEXT DEFAULT "Unknown"'), ('city', 'TEXT DEFAULT "Unknown"'), ('latitude', 'REAL'), ('longitude', 'REAL')]:
            try:
                conn.execute(f"ALTER TABLE blocked_ips ADD COLUMN {col} {col_type}")
            except sqlite3.OperationalError:
                pass  # Already exists


def insert_threat(threat: dict):
    """Insert a single threat record."""
    with get_db() as conn:
        conn.execute("""
            INSERT INTO threats (src_ip, dst_ip, threat_level, threat_score,
                prediction, indicators, attack_type, protocol, src_port, dst_port,
                packet_size, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            threat.get('src_ip', ''),
            threat.get('dst_ip', ''),
            threat.get('threat_level', 'NORMAL'),
            threat.get('threat_score', 0),
            threat.get('prediction', 0),
            json.dumps(threat.get('indicators', [])),
            threat.get('attack_type', 'Normal'),
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
                prediction, indicators, attack_type, protocol, src_port, dst_port,
                packet_size, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [(
            t.get('src_ip', ''),
            t.get('dst_ip', ''),
            t.get('threat_level', 'NORMAL'),
            t.get('threat_score', 0),
            t.get('prediction', 0),
            json.dumps(t.get('indicators', [])),
            t.get('attack_type', 'Normal'),
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


def block_ip(ip: str, reason: str = '', country: str = 'Unknown', city: str = 'Unknown', latitude: Optional[float] = None, longitude: Optional[float] = None):
    """Block an IP address with optional location data."""
    with get_db() as conn:
        conn.execute("""
            INSERT INTO blocked_ips (ip, reason, country, city, latitude, longitude, is_active)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(ip) DO UPDATE SET 
                reason = excluded.reason,
                country = excluded.country,
                city = excluded.city,
                latitude = excluded.latitude,
                longitude = excluded.longitude,
                is_active = 1,
                blocked_at = datetime('now')
        """, (ip, reason, country, city, latitude, longitude))


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


def get_ip_threat_stats(ip: str):
    """Get recent threat history for a specific IP."""
    with get_db() as conn:
        # Get count of total packets and average threat score
        stats = conn.execute("""
            SELECT COUNT(*) as count, 
                   AVG(threat_score) as avg_score,
                   MAX(threat_score) as max_score,
                   SUM(CASE WHEN threat_level = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count
            FROM threats
            WHERE src_ip = ?
        """, (ip,)).fetchone()
        
        # Get most recent threat record
        recent = conn.execute("""
            SELECT threat_level, threat_score, attack_type, timestamp
            FROM threats
            WHERE src_ip = ?
            ORDER BY id DESC
            LIMIT 1
        """, (ip,)).fetchone()

        return {
            'packet_count': stats['count'] if stats else 0,
            'avg_score': stats['avg_score'] if stats and stats['avg_score'] is not None else 0,
            'max_score': stats['max_score'] if stats and stats['max_score'] is not None else 0,
            'critical_count': stats['critical_count'] if stats and stats['critical_count'] is not None else 0,
            'recent': dict(recent) if recent else None
        }


def get_expired_blocked_ips(minutes: int = 30):
    """Get blocked IPs that have been blocked for more than specified minutes."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT ip FROM blocked_ips WHERE is_active = 1 AND blocked_at < datetime('now', ?)",
            (f'-{minutes} minutes',)
        ).fetchall()
        return [row['ip'] for row in rows]


# ── Threat History & Analytics ────────────────────────────────────────

def get_threat_history(hours: int = 24, limit: int = 500) -> list:
    """Get threat history within a time window."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT id, src_ip, dst_ip, threat_level, threat_score, 
                   attack_type, protocol, src_port, dst_port, packet_size, timestamp
            FROM threats
            WHERE created_at > datetime('now', ?)
            ORDER BY id DESC
            LIMIT ?
        """, (f'-{hours} hours', limit)).fetchall()
        return [dict(row) for row in rows]


def get_threat_summary() -> dict:
    """Get aggregated threat analytics."""
    with get_db() as conn:
        # Total counts by level
        levels = conn.execute("""
            SELECT threat_level, COUNT(*) as count
            FROM threats
            WHERE created_at > datetime('now', '-24 hours')
            GROUP BY threat_level
        """).fetchall()
        
        # Top attack types
        attack_types = conn.execute("""
            SELECT attack_type, COUNT(*) as count
            FROM threats
            WHERE created_at > datetime('now', '-24 hours') AND attack_type != 'Normal'
            GROUP BY attack_type
            ORDER BY count DESC
            LIMIT 5
        """).fetchall()
        
        # Hourly trend (last 24h)
        hourly = conn.execute("""
            SELECT strftime('%H:00', created_at) as hour,
                   COUNT(*) as total,
                   SUM(CASE WHEN threat_level = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                   SUM(CASE WHEN threat_level = 'HIGH' THEN 1 ELSE 0 END) as high
            FROM threats
            WHERE created_at > datetime('now', '-24 hours')
            GROUP BY strftime('%H', created_at)
            ORDER BY hour
        """).fetchall()
        
        # Total count
        total = conn.execute("""
            SELECT COUNT(*) as count FROM threats
            WHERE created_at > datetime('now', '-24 hours')
        """).fetchone()

        return {
            'total_24h': total['count'] if total else 0,
            'by_level': {row['threat_level']: row['count'] for row in levels},
            'top_attacks': [dict(row) for row in attack_types],
            'hourly_trend': [dict(row) for row in hourly],
        }


# ── Country-Level Blocking ────────────────────────────────────────────

def block_country(country_code: str, country_name: str):
    """Add a country to the blocked list."""
    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO blocked_countries (country_code, country_name, blocked_at) VALUES (?, ?, datetime('now'))",
            (country_code.upper(), country_name)
        )


def unblock_country(country_code: str):
    """Remove a country from the blocked list."""
    with get_db() as conn:
        conn.execute(
            "DELETE FROM blocked_countries WHERE country_code = ?",
            (country_code.upper(),)
        )


def get_blocked_countries() -> list:
    """Get all blocked countries."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM blocked_countries ORDER BY blocked_at DESC"
        ).fetchall()
        return [dict(row) for row in rows]


def is_country_blocked(country_code: str) -> bool:
    """Check if a country is blocked."""
    if not country_code:
        return False
    with get_db() as conn:
        row = conn.execute(
            "SELECT 1 FROM blocked_countries WHERE country_code = ?",
            (country_code.upper(),)
        ).fetchone()
        return row is not None


# ── User Authentication ───────────────────────────────────────────────

def _hash_password(password: str, salt: str) -> str:
    """Hash a password with a salt."""
    return hashlib.sha256((salt + password).encode()).hexdigest()


def create_user(username: str, password: str, role: str = 'admin') -> bool:
    """Create a new user. Returns True on success, False on duplicate."""
    salt = secrets.token_hex(16)
    pw_hash = _hash_password(password, salt)
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
                (username, pw_hash, salt, role)
            )
        return True
    except sqlite3.IntegrityError:
        return False


def verify_user(username: str, password: str):
    """Verify credentials. Returns user dict on success, None on failure."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if not row:
            return None
        pw_hash = _hash_password(password, row['salt'])
        if pw_hash == row['password_hash']:
            return {'id': row['id'], 'username': row['username'], 'role': row['role']}
        return None


def user_count() -> int:
    """Get total user count."""
    with get_db() as conn:
        row = conn.execute("SELECT COUNT(*) as count FROM users").fetchone()
        return row['count'] if row else 0
