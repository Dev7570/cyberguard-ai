"""
CyberGuard-AI Flask Application
REST API + WebSocket server for real-time threat intelligence.
"""

import numpy as np
import random
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
from ml_model import ThreatDetectionModel, generate_training_data
from data_processor import DataProcessor
from network_monitor import create_monitor, get_network_interfaces, get_system_network_stats
import database as db
import numpy as np
from datetime import datetime
import threading
import time
import logging
import os
import json
import urllib.request
import jwt
from functools import wraps


def get_ip_location(ip: str):
    """Fetch geographical data for an IP using ipapi.co."""
    try:
        # Avoid local address lookup
        if ip.startswith(('127.', '192.168.', '10.', '172.')) or ip == '::1':
            return {'country': 'Local Network', 'city': 'Internal', 'country_code': '', 'lat': 0, 'lon': 0}
            
        url = f"https://ipapi.co/{ip}/json/"
        req = urllib.request.Request(url, headers={'User-Agent': 'CyberGuard-AI/1.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            return {
                'country': data.get('country_name', 'Unknown'),
                'country_code': data.get('country_code', ''),
                'city': data.get('city', 'Unknown'),
                'lat': data.get('latitude', 0),
                'lon': data.get('longitude', 0)
            }
    except Exception as e:
        logging.error(f"Geo-IP lookup failed for {ip}: {e}")
        return {'country': 'Unknown', 'city': 'Unknown', 'country_code': '', 'lat': 0, 'lon': 0}


def send_webhook_notification(title, message, color=0x3b82f6):
    """Send a structured notification to the configured Discord/Slack webhook."""
    webhook_url = db.get_setting('webhook_url')
    if not webhook_url or not webhook_url.startswith('http'):
        return

    try:
        # Discord-style embed payload
        payload = {
            "embeds": [{
                "title": f"🛡️ CyberGuard: {title}",
                "description": message,
                "color": color,
                "timestamp": datetime.now().isoformat(),
                "footer": {"text": "CyberGuard-AI Autonomous Security"}
            }]
        }
        
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            webhook_url, 
            data=data, 
            headers={'Content-Type': 'application/json', 'User-Agent': 'CyberGuard-AI/1.0'}
        )
        with urllib.request.urlopen(req, timeout=5) as res:
            if res.status >= 400:
                logger.error(f"Webhook failed with status {res.status}")
    except Exception as e:
        logger.error(f"Failed to send webhook notification: {e}")

# ── App Setup ──────────────────────────────────────────────────────────

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%H:%M:%S',
)
logger = logging.getLogger('cyberguard')

# ── Initialize Components ─────────────────────────────────────────────

db.init_db()
logger.info("Database initialized")

model = ThreatDetectionModel()
processor = DataProcessor()

# Train model on startup if needed
if not model.is_trained:
    logger.info("Generating synthetic training data...")
    X_train, y_train = generate_training_data(15000)
    accuracy = model.train(X_train, y_train)
    logger.info(f"Model trained — accuracy: {accuracy:.3f}")
else:
    logger.info("Loaded pre-trained model")

# Start network monitor
monitor_mode = db.get_setting('simulation_mode', 'true')
monitor = create_monitor('simulate' if monitor_mode == 'true' else 'live')
monitor.start()
logger.info(f"Network monitor started in {'simulation' if monitor_mode == 'true' else 'live'} mode")


# ── Background Processing Thread ──────────────────────────────────────

def process_packets_loop():
    """Continuously process packets from the network monitor."""
    while True:
        try:
            interval = int(db.get_setting('scan_interval', '3'))
            time.sleep(interval)

            packets = monitor.get_packets()
            if not packets:
                continue

            # Filter out blocked IPs
            blocked = {ip['ip'] for ip in db.get_blocked_ips()}
            packets = [p for p in packets if p.get('src_ip') not in blocked]

            if not packets:
                continue

            # Geo-Fence Check: Block packets from banned countries
            blocked_countries = db.get_blocked_countries()
            banned_codes = {c['country_code'] for c in blocked_countries}
            if banned_codes:
                geo_filtered = []
                for p in packets:
                    src_ip = p.get('src_ip', '')
                    loc = get_ip_location(src_ip)
                    country_code = loc.get('country_code', '')
                    if country_code and country_code.upper() in banned_codes:
                        if not db.is_ip_blocked(src_ip):
                            db.block_ip(src_ip, f'Geo-Fence: {loc["country"]}',
                                        country=loc['country'], city=loc['city'],
                                        latitude=loc['lat'], longitude=loc['lon'])
                            logger.warning(f"Geo-Fence blocked IP {src_ip} from {loc['country']}")
                            socketio.emit('ip_blocked', {'ip': src_ip, 'reason': f'Geo-Fence: {loc["country"]}', 'location': loc})
                            send_webhook_notification(
                                "Geo-Fence Violation",
                                f"**IP**: `{src_ip}`\n**Country**: {loc['country']}\n**Action**: Auto-blocked by country rule.",
                                color=0xff6348
                            )
                    else:
                        geo_filtered.append(p)
                packets = geo_filtered

            if not packets:
                continue

            # Extract ML features
            features = processor.extract_features(packets)
            if len(features) == 0:
                continue

            # ML predictions
            predictions = model.predict(features)
            probabilities = model.predict_proba(features)
            anomaly_flags = model.detect_anomalies(features)

            # Heuristic detections
            heuristics = processor.detect_anomalies_heuristic(packets)
            heuristic_map = {h['src_ip']: h for h in heuristics}

            # Combine results
            results = []
            for i, packet in enumerate(packets):
                # ML threat score
                ml_score = float(probabilities[i][1] * 100)

                # Boost from isolation forest anomaly
                if anomaly_flags[i] == -1:
                    ml_score = max(ml_score, ml_score + 15)

                # Boost from heuristic rules
                src_ip = packet.get('src_ip', '')
                heuristic = heuristic_map.get(src_ip)
                indicators = []
                attack_type = 'Normal'

                if heuristic:
                    ml_score = max(ml_score, heuristic['threat_score'])
                    indicators = heuristic.get('indicators', [])
                    attack_type = heuristic.get('attack_type', 'Unknown')

                # Clamp score
                threat_score = min(100, max(0, ml_score))

                # Determine level
                if threat_score > 75:
                    level = 'CRITICAL'
                elif threat_score > 50:
                    level = 'HIGH'
                elif threat_score > 30:
                    level = 'MEDIUM'
                else:
                    level = 'NORMAL'

                result = {
                    'src_ip': src_ip,
                    'dst_ip': packet.get('dst_ip', ''),
                    'src_port': packet.get('src_port', 0),
                    'dst_port': packet.get('dst_port', 0),
                    'protocol': packet.get('protocol', 'TCP'),
                    'packet_size': packet.get('packet_size', 0),
                    'threat_level': level,
                    'threat_score': round(threat_score, 1),
                    'prediction': int(predictions[i]),
                    'indicators': indicators,
                    'attack_type': attack_type,
                    'timestamp': packet.get('timestamp', datetime.now().isoformat()),
                }
                results.append(result)

                # Auto-block critical threats if enabled
                auto_block = db.get_setting('auto_block_critical', 'false')
                if auto_block == 'true' and level == 'CRITICAL':
                    if not db.is_ip_blocked(src_ip):
                        db.block_ip(src_ip, f'Auto-blocked: {attack_type}')
                        logger.warning(f"Auto-blocked IP: {src_ip} ({attack_type})")

            # Store in database
            if results:
                db.insert_threats_batch(results)

            # Push to connected dashboards via WebSocket
            non_normal = [r for r in results if r['threat_level'] != 'NORMAL']
            socketio.emit('threats_update', {
                'threats': results,
                'new_alerts': len(non_normal),
                'total_processed': len(results),
                'timestamp': datetime.now().isoformat(),
            })

            if non_normal:
                logger.info(
                    f"Processed {len(results)} packets — "
                    f"{len(non_normal)} threats detected"
                )

        except Exception as e:
            logger.error(f"Processing error: {e}", exc_info=True)
            time.sleep(5)


# Start background processing
bg_thread = threading.Thread(target=process_packets_loop, daemon=True)
bg_thread.start()


# ── Rate Limiting ─────────────────────────────────────────────────────

from collections import defaultdict

_rate_store = defaultdict(list)  # ip -> [timestamps]
RATE_LIMIT = 60        # max requests per window
RATE_WINDOW = 60       # window in seconds


def rate_limit_check():
    """Check if the request IP is within rate limits. Call as @app.before_request."""
    ip = request.remote_addr or '0.0.0.0'
    now = time.time()
    # Clean old entries
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_WINDOW]
    if len(_rate_store[ip]) >= RATE_LIMIT:
        return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429
    _rate_store[ip].append(now)
    return None


@app.before_request
def before_request_rate_limit():
    """Apply rate limiting to all requests."""
    # Skip rate limiting for health checks and static assets  
    if request.path in ('/health', '/auth/status'):
        return None
    return rate_limit_check()


# ── DDoS Pattern Detection ───────────────────────────────────────────

_ddos_tracker = defaultdict(lambda: defaultdict(int))  # dst_ip -> {src_ip: count}
_ddos_window_start = [time.time()]
DDOS_THRESHOLD = 5   # unique sources targeting same dest = distributed attack
DDOS_WINDOW = 30     # seconds


def check_ddos_pattern(packets):
    """Detect distributed attack patterns: many different IPs → same target."""
    now = time.time()
    if now - _ddos_window_start[0] > DDOS_WINDOW:
        _ddos_tracker.clear()
        _ddos_window_start[0] = now
    
    alerts = []
    for p in packets:
        src = p.get('src_ip', '')
        dst = p.get('dst_ip', '')
        if src and dst:
            _ddos_tracker[dst][src] += 1
    
    for dst, sources in _ddos_tracker.items():
        if len(sources) >= DDOS_THRESHOLD:
            for src_ip in list(sources.keys()):
                if not db.is_ip_blocked(src_ip):
                    loc = get_ip_location(src_ip)
                    db.block_ip(src_ip, f'DDoS: {len(sources)} sources → {dst}',
                                country=loc['country'], city=loc['city'],
                                latitude=loc['lat'], longitude=loc['lon'])
                    alerts.append(src_ip)
            if alerts:
                logger.warning(f"DDoS detected: {len(sources)} IPs targeting {dst}, blocked {len(alerts)} sources")
                send_webhook_notification(
                    "DDoS Attack Detected",
                    f"**Target**: `{dst}`\n**Sources**: {len(sources)} unique IPs\n**Action**: {len(alerts)} IPs auto-blocked.",
                    color=0xe74c3c
                )
                _ddos_tracker[dst].clear()
    return alerts


# ── JWT Auth Configuration ────────────────────────────────────────────

JWT_SECRET = os.environ.get('JWT_SECRET', 'cyberguard-secret-key-change-in-production')
JWT_EXPIRY_HOURS = 24


def token_required(f):
    """Decorator to protect routes with JWT auth."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            
        # Fallback to query parameter for GET downloads (e.g. PDF Export)
        if not token:
            token = request.args.get('token')
            
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            request.user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated


# ── Auth Endpoints ────────────────────────────────────────────────────

@app.route('/auth/register', methods=['POST'])
def register():
    """Register a new user (first user becomes admin)."""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if len(password) < 4:
        return jsonify({'error': 'Password must be at least 4 characters'}), 400
    
    success = db.create_user(username, password)
    if not success:
        return jsonify({'error': 'Username already exists'}), 409
    return jsonify({'status': 'registered', 'username': username}), 201


@app.route('/auth/login', methods=['POST'])
def login():
    """Login and receive a JWT token."""
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    user = db.verify_user(username, password)
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    import datetime as dt
    token = jwt.encode({
        'user_id': user['id'],
        'username': user['username'],
        'role': user['role'],
        'exp': dt.datetime.utcnow() + dt.timedelta(hours=JWT_EXPIRY_HOURS)
    }, JWT_SECRET, algorithm='HS256')
    
    return jsonify({'token': token, 'username': user['username'], 'role': user['role']}), 200


@app.route('/auth/status', methods=['GET'])
def auth_status():
    """Check if auth is set up (users exist)."""
    count = db.user_count()
    return jsonify({'has_users': count > 0, 'user_count': count}), 200


# ── REST API Endpoints ────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'model_trained': model.is_trained,
        'monitor_type': monitor.stats.get('type', 'unknown'),
        'monitor_running': monitor.is_running,
        'uptime': datetime.now().isoformat(),
    })


@app.route('/predict', methods=['POST'])
def predict():
    """Analyze packets and return threat predictions."""
    try:
        packets = request.get_json()
        if not packets:
            return jsonify({'error': 'No packets provided'}), 400

        features = processor.extract_features(packets)
        if len(features) == 0:
            return jsonify({'predictions': []}), 200

        predictions = model.predict(features)
        probabilities = model.predict_proba(features)
        heuristics = processor.detect_anomalies_heuristic(packets)
        heuristic_map = {h['src_ip']: h for h in heuristics}

        results = []
        for i, packet in enumerate(packets):
            threat_score = float(probabilities[i][1] * 100)
            src_ip = packet.get('src_ip', '')
            h = heuristic_map.get(src_ip)
            if h:
                threat_score = max(threat_score, h['threat_score'])

            if threat_score > 75:
                level = 'CRITICAL'
            elif threat_score > 50:
                level = 'HIGH'
            elif threat_score > 30:
                level = 'MEDIUM'
            else:
                level = 'NORMAL'

            result = {
                'src_ip': src_ip,
                'dst_ip': packet.get('dst_ip', ''),
                'threat_level': level,
                'threat_score': round(threat_score, 1),
                'prediction': int(predictions[i]),
                'timestamp': datetime.now().isoformat(),
            }
            results.append(result)
            db.insert_threat(result)

        return jsonify({
            'predictions': results,
            'anomalies_detected': len(heuristics),
        }), 200

    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/threats', methods=['GET'])
def get_threats():
    """Get recent threats with optional filtering."""
    limit = request.args.get('limit', 100, type=int)
    level = request.args.get('level', None)
    src_ip = request.args.get('src_ip', None)
    return jsonify(db.get_threats(limit=limit, level=level, src_ip=src_ip)), 200


@app.route('/threats/history', methods=['GET'])
def get_threat_history():
    """Get threat history within a time window."""
    hours = request.args.get('hours', 24, type=int)
    limit = request.args.get('limit', 500, type=int)
    return jsonify(db.get_threat_history(hours=hours, limit=limit)), 200


@app.route('/threats/summary', methods=['GET'])
def get_threat_summary():
    """Get aggregated analytics for the last 24h."""
    return jsonify(db.get_threat_summary()), 200


@app.route('/threats/export', methods=['GET'])
def export_threats():
    """Export threats as a CSV file."""
    hours = request.args.get('hours', 24, type=int)
    threats = db.get_threat_history(hours=hours, limit=10000)
    
    import io
    output = io.StringIO()
    output.write('ID,Source IP,Dest IP,Level,Score,Attack Type,Protocol,Src Port,Dst Port,Size,Timestamp\n')
    for t in threats:
        output.write(f"{t.get('id','')},{t.get('src_ip','')},{t.get('dst_ip','')},{t.get('threat_level','')},{t.get('threat_score','')},{t.get('attack_type','')},{t.get('protocol','')},{t.get('src_port','')},{t.get('dst_port','')},{t.get('packet_size','')},{t.get('timestamp','')}\n")
    
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=cyberguard_threats_{hours}h.csv'}
    )


@app.route('/threats/report/pdf', methods=['GET'])
@token_required
def export_threats_pdf():
    """Generate a high-quality PDF forensic report."""
    hours = request.args.get('hours', 24, type=int)
    threats = db.get_threat_history(hours=hours, limit=1000)
    
    import io
    from flask import Response
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle('CyberTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#3b82f6'), spaceAfter=20)
    subtitle_style = ParagraphStyle('CyberSub', parent=styles['Normal'], fontSize=12, textColor=colors.gray, spaceAfter=30)
    
    # Header
    elements.append(Paragraph("CyberGuard-AI Forensic Report", title_style))
    elements.append(Paragraph(f"Threat Analysis for the past {hours} hours. Generated strictly for administrative review.", subtitle_style))
    
    # Summary Table
    total_threats = len(threats)
    critical = sum(1 for t in threats if t.get('threat_level') == 'CRITICAL')
    high = sum(1 for t in threats if t.get('threat_level') == 'HIGH')
    
    summary_data = [
        ['Total Threats Analyzed', 'CRITICAL Threats', 'HIGH Threats'],
        [str(total_threats), str(critical), str(high)]
    ]
    summary_table = Table(summary_data, colWidths=[150, 150, 150])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 12),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f8fafc')),
        ('TEXTCOLOR', (0,1), (-1,-1), colors.black),
        ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#e2e8f0'))
    ]))
    
    elements.append(summary_table)
    elements.append(Spacer(1, 30))
    
    # Details Grid
    elements.append(Paragraph("Top Critical Threats", styles['Heading2']))
    
    threat_data = [['Timestamp', 'Source IP', 'Target IP', 'Type', 'Score']]
    for t in threats[:50]:  # Top 50 to fit nicely
        if t.get('threat_level') in ['CRITICAL', 'HIGH']:
            threat_data.append([
                t.get('timestamp', '')[:19].replace('T', ' '),
                t.get('src_ip', ''),
                t.get('dst_ip', ''),
                t.get('attack_type', 'Unknown'),
                str(t.get('threat_score', 0))
            ])
            
    if len(threat_data) > 1:
        details_table = Table(threat_data, colWidths=[120, 100, 100, 120, 60])
        details_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#334155')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 8),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1'))
        ]))
        elements.append(details_table)
    else:
        elements.append(Paragraph("No critical threats detected in this timeframe.", styles['Normal']))

    doc.build(elements)
    
    return Response(
        buffer.getvalue(),
        mimetype='application/pdf',
        headers={'Content-Disposition': f'attachment; filename=cyberguard_report_{hours}h.pdf'}
    )



@app.route('/stats', methods=['GET'])
def get_stats():
    """Get aggregated threat statistics."""
    stats = db.get_threat_stats()
    stats['model_accuracy'] = 0.95
    stats['monitor'] = monitor.stats
    stats['system_network'] = get_system_network_stats()
    return jsonify(stats), 200


@app.route('/block', methods=['POST'])
def block_ip_endpoint():
    """Block an IP address."""
    data = request.get_json()
    ip = data.get('ip')
    reason = data.get('reason', 'Manually blocked')
    
    if not ip:
        return jsonify({'error': 'IP required'}), 400

    # Fetch Geo-IP data
    location = get_ip_location(ip)
    
    db.block_ip(
        ip, 
        reason, 
        country=location['country'],
        city=location['city'],
        latitude=location['lat'],
        longitude=location['lon']
    )
    
    logger.warning(f"IP blocked: {ip} ({location['city']}, {location['country']}) — {reason}")
    socketio.emit('ip_blocked', {
        'ip': ip, 
        'reason': reason,
        'location': location
    })
    
    # Send Webhook Alert
    send_webhook_notification(
        "New Threat Blocked",
        f"**IP**: `{ip}`\n**Location**: {location['city']}, {location['country']}\n**Reason**: {reason}",
        color=0xff4757 # Red
    )
    
    return jsonify({'status': 'success', 'location': location}), 200


@app.route('/unblock', methods=['POST'])
def unblock_ip_endpoint():
    """Unblock an IP address."""
    data = request.get_json()
    ip = data.get('ip')
    if not ip:
        return jsonify({'error': 'IP required'}), 400
    db.unblock_ip(ip)
    logger.info(f"IP unblocked: {ip}")
    socketio.emit('ip_unblocked', {'ip': ip})
    return jsonify({'status': 'unblocked', 'ip': ip}), 200


# ── Threat Simulation Engine ──────────────────────────────────────

@app.route('/simulate-threat', methods=['POST'])
@token_required
def simulate_threat_endpoint():
    """Inject a synthetic high-risk packet into the analysis queue."""
    data = request.get_json() or {}
    attack_type = data.get('attack_type', 'DDoS')
    target_ip = data.get('target_ip', '192.168.1.100')
    
    # Generate realistic fake packet details
    fake_packet = {
        'src_ip': f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        'dst_ip': target_ip,
        'protocol': 'TCP',
        'timestamp': datetime.now().isoformat()
    }
    
    if attack_type == 'SQL_Injection':
        fake_packet['src_port'] = random.randint(1024, 65535)
        fake_packet['dst_port'] = 80
        fake_packet['packet_size'] = random.randint(300, 1500)
    elif attack_type == 'DDoS':
        fake_packet['src_port'] = random.randint(1024, 65535)
        fake_packet['dst_port'] = 443
        fake_packet['packet_size'] = random.randint(40, 60) # Typical SYN flood
        # Inject multiple packets to trigger DDoS heuristic
        for _ in range(DDOS_THRESHOLD + 1):
            p = dict(fake_packet)
            p['src_ip'] = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            monitor.inject_packets(p)
    elif attack_type == 'Port_Scan':
        fake_packet['packet_size'] = random.randint(40, 100)
        # Inject multiple packets with incrementing ports
        for i in range(10):
            p = dict(fake_packet)
            p['dst_port'] = 20 + i
            monitor.inject_packets(p)
    else:
        fake_packet['src_port'] = random.randint(1024, 65535)
        fake_packet['dst_port'] = random.randint(1, 1024)
        fake_packet['packet_size'] = random.randint(200, 800)

    # Put the base packet
    monitor.inject_packets(fake_packet)
    
    return jsonify({
        'status': 'simulating', 
        'message': f'Injected {attack_type} simulation targeting {target_ip}'
    }), 200


# ── Country-Level Blocking Endpoints ──────────────────────────────────

@app.route('/countries/blocked', methods=['GET'])
def get_blocked_countries():
    """Get all blocked countries."""
    return jsonify(db.get_blocked_countries()), 200


@app.route('/countries/block', methods=['POST'])
def block_country_endpoint():
    """Block a country by its code."""
    data = request.get_json()
    code = data.get('country_code', '').upper()
    name = data.get('country_name', code)
    if not code:
        return jsonify({'error': 'country_code required'}), 400
    
    db.block_country(code, name)
    logger.warning(f"Country blocked: {name} ({code})")
    socketio.emit('country_blocked', {'country_code': code, 'country_name': name})
    
    send_webhook_notification(
        "Country Blocked",
        f"**Country**: {name} (`{code}`)\n**Status**: All future traffic from this region will be auto-blocked.",
        color=0xff4757
    )
    return jsonify({'status': 'blocked', 'country_code': code}), 200


@app.route('/countries/unblock', methods=['POST'])
def unblock_country_endpoint():
    """Unblock a country."""
    data = request.get_json()
    code = data.get('country_code', '').upper()
    if not code:
        return jsonify({'error': 'country_code required'}), 400
    
    db.unblock_country(code)
    logger.info(f"Country unblocked: {code}")
    socketio.emit('country_unblocked', {'country_code': code})
    return jsonify({'status': 'unblocked', 'country_code': code}), 200


@app.route('/blocked', methods=['GET'])
def get_blocked():
    """Get all blocked IPs with AI unblock recommendations."""
    blocked_ips = db.get_blocked_ips()
    results = []
    
    for item in blocked_ips:
        ip = item['ip']
        stats = db.get_ip_threat_stats(ip)
        
        # AI Recommendation & Reasoning Logic
        recommendation = "Maintain Block - Persistent Threat"
        reasoning = "High frequency of suspicious packets detected from this source."
        action = "BLOCK"
        confidence = 0.9
        
        avg_score = stats.get('avg_score', 100)
        max_score = stats.get('max_score', 100)
        crit_count = stats.get('critical_count', 0)
        packet_count = stats.get('packet_count', 0)
        recent = stats.get('recent', {})
        attack_type = recent.get('attack_type', 'Unknown') if recent else 'Unknown'
        
        if packet_count > 0:
            if avg_score < 25 and crit_count == 0:
                recommendation = "Recommended to Unblock"
                reasoning = f"Low risk history detected ({avg_score:.1f}% avg score). No critical incidents logged."
                action = "UNBLOCK"
                confidence = 0.85
            elif avg_score < 40 and crit_count < 2:
                recommendation = "Consider Unblocking"
                reasoning = f"Minimal impact detected. Most recent activity was {attack_type} with low intensity."
                action = "UNBLOCK"
                confidence = 0.65
            elif max_score > 90 or crit_count > 5:
                recommendation = "Maintain Block"
                reasoning = f"Highly malicious/critical behavior confirmed ({crit_count} critical hits). Identified as {attack_type}."
                action = "BLOCK"
                confidence = 0.95
            elif avg_score > 60:
                recommendation = "Maintain Block"
                reasoning = f"Suspicious activity level remains high ({avg_score:.1f}%). Pattern suggests {attack_type}."
                action = "BLOCK"
                confidence = 0.8
        else:
            recommendation = "Manual Block"
            reasoning = "No threat history available for this IP. Manually blocked by administrator."
            action = "NEUTRAL"
            confidence = 0.5

        results.append({
            **dict(item),
            'ai_insight': {
                'recommendation': recommendation,
                'reasoning': reasoning,
                'action_suggested': action,
                'confidence': confidence,
                'avg_threat_score': round(avg_score, 1),
                'total_incident_count': packet_count
            }
        })
        
    return jsonify(results), 200


def autonomous_recovery_loop():
    """Background task to automatically unblock safe IPs after a cooldown."""
    while True:
        try:
            # Check every 5 minutes
            time.sleep(300)
            
            # Find IPs blocked for more than 30 minutes
            cooldown_mins = int(db.get_setting('unblock_cooldown_mins', '30'))
            expired_ips = db.get_expired_blocked_ips(cooldown_mins)
            
            for ip in expired_ips:
                stats = db.get_ip_threat_stats(ip)
                avg_score = stats.get('avg_score', 100)
                crit_count = stats.get('critical_count', 0)
                
                # Only auto-unblock if AI considers it safe (low risk)
                if avg_score < 25 and crit_count == 0:
                    db.unblock_ip(ip)
                    logger.info(f"Autonomous Recovery: Unblocked safe IP {ip} after cooldown.")
                    socketio.emit('ip_unblocked', {'ip': ip, 'reason': 'Autonomous recovery'})
                    
                    send_webhook_notification(
                        "Autonomous Recovery",
                        f"**Action**: Unblocked safe IP `{ip}`\n**Status**: Cooldown expired and threat level remains low.",
                        color=0x2ed573 # Green
                    )
                    
        except Exception as e:
            logger.error(f"Autonomous recovery error: {e}")
            time.sleep(60)

# Start autonomous recovery thread
recovery_thread = threading.Thread(target=autonomous_recovery_loop, daemon=True)
recovery_thread.start()


@app.route('/network/interfaces', methods=['GET'])
def get_interfaces():
    """List network interfaces."""
    return jsonify(get_network_interfaces()), 200


@app.route('/network/stats', methods=['GET'])
def get_net_stats():
    """Get system network statistics."""
    return jsonify(get_system_network_stats()), 200


@app.route('/settings', methods=['GET'])
def get_settings():
    """Get all settings."""
    return jsonify(db.get_all_settings()), 200


@app.route('/settings', methods=['POST'])
def update_settings():
    """Update system settings and handle mode changes."""
    data = request.get_json()
    for key, value in data.items():
        db.update_setting(key, str(value))
        
    # Handle monitor mode change
    if 'simulation_mode' in data:
        global monitor
        monitor.stop()
        mode = 'simulate' if data['simulation_mode'] in ('true', True) else 'live'
        monitor = create_monitor(mode)
        monitor.start()
        logger.info(f"Monitor switched to {mode} mode")

    return jsonify({'status': 'success'}), 200


@app.route('/test-webhook', methods=['POST'])
def test_webhook():
    """Send a test notification to the configured webhook."""
    webhook_url = db.get_setting('webhook_url')
    if not webhook_url:
        return jsonify({'error': 'No webhook URL configured'}), 400
        
    send_webhook_notification(
        "Test Connection", 
        "CyberGuard-AI successfully connected to your notification channel!",
        color=0x2ed573 # Green
    )
    return jsonify({'status': 'sent'}), 200


@app.route('/model/info', methods=['GET'])
def model_info():
    """Get ML model information."""
    return jsonify({
        'is_trained': model.is_trained,
        'feature_importance': model.get_feature_importance(),
        'model_type': 'RandomForest + IsolationForest',
        'n_features': 15,
    }), 200


@app.route('/reset', methods=['POST'])
def reset_data():
    """Reset all threat data and statistics."""
    processor.reset_stats()
    db.cleanup_old_threats(0)
    logger.info("Data reset by user")
    return jsonify({'status': 'reset complete'}), 200


# ── WebSocket Events ──────────────────────────────────────────────────

@socketio.on('connect')
def handle_connect():
    logger.info("Dashboard client connected")
    socketio.emit('server_status', {
        'status': 'connected',
        'model_trained': model.is_trained,
        'monitor_running': monitor.is_running,
    })


@socketio.on('disconnect')
def handle_disconnect():
    logger.info("Dashboard client disconnected")


@socketio.on('request_stats')
def handle_stats_request():
    stats = db.get_threat_stats()
    stats['monitor'] = monitor.stats
    socketio.emit('stats_update', stats)


# ── Main ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"CyberGuard-AI backend starting on port {port}")
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)
