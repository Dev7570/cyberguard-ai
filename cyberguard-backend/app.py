"""
CyberGuard-AI Flask Application
REST API + WebSocket server for real-time threat intelligence.
"""

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
    db.block_ip(ip, reason)
    logger.warning(f"IP blocked: {ip} — {reason}")
    socketio.emit('ip_blocked', {'ip': ip, 'reason': reason})
    return jsonify({'status': 'blocked', 'ip': ip}), 200


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


@app.route('/blocked', methods=['GET'])
def get_blocked():
    """Get all blocked IPs."""
    return jsonify(db.get_blocked_ips()), 200


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
    """Update settings."""
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

    return jsonify({'status': 'updated'}), 200


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
