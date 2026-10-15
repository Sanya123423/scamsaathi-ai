"""
ScamSaathi - Flask Backend & Threat Analysis API
Provides endpoints:
- POST /api/analyze (Primary threat detection endpoint)
- POST /api/scan (Alias for compatibility)
- GET /api/stats (Telemetry metrics for dashboard)
- GET /api/alerts (Recent scan history)
- POST /api/clear (Reset telemetry for clean demos)
- GET /api/health (Liveness check)
- GET / (Serves Frontend Dashboard)
"""

import os
from flask import Flask, request, jsonify, render_template, send_from_directory
from werkzeug.exceptions import RequestEntityTooLarge

from analyzer.scoring import calculate_risk_score
from analyzer.url_checker import analyze_dedicated_url
from db import init_db, record_scan, get_telemetry_stats, get_recent_alerts, clear_all_scans

app = Flask(
    __name__,
    static_folder='static',
    template_folder='templates'
)

# Enforce 1MB maximum payload limit
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024

# Initialize database schema on startup
init_db()

@app.errorhandler(RequestEntityTooLarge)
def handle_payload_too_large(error):
    return jsonify({
        'error': 'Request payload exceeds 1MB limit. Please provide a shorter input.'
    }), 413

@app.errorhandler(404)
def handle_not_found(error):
    return jsonify({'error': 'Requested API endpoint not found.'}), 404

@app.errorhandler(500)
def handle_internal_error(error):
    return jsonify({'error': 'Internal server error occurred during threat analysis.'}), 500

@app.route('/')
def index():
    """Serves the ScamSaathi cybersecurity dashboard."""
    if os.path.exists(os.path.join(app.root_path, 'templates', 'index.html')):
        return render_template('index.html')
    return send_from_directory('.', 'index.html')

@app.route('/api/health', methods=['GET'])
def health():
    """System health & connectivity verification."""
    return jsonify({
        'status': 'online',
        'service': 'ScamSaathi Threat Analysis Engine',
        'version': '1.0.0'
    })

@app.route('/api/analyze', methods=['POST'])
@app.route('/api/scan', methods=['POST'])
def analyze():
    """
    Main Threat Detection & Risk Assessment API.
    
    Accepts:
        JSON: { "message": "string (optional)", "url": "string (optional)" }
        
    Returns:
        JSON with risk_score, severity, detected_indicators, explanations,
        recommended_actions, and safe URL forensics.
    """
    if not request.is_json:
        return jsonify({
            'error': 'Invalid request format. Content-Type must be application/json.'
        }), 400

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({'error': 'Malformed or empty JSON body.'}), 400

    message = data.get('message', '')
    url = data.get('url', '')

    # Type validation
    if not isinstance(message, str) or not isinstance(url, str):
        return jsonify({'error': '"message" and "url" fields must be text strings.'}), 400

    # Input length validation
    if len(message) > 10000:
        return jsonify({'error': 'Message length exceeds maximum limit of 10,000 characters.'}), 400
    if len(url) > 2048:
        return jsonify({'error': 'URL length exceeds maximum limit of 2,048 characters.'}), 400

    # Non-empty input validation
    clean_message = message.strip()
    clean_url = url.strip()
    if not clean_message and not clean_url:
        return jsonify({'error': 'Please provide a non-empty message or URL to analyze.'}), 400

    try:
        # Run modular threat assessment
        assessment = calculate_risk_score(clean_message, clean_url)
        result_dict = assessment.to_dict()

        # Record scan in SQLite database for telemetry
        record_scan(result_dict, clean_url)

        return jsonify(result_dict), 200

    except Exception as exc:
        app.logger.error(f"Error in threat detection pipeline: {exc}", exc_info=True)
        return jsonify({
            'error': f'Failed to analyze threat indicators: {str(exc)}'
        }), 500

@app.route('/api/check-url', methods=['POST'])
def check_url():
    """
    Dedicated Static URL Threat Inspection API.
    Zero-visit, 100% offline inspection. Never sends HTTP requests or downloads files.
    
    Accepts:
        JSON: { "url": "string" }
    Returns:
        JSON: normalized_url, detected_indicators, risk_score, severity,
              compound_signals, summary, and safe_next_steps.
    """
    if not request.is_json:
        return jsonify({
            'error': 'Invalid request format. Content-Type must be application/json.'
        }), 400

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({'error': 'Malformed or empty JSON body.'}), 400

    raw_url = data.get('url', '')
    if not isinstance(raw_url, str):
        return jsonify({'error': '"url" field must be a text string.'}), 400

    clean_url = raw_url.strip()
    if not clean_url:
        return jsonify({'error': 'Please provide a non-empty URL to analyze.'}), 400

    if len(clean_url) > 2048:
        return jsonify({'error': 'URL length exceeds maximum limit of 2,048 characters.'}), 400

    try:
        url_report = analyze_dedicated_url(clean_url)

        # Log to telemetry store as a scan
        telemetry_entry = {
            'threat_type': f"URL Inspection: {url_report['severity']} Risk",
            'risk_score': url_report['risk_score'],
            'severity': url_report['severity'],
            'threat_categories': ['URL Forensics'],
            'detected_indicators': url_report['detected_indicators'],
            'redacted_message': f"URL Target: {clean_url}"
        }
        record_scan(telemetry_entry, clean_url)

        return jsonify(url_report), 200

    except Exception as exc:
        app.logger.error(f"Error in dedicated URL analysis: {exc}", exc_info=True)
        return jsonify({
            'error': f'Failed to perform URL forensics: {str(exc)}'
        }), 500

@app.route('/api/stats', methods=['GET'])
def stats():
    """Returns telemetry metrics for total scans and severity counts."""
    try:
        metrics = get_telemetry_stats()
        return jsonify(metrics), 200
    except Exception as exc:
        return jsonify({'error': f'Failed to retrieve telemetry stats: {str(exc)}'}), 500

@app.route('/api/alerts', methods=['GET'])
def alerts():
    """Returns recent scan history records."""
    try:
        limit = request.args.get('limit', default=15, type=int)
        limit = max(1, min(limit, 50))
        recent = get_recent_alerts(limit=limit)
        return jsonify({'alerts': recent}), 200
    except Exception as exc:
        return jsonify({'error': f'Failed to fetch alert history: {str(exc)}'}), 500

@app.route('/api/clear', methods=['POST'])
def clear_history():
    """Clears all historical scans from the SQLite database."""
    try:
        clear_all_scans()
        return jsonify({'status': 'cleared', 'message': 'All scan records reset successfully.'}), 200
    except Exception as exc:
        return jsonify({'error': f'Failed to clear scan history: {str(exc)}'}), 500

if __name__ == '__main__':
    print("=" * 65)
    print(" ScamSaathi - Cyber Threat Detection Engine")
    print(" Challenge ABSC-01: Intelligent Cyber Threat Detection")
    print(" Serving at: http://127.0.0.1:5000")
    print("=" * 65)
    app.run(host='127.0.0.1', port=5000, debug=False)
