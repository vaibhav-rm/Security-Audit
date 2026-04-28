from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from urllib.parse import urlparse
import os, sys, re, logging, sqlite3, json
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))  # Add parent directory for advanced_scanner
from scanner import run_full_scan
from report_generator import generate_pdf_report
from chatbot import get_chat_response

from advanced_scanner import (
    run_full_advanced_scan,
    run_nmap_scan,
    run_nikto_scan,
    run_sqlmap_scan,
    run_subdomain_scan,
    check_docker_available,
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='../frontend/templates', static_folder='../frontend/static')

ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', '*')
if ALLOWED_ORIGINS == '*':
    CORS(app)
else:
    CORS(app, origins=ALLOWED_ORIGINS.split(','))

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"],
    storage_uri="memory://"
)

# ─── SQLite history setup ───────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), 'prawl_history.db')

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                domain    TEXT    NOT NULL,
                url       TEXT    NOT NULL,
                score     INTEGER NOT NULL,
                risk_level TEXT   NOT NULL,
                stats     TEXT    NOT NULL,
                scanned_at TEXT   NOT NULL
            )
        ''')
        conn.commit()

def save_scan(result):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                'INSERT INTO scan_history (domain, url, score, risk_level, stats, scanned_at) VALUES (?,?,?,?,?,?)',
                (
                    result['hostname'],
                    result['url'],
                    result['score'],
                    result['risk_level'],
                    json.dumps(result['stats']),
                    result['scanned_at']
                )
            )
            conn.commit()
    except Exception as e:
        logger.warning(f"Failed to save scan history: {e}")

def get_history(domain):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                'SELECT score, risk_level, scanned_at FROM scan_history WHERE domain=? ORDER BY id DESC LIMIT 20',
                (domain,)
            ).fetchall()
            return [{'score': r[0], 'risk_level': r[1], 'scanned_at': r[2]} for r in rows]
    except Exception as e:
        logger.warning(f"Failed to fetch scan history: {e}")
        return []

init_db()
# ────────────────────────────────────────────────────────────────────────────


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
@limiter.limit("5 per minute")
def scan():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON body'}), 400

    url = data.get('url', '').strip().rstrip('/')
    language = data.get('language', 'english').strip().lower()

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    url = url.split()[0]

    if not url.startswith('http://') and not url.startswith('https://'):
        if url.startswith('localhost') or re.match(r'^(127\.|192\.168\.|10\.)', url):
            url = 'http://' + url
        else:
            url = 'https://' + url

    hostname = urlparse(url).hostname or ''
    if not hostname:
        return jsonify({'error': 'Please enter a valid website URL.'}), 400

    logger.info(f"Scan requested for: {hostname} (lang={language})")

    try:
        result = run_full_scan(url, language=language)
        save_scan(result)
        result['history'] = get_history(hostname)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Scan failed for {hostname}: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/network-scan', methods=['POST'])
@limiter.limit("2 per minute")
def network_scan():
    """Execute a subnet sweep on a CIDR block or multiple IPs"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400

    cidr = data.get('cidr', '').strip()
    if not cidr:
        return jsonify({'error': 'No CIDR or IP range provided'}), 400
    
    logger.info(f"Network sweep requested for: {cidr}")
    from network_scanner import run_network_sweep
    try:
        results = run_network_sweep(cidr)
        return jsonify(results)
    except Exception as e:
        logger.error(f"Network scan failed for {cidr}: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/history/<domain>')
def history(domain):
    """Return scan history for a domain as JSON."""
    return jsonify(get_history(domain))


@app.route('/chat', methods=['POST'])
@limiter.limit("30 per minute")
def chat():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON body'}), 400

    user_message  = data.get('message', '').strip()
    scan_context  = data.get('scan_context', {})
    chat_history  = data.get('history', [])

    if not user_message:
        return jsonify({'error': 'No message provided'}), 400

    try:
        reply = get_chat_response(user_message, scan_context, chat_history)
        return jsonify({'reply': reply})
    except Exception as e:
        logger.error(f"Chat error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/generate-report', methods=['POST'])
@limiter.limit("10 per minute")
def generate_report():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON body'}), 400
    try:
        reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
        filename = generate_pdf_report(data, reports_dir)
        if filename:
            return jsonify({'filename': filename, 'url': f'/report/{filename}'})
        return jsonify({'error': 'PDF generation failed - install reportlab'}), 500
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/report/<path:filename>')
def download_report(filename):
    if not re.match(r'^[\w\-\.]+\.pdf$', filename):
        return jsonify({'error': 'Invalid filename'}), 400
    reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
    return send_from_directory(reports_dir, filename, as_attachment=True)


@app.route("/api/docker-status", methods=["GET"])
def docker_status():
    """
    Frontend calls this on page load to show/hide the Advanced Scan button.
    GET /api/docker-status
    """
    return jsonify(check_docker_available())


@app.route("/api/advanced-scan", methods=["POST"])
@limiter.limit("2 per minute")          # stricter limit — these scans are heavier
def advanced_scan():
    """
    Run all three tools: Nmap, Nikto, SQLMap.
    POST /api/advanced-scan
    Body: { "url": "example.com", "sqlmap_consent": true }

    sqlmap_consent MUST be true for SQLMap to run — the frontend
    shows the user a consent checkbox before they can submit.
    """
    data    = request.get_json(silent=True) or {}
    url     = (data.get("url") or "").strip()
    consent = bool(data.get("sqlmap_consent", False))

    if not url:
        return jsonify({"error": "URL is required"}), 400

    # No localhost blocking so you can test locally
    from advanced_scanner import _extract_hostname
    hostname = _extract_hostname(url)

    results = run_full_advanced_scan(url, consent=consent)
    return jsonify(results)


@app.route("/api/scan/nmap", methods=["POST"])
@limiter.limit("3 per minute")
def scan_nmap_only():
    """Run only Nmap. POST { "url": "..." }"""
    data = request.get_json(silent=True) or {}
    url  = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    return jsonify(run_nmap_scan(url))


@app.route("/api/scan/nikto", methods=["POST"])
@limiter.limit("3 per minute")
def scan_nikto_only():
    """Run only Nikto. POST { "url": "..." }"""
    data = request.get_json(silent=True) or {}
    url  = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    return jsonify(run_nikto_scan(url))


@app.route("/api/scan/sqlmap", methods=["POST"])
@limiter.limit("2 per minute")
def scan_sqlmap_only():
    """
    Run only SQLMap.
    POST { "url": "...", "sqlmap_consent": true }
    Requires explicit consent.
    """
    data    = request.get_json(silent=True) or {}
    url     = (data.get("url") or "").strip()
    consent = bool(data.get("sqlmap_consent", False))

    if not url:
        return jsonify({"error": "URL is required"}), 400
    if not consent:
        return jsonify({"error": "Explicit consent required to run SQLMap."}), 403

    return jsonify(run_sqlmap_scan(url))


@app.route("/api/scan/subdomains", methods=["POST"])
@limiter.limit("5 per minute")
def scan_subdomains_only():
    """Run OSINT Subdomain Enumeration."""
    data = request.get_json(silent=True) or {}
    url  = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    return jsonify(run_subdomain_scan(url))


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"Starting PRAWL on port {port} (debug={debug_mode})")
    app.run(debug=debug_mode, port=port)