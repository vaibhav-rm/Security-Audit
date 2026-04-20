"""
═══════════════════════════════════════════════════════════════════
ADD THESE ROUTES TO YOUR EXISTING  backend/app.py
Place them AFTER your existing route definitions, before  if __name__ == "__main__":
═══════════════════════════════════════════════════════════════════
"""

# ── 1. ADD THIS IMPORT at the top of app.py ─────────────────────
from advanced_scanner import (
    run_full_advanced_scan,
    run_nmap_scan,
    run_nikto_scan,
    run_sqlmap_scan,
    check_docker_available,
)


# ── 2. ADD THESE ROUTES ─────────────────────────────────────────

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

    # Basic sanity check — don't let localhost / RFC-1918 addresses be scanned
    blocked_prefixes = ("localhost", "127.", "192.168.", "10.", "172.16.", "0.0.0.0")
    from advanced_scanner import _extract_hostname
    hostname = _extract_hostname(url)
    if any(hostname.startswith(p) for p in blocked_prefixes):
        return jsonify({"error": "Scanning private/local addresses is not allowed."}), 400

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
