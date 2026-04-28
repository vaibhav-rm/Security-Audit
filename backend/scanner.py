import ssl, socket, requests, os, logging
from urllib.parse import urlparse
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Referrer-Policy',
    'Permissions-Policy',
]


def check_ssl(hostname):
    result = {'check': 'SSL Certificate', 'status': 'unknown', 'details': '', 'severity': 'info', 'fix': ''}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()

        expire_str = cert.get('notAfter', '')
        expire_dt  = datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z') if expire_str else None

        # ✅ FIX: replaced deprecated datetime.utcnow() with timezone-aware datetime
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        days_left = (expire_dt - now).days if expire_dt else None

        if days_left is not None and days_left < 0:
            result.update({
                'status': 'fail', 'severity': 'critical',
                'details': 'SSL certificate has EXPIRED.',
                'fix': "Renew your SSL certificate now. An expired cert scares away customers and exposes data."
            })
        elif days_left is not None and days_left < 30:
            result.update({
                'status': 'warning', 'severity': 'medium',
                'details': f'SSL certificate expires in {days_left} days.',
                'fix': "Renew your SSL certificate immediately using your hosting provider or Let's Encrypt (free)."
            })
        else:
            result.update({
                'status': 'pass', 'severity': 'none',
                'details': f'SSL certificate is valid. Expires in {days_left} days.' if days_left else 'SSL valid.',
                'fix': ''
            })
    except ssl.SSLError as e:
        result.update({
            'status': 'fail', 'severity': 'critical',
            'details': f'SSL error: {str(e)}',
            'fix': "Install a valid SSL certificate. Use Let's Encrypt for free SSL."
        })
    except Exception as e:
        # ✅ FIX: log instead of silent pass
        logger.warning(f"SSL check failed for {hostname}: {e}")
        result.update({
            'status': 'fail', 'severity': 'high',
            'details': f'Could not connect over HTTPS: {str(e)}',
            'fix': 'Ensure your site uses HTTPS. Most hosting providers offer free SSL.'
        })
    return result


def check_headers(url):
    results = []
    try:
        parsed    = urlparse(url)
        hostname  = parsed.hostname or parsed.path.split('/')[0]
        scheme    = parsed.scheme if parsed.scheme in ('http', 'https') else 'https'
        target_url = f'{scheme}://{hostname}'

        r = requests.get(
            target_url, timeout=8, allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; PRAWL/1.0)'}
        )
        headers = {k.lower(): v for k, v in r.headers.items()}

        for h in SECURITY_HEADERS:
            found = h.lower() in headers
            results.append({
                'check':    f'Header: {h}',
                'status':   'pass' if found else 'fail',
                'severity': 'none' if found else 'medium',
                'details':  f'Present: {headers[h.lower()]}' if found else f'Missing header: {h}',
                'fix':      '' if found else get_header_fix(h),
            })

        # HTTPS redirect check
        try:
            http_r = requests.get(
                f'http://{hostname}', timeout=5, allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; PRAWL/1.0)'}
            )
            if http_r.url.startswith('https://'):
                results.append({'check': 'HTTPS Redirect', 'status': 'pass', 'severity': 'none',
                                 'details': 'HTTP correctly redirects to HTTPS.', 'fix': ''})
            else:
                results.append({'check': 'HTTPS Redirect', 'status': 'fail', 'severity': 'medium',
                                 'details': 'HTTP traffic is not redirected to HTTPS.',
                                 'fix': 'Configure your web server to redirect all HTTP traffic to HTTPS.'})
        except Exception as e:
            # ✅ FIX: log the exception instead of bare except
            logger.debug(f"HTTP redirect check: {e} — assuming HTTPS-only (good)")
            results.append({'check': 'HTTPS Redirect', 'status': 'pass', 'severity': 'none',
                             'details': 'HTTP port not accessible — site is HTTPS only.', 'fix': ''})

    except Exception as e:
        logger.warning(f"Header check failed for {url}: {e}")
        err_msg = "Connection failed or refused. Target may be unreachable." if "Max retries exceeded" in str(e) else str(e)
        results.append({'check': 'Security Headers', 'status': 'error', 'severity': 'high',
                        'details': err_msg, 'fix': 'Check that your website is reachable on this port.'})
    return results


def get_header_fix(header):
    fixes = {
        'Strict-Transport-Security': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
        'Content-Security-Policy':   'Add Content-Security-Policy header to prevent XSS attacks.',
        'X-Frame-Options':           'Add X-Frame-Options: DENY to block clickjacking attacks.',
        'X-Content-Type-Options':    'Add X-Content-Type-Options: nosniff to prevent MIME sniffing.',
        'Referrer-Policy':           'Add Referrer-Policy: strict-origin-when-cross-origin to stop data leaking.',
        'Permissions-Policy':        'Add Permissions-Policy header to control camera/mic/location access.',
    }
    return fixes.get(header, f'Add the {header} header to your server configuration.')


def check_open_ports(hostname):
    common_ports = {
        21: 'FTP',  22: 'SSH',         23: 'Telnet',   25: 'SMTP',
        3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB',
        6379: 'Redis',  8080: 'HTTP Alt',  8443: 'HTTPS Alt'
    }
    risky_ports = [21, 23, 3306, 5432, 27017, 6379]
    open_ports  = []

    for port, service in common_ports.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            r1 = s.connect_ex((hostname, port))
            s.close()
            if r1 == 0:
                # Double-verify to eliminate false positives
                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s2.settimeout(1.5)
                r2 = s2.connect_ex((hostname, port))
                s2.close()
                if r2 == 0:
                    open_ports.append({'port': port, 'service': service, 'risky': port in risky_ports})
        except Exception as e:
            # ✅ FIX: log instead of silent pass
            logger.debug(f"Port {port} check error on {hostname}: {e}")

    if not open_ports:
        return [{'check': 'Open Ports', 'status': 'pass', 'severity': 'none',
                 'details': 'No unexpected open ports detected.', 'fix': ''}]

    results = []
    risky = [p for p in open_ports if p['risky']]
    safe  = [p for p in open_ports if not p['risky']]

    if risky:
        port_list = ', '.join([f"{p['port']} ({p['service']})" for p in risky])
        results.append({
            'check': 'Dangerous Open Ports', 'status': 'fail', 'severity': 'high',
            'details': f'Risky ports exposed to internet: {port_list}',
            'fix': 'Close these ports in your firewall immediately. Database ports should NEVER be public.'
        })
    if safe:
        port_list = ', '.join([f"{p['port']} ({p['service']})" for p in safe])
        results.append({
            'check': 'Open Service Ports', 'status': 'warning', 'severity': 'low',
            'details': f'Additional ports open: {port_list}.',
            'fix': 'Check with your hosting provider whether these ports need to be publicly accessible.'
        })
    return results


def check_software_versions(url):
    results = []
    try:
        parsed   = urlparse(url)
        hostname = parsed.hostname or parsed.path.split('/')[0]
        scheme   = parsed.scheme if parsed.scheme in ('http', 'https') else 'https'
        r = requests.get(
            f'{scheme}://{hostname}', timeout=8,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; PRAWL/1.0)'}
        )
        disclosed = []
        for h in ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator']:
            if h in r.headers:
                disclosed.append(f'{h}: {r.headers[h]}')
        if disclosed:
            results.append({
                'check': 'Software Version Disclosure', 'status': 'warning', 'severity': 'low',
                'details': f'Server discloses software info: {"; ".join(disclosed)}',
                'fix': 'Hide version info. Apache: ServerTokens Prod. Nginx: server_tokens off.'
            })
        else:
            results.append({
                'check': 'Software Version Disclosure', 'status': 'pass', 'severity': 'none',
                'details': 'No software version information leaked in headers.', 'fix': ''
            })
    except Exception as e:
        # ✅ FIX: log instead of silent pass
        logger.warning(f"Version check failed for {url}: {e}")
        err_msg = "Connection failed or refused." if "Max retries exceeded" in str(e) else str(e)
        results.append({'check': 'Software Version Check', 'status': 'error',
                        'severity': 'info', 'details': err_msg, 'fix': ''})
    return results


def check_cookies_secure(url):
    try:
        response = requests.get(url, timeout=10, allow_redirects=False)
        cookies_header = response.headers.get('set-cookie', '').lower()
        if not cookies_header:
            return [{'check': 'Cookie Security', 'status': 'pass', 'severity': 'none', 
                     'details': 'No session cookies are exposed directly on initialization.', 'fix': 'N/A'}]
        
        missing_secure = 'secure' not in cookies_header
        missing_httponly = 'httponly' not in cookies_header
        
        if missing_secure and url.startswith('https://'):
            return [{'check': 'Cookie Security', 'status': 'warning', 'severity': 'medium',
                     'details': 'Cookies are missing the Secure flag, making them vulnerable to interception over unencrypted connections.',
                     'fix': 'Set the Secure flag on all session cookies.'}]
        if missing_httponly:
            return [{'check': 'Cookie Security', 'status': 'warning', 'severity': 'medium',
                     'details': 'Cookies are missing the HttpOnly flag, increasing risk of Cross-Site Scripting (XSS) token theft.',
                     'fix': 'Set the HttpOnly flag on all sensitive cookies.'}]
            
        return [{'check': 'Cookie Security', 'status': 'pass', 'severity': 'none',
                 'details': 'Cookies are configured securely.', 'fix': ''}]
    except Exception as e:
        return [{'check': 'Cookie Security', 'status': 'error', 'severity': 'info', 'details': f'Failed to check cookies: {str(e)}', 'fix': ''}]

def check_cors(url):
    try:
        headers = {'Origin': 'https://evil.com'}
        response = requests.get(url, headers=headers, timeout=10)
        acao = response.headers.get('Access-Control-Allow-Origin', '')
        if acao == '*' or acao == 'https://evil.com':
            return [{'check': 'CORS Configuration', 'status': 'warning', 'severity': 'medium',
                     'details': f"Overly permissive CORS policy detected (Access-Control-Allow-Origin: {acao}).",
                     'fix': "Restrict CORS headers to trusted domains only instead of a wildcard."}]
        return [{'check': 'CORS Configuration', 'status': 'pass', 'severity': 'none',
                 'details': 'CORS policy appears restrictive.', 'fix': ''}]
    except Exception as e:
        return [{'check': 'CORS Configuration', 'status': 'error', 'severity': 'info', 'details': f'Failed to check CORS: {str(e)}', 'fix': ''}]

def check_security_headers(url):
    try:
        response = requests.get(url, timeout=10, allow_redirects=False)
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        results = []
        
        if 'x-frame-options' not in headers and 'content-security-policy' not in headers:
            results.append({'check': 'Clickjacking Protection', 'status': 'warning', 'severity': 'medium', 'details': 'Missing X-Frame-Options or CSP frame-ancestors. Site may be vulnerable to Clickjacking.', 'fix': 'Add X-Frame-Options: DENY or SAMEORIGIN.'})
        else:
            results.append({'check': 'Clickjacking Protection', 'status': 'pass', 'severity': 'none', 'details': 'Anti-clickjacking headers are present.', 'fix': ''})
            
        if 'x-content-type-options' not in headers:
            results.append({'check': 'MIME Sniffing', 'status': 'warning', 'severity': 'low', 'details': 'Missing X-Content-Type-Options header.', 'fix': 'Add X-Content-Type-Options: nosniff.'})
        else:
            results.append({'check': 'MIME Sniffing', 'status': 'pass', 'severity': 'none', 'details': 'MIME-sniffing protection enabled.', 'fix': ''})
            
        if url.startswith('https://'):
            if 'strict-transport-security' not in headers:
                results.append({'check': 'HSTS Check', 'status': 'warning', 'severity': 'medium', 'details': 'HTTP Strict-Transport-Security (HSTS) is not enabled.', 'fix': 'Add Strict-Transport-Security header to enforce secure connections.'})
            else:
                results.append({'check': 'HSTS Check', 'status': 'pass', 'severity': 'none', 'details': 'HSTS is enabled.', 'fix': ''})
        
        return results
    except Exception as e:
        return [{'check': 'Advanced Security Headers', 'status': 'error', 'severity': 'info', 'details': f'Failed to verify headers: {str(e)}', 'fix': ''}]

def check_exposed_files(url):
    base_url = url.rstrip('/')
    results = []
    
    try:
        env_resp = requests.get(base_url + '/.env', timeout=5, allow_redirects=False)
        if env_resp.status_code == 200 and 'DB_' in env_resp.text:
            results.append({'check': 'Exposed Secrets (.env)', 'status': 'fail', 'severity': 'critical', 'details': '.env configuration file is publicly exposed!', 'fix': 'Deny access to dotfiles located in the root web directory.'})
    except:
        pass
        
    try:
        git_resp = requests.get(base_url + '/.git/config', timeout=5, allow_redirects=False)
        if git_resp.status_code == 200 and '[core]' in git_resp.text:
            results.append({'check': 'Exposed Codebase (.git)', 'status': 'fail', 'severity': 'critical', 'details': 'Git configuration folder is publicly exposed!', 'fix': 'Deny access to the .git directory immediately.'})
    except:
        pass

    if not results:
        results.append({'check': 'Sensitive Files Exposure', 'status': 'pass', 'severity': 'none', 'details': 'No common sensitive configuration files (.env, .git) exposed.', 'fix': ''})
        
    return results

def calculate_score(findings):
    score        = 100
    deductions   = {'critical': 15, 'high': 10, 'medium': 5, 'low': 2, 'info': 0, 'none': 0}
    per_check_cap = 15
    per_check_totals = {}

    for f in findings:
        if f['status'] in ['fail', 'warning', 'error']:
            sev = f.get('severity', 'medium')
            key = f.get('check', 'Unknown')
            per_check_totals[key] = per_check_totals.get(key, 0) + deductions.get(sev, 5)

    for total in per_check_totals.values():
        score -= min(total, per_check_cap)

    # ✅ FIX: Raised cap from 88 to 95 — previously a perfect site was penalised unfairly
    return max(0, min(score, 95))


def get_risk_level(score, findings):
    if score >= 75: return 'LOW',      '#00d4aa'
    if score >= 60: return 'MEDIUM',   '#f59e0b'
    if score >= 40: return 'HIGH',     '#f97316'
    return                 'CRITICAL', '#ef4444'


LANGUAGE_INSTRUCTIONS = {
    'english': 'Write in plain English.',
    'hindi':   'हिंदी में लिखें। (Write entirely in Hindi script.)',
    'telugu':  'తెలుగులో రాయండి. (Write entirely in Telugu script.)',
    'tamil':   'தமிழில் எழுதுங்கள். (Write entirely in Tamil script.)',
    'kannada': 'ಕನ್ನಡದಲ್ಲಿ ಬರೆಯಿರಿ. (Write entirely in Kannada script.)',
    'marathi': 'मराठीत लिहा. (Write entirely in Marathi script.)',
    'bengali': 'বাংলায় লিখুন। (Write entirely in Bengali script.)',
}

def generate_ai_summary(url, findings, score, language='english'):
    """
    Uses Groq (Llama 3.3) for AI summaries if GROQ_API_KEY is set,
    otherwise falls back to a plain-text rule-based summary.
    Supports multiple Indian languages via the language parameter.
    """
    issues = [f for f in findings if f['status'] in ['fail', 'warning']]
    issues_text = '\n'.join([
        f"- [{f['severity'].upper()}] {f['check']}: {f['details']}"
        for f in issues[:8]
    ])
    lang_key = language.lower().strip()
    lang_instruction = LANGUAGE_INSTRUCTIONS.get(lang_key, LANGUAGE_INSTRUCTIONS['english'])

    prompt = f"""You are PRAWL, an AI cybersecurity assistant for Indian small businesses.
Website: {url} | Score: {score}/100
Issues found:
{issues_text or 'No major issues found.'}
Write exactly 3 sentences for a non-technical Indian business owner.
Mention the score, the most critical issue, and one clear action to take today.
No bullet points. No jargon. Plain paragraph only.
Language instruction: {lang_instruction}"""

    groq_key = os.environ.get('GROQ_API_KEY', '')
    if groq_key:
        try:
            import httpx
            from groq import Groq
            client = Groq(
                api_key=groq_key,
                http_client=httpx.Client()
            )
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=350
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.warning(f"Groq API failed, using text fallback: {e}")

    return generate_fallback_summary(findings, score)


def generate_fallback_summary(findings, score):
    issues   = [f for f in findings if f['status'] in ['fail', 'warning']]
    critical = [f for f in issues   if f['severity'] in ['critical', 'high']]
    if score >= 75:
        return (f"Your website scored {score}/100 — good security overall. "
                f"We found {len(issues)} minor issue(s) to address. "
                "Add the missing security headers to fully protect your customers.")
    elif score >= 60:
        return (f"Your website scored {score}/100 — moderate risk. "
                f"We found {len(issues)} security issues including {len(critical)} high-priority item(s). "
                "Address the red-flagged findings this week to protect your customers.")
    else:
        return (f"Your website scored {score}/100 — this is high risk. "
                f"We found {len(critical)} critical issues out of {len(issues)} total problems. "
                "Contact your hosting provider today and ask them to fix the critical items on this report.")


def run_full_scan(url, language='english'):
    parsed   = urlparse(url)
    hostname = parsed.hostname or parsed.path.split('/')[0]

    findings = []
    findings.append(check_ssl(hostname))
    findings.extend(check_headers(url))
    findings.extend(check_open_ports(hostname))
    findings.extend(check_software_versions(url))
    findings.extend(check_cookies_secure(url))
    findings.extend(check_cors(url))
    findings.extend(check_security_headers(url))
    findings.extend(check_exposed_files(url))

    score                  = calculate_score(findings)
    risk_level, risk_color = get_risk_level(score, findings)
    ai_summary             = generate_ai_summary(url, findings, score, language)

    critical_count = len([f for f in findings if f['status'] == 'fail'              and f['severity'] in ['critical', 'high']])
    warning_count  = len([f for f in findings if f['status'] in ['warning', 'fail'] and f['severity'] in ['medium', 'low']])
    pass_count     = len([f for f in findings if f['status'] == 'pass'])

    return {
        'url': url, 'hostname': hostname,
        'score': score, 'risk_level': risk_level, 'risk_color': risk_color,
        'ai_summary': ai_summary, 'findings': findings,
        'stats': {
            'critical': critical_count, 'warnings': warning_count,
            'passed': pass_count,       'total': len(findings)
        },
        # ✅ FIX: replaced deprecated datetime.utcnow()
        'scanned_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    }