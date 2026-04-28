"""
PRAWL AI Chatbot — Security Assistant
Answers questions about scan results in plain English.
Uses Groq (free) → Anthropic → OpenRouter → Smart Rule-based fallback.
"""
import os, json


SYSTEM_PROMPT = """You are PRAWL, a friendly AI cybersecurity assistant built specifically for Indian small business owners.

Your job is to answer questions about their website security scan results in plain, simple English — like explaining to a friend, not a technical expert.

Rules you MUST follow:
1. NEVER use technical jargon without immediately explaining it in simple words
2. Always be encouraging and helpful, never scary or overwhelming
3. Keep answers short — 2 to 4 sentences maximum unless they ask for detail
4. If they ask what to fix first, always prioritise CRITICAL and HIGH severity issues
5. Always end with one specific action they can take today
6. If you don't know something, say so honestly
7. Reference their actual scan data when answering — make it personal to their website
8. You are talking to a non-technical Indian business owner — think restaurant owner, clinic, shop

You have access to their full scan results including: URL, score, all findings with severity, and AI summary."""


def build_context_string(scan_context):
    """Convert scan data into readable context for the AI"""
    if not scan_context:
        return "No scan data available yet. The user hasn't scanned a website."

    ctx = f"""
WEBSITE SCANNED: {scan_context.get('url', 'Unknown')}
SECURITY SCORE: {scan_context.get('score', 'N/A')}/100
RISK LEVEL: {scan_context.get('risk_level', 'Unknown')}

SUMMARY: {scan_context.get('ai_summary', 'Not available')}

STATS:
- Critical/High issues: {scan_context.get('stats', {}).get('critical', 0)}
- Warnings: {scan_context.get('stats', {}).get('warnings', 0)}
- Passed checks: {scan_context.get('stats', {}).get('passed', 0)}
- Total checks: {scan_context.get('stats', {}).get('total', 0)}

DETAILED FINDINGS:"""

    findings = scan_context.get('findings', [])
    for f in findings:
        status_emoji = {'pass': '✓', 'fail': '✗', 'warning': '⚠', 'info': 'ℹ'}.get(f.get('status'), '?')
        ctx += f"\n{status_emoji} [{f.get('severity','?').upper()}] {f.get('check','?')}: {f.get('details','')}"
        if f.get('fix'):
            ctx += f"\n   Fix: {f.get('fix','')}"

    adv = scan_context.get('advanced_scan')
    if adv:
        ctx += "\n\nADVANCED SCAN FINDINGS:"
        
        nmap = adv.get('nmap', {})
        if nmap and not nmap.get('error'):
            risks = nmap.get('risk_findings', [])
            if risks:
                ctx += f"\n- NMAP: Found {len(risks)} dangerous open ports."
                for r in risks[:3]:
                    ctx += f"\n  * Port {r.get('port')} ({r.get('service')}): {r.get('description')}"
            else:
                ctx += "\n- NMAP: No dangerous open ports found."
                
        nikto = adv.get('nikto', {})
        if nikto and not nikto.get('error'):
            vulns = nikto.get('vulnerabilities', [])
            if vulns:
                ctx += f"\n- NIKTO: Found {len(vulns)} web vulnerabilities."
                for v in vulns[:3]:
                    ctx += f"\n  * [{v.get('severity').upper()}] {v.get('description')}"
            else:
                ctx += "\n- NIKTO: No web vulnerabilities found."
                
        sql = adv.get('sqlmap', {})
        if sql and not sql.get('error') and not sql.get('skipped'):
            if sql.get('injectable'):
                ctx += f"\n- SQLMAP: 🚨 CRITICAL SQL INJECTION FOUND!"
                ctx += f"\n  * DB: {sql.get('dbms')}"
                ctx += f"\n  * Params: {', '.join(sql.get('parameters', []))}"
            else:
                ctx += "\n- SQLMAP: No SQL injection detected."

    return ctx


def build_messages(user_message, scan_context, chat_history):
    """Build the messages array for the API call"""
    context_str = build_context_string(scan_context)

    messages = []

    # Add chat history (last 6 messages to save tokens)
    for msg in chat_history[-6:]:
        messages.append({
            'role': msg.get('role', 'user'),
            'content': msg.get('content', '')
        })

    # Add current message with context
    full_message = f"""Scan Context:
{context_str}

User Question: {user_message}"""

    messages.append({'role': 'user', 'content': full_message})
    return messages


def chat_via_groq(user_message, scan_context, chat_history):
    """Groq — 100% free, extremely fast LLaMA 3.3 70B"""
    groq_key = os.environ.get('GROQ_API_KEY', '')
    if not groq_key:
        return None
    try:
        import httpx
        from groq import Groq
        client = Groq(
            api_key=groq_key,
            http_client=httpx.Client()
        )
        messages = build_messages(user_message, scan_context, chat_history)
        
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{'role': 'system', 'content': SYSTEM_PROMPT}] + messages,
            max_tokens=400,
            temperature=0.7
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"Groq API error: {e}")
        return None


def chat_via_anthropic(user_message, scan_context, chat_history):
    """Anthropic Claude — paid, best quality"""
    anthropic_key = os.environ.get('ANTHROPIC_API_KEY', '')
    if not anthropic_key:
        return None
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=anthropic_key)
        messages = build_messages(user_message, scan_context, chat_history)
        msg = client.messages.create(
            model='claude-3-5-sonnet-20241022',
            max_tokens=400,
            system=SYSTEM_PROMPT,
            messages=messages
        )
        return msg.content[0].text.strip()
    except Exception as e:
        print(f"Anthropic error: {e}")
        return None


def chat_via_openrouter(user_message, scan_context, chat_history):
    """OpenRouter — free tier with Mistral"""
    or_key = os.environ.get('OPENROUTER_API_KEY', '')
    if not or_key:
        return None
    try:
        import requests
        messages = build_messages(user_message, scan_context, chat_history)
        r = requests.post(
            'https://openrouter.ai/api/v1/chat/completions',
            headers={
                'Authorization': f'Bearer {or_key}',
                'Content-Type': 'application/json'
            },
            json={
                'model': 'mistralai/mistral-7b-instruct:free',
                'messages': [{'role': 'system', 'content': SYSTEM_PROMPT}] + messages,
                'max_tokens': 300
            },
            timeout=15
        )
        if r.status_code == 200:
            return r.json()['choices'][0]['message']['content'].strip()
        return None
    except Exception as e:
        print(f"OpenRouter error: {e}")
        return None


def smart_rule_based_chat(user_message, scan_context):
    """
    Smart rule-based fallback — works with zero API keys.
    Answers the most common questions using actual scan data.
    """
    msg = user_message.lower().strip()
    score = scan_context.get('score', None)
    findings = scan_context.get('findings', [])
    url = scan_context.get('url', 'your website')
    risk = scan_context.get('risk_level', 'UNKNOWN')

    failed = [f for f in findings if f.get('status') in ['fail', 'warning']]
    critical = [f for f in findings if f.get('status') == 'fail' and f.get('severity') in ['critical', 'high']]
    passed = [f for f in findings if f.get('status') == 'pass']

    # No scan done yet
    if not scan_context or score is None:
        return "Please scan your website first by entering your URL above, then I can answer questions about your specific results! 🔍"

    # What should I fix first / priority
    if any(w in msg for w in ['fix first', 'priority', 'most important', 'urgent', 'start', 'begin', 'worst']):
        if critical:
            top = critical[0]
            return f"Fix this first: **{top['check']}** — {top['details']} This is your highest priority because it's rated {top['severity'].upper()} severity. {top.get('fix', '')}"
        elif failed:
            top = failed[0]
            return f"Start with **{top['check']}** — {top['details']} {top.get('fix', '')}"
        else:
            return f"Great news — no critical issues found! Your score is {score}/100. Just maintain regular scans to stay protected."

    # Score meaning
    if any(w in msg for w in ['score', 'mean', 'good', 'bad', 'rating', 'number', 'result']):
        if score >= 80:
            return f"Your score of {score}/100 is GOOD! 🟢 Your website has solid security. We found {len(failed)} minor issue(s) to address, but you're in much better shape than most small businesses."
        elif score >= 60:
            return f"Your score of {score}/100 is MODERATE. 🟡 There's room for improvement. You have {len(critical)} high-priority issues that need attention this week to properly protect your customers."
        elif score >= 40:
            return f"Your score of {score}/100 means HIGH RISK. 🔴 You have {len(critical)} serious vulnerabilities. Hackers actively scan for websites like yours. Please fix the red-flagged issues as soon as possible."
        else:
            return f"Your score of {score}/100 is CRITICAL. 🚨 Your website is highly vulnerable right now with {len(critical)} serious issues. Please contact your web developer today and share this report with them."

    # SSL questions
    if 'ssl' in msg or 'padlock' in msg or 'https' in msg or 'secure' in msg or 'certificate' in msg:
        ssl_finding = next((f for f in findings if 'SSL' in f.get('check', '') or 'HTTPS' in f.get('check', '')), None)
        if ssl_finding:
            if ssl_finding['status'] == 'pass':
                return f"Good news — your SSL certificate is working correctly! ✅ This means the connection between your website and your customers is encrypted and secure. {ssl_finding.get('details', '')}"
            else:
                return f"SSL issue detected: {ssl_finding.get('details', '')} This is serious because without SSL, customer data can be intercepted. Fix: {ssl_finding.get('fix', 'Contact your hosting provider to install a free SSL certificate.')}"
        return "SSL (Secure Sockets Layer) is like a padlock for your website. It encrypts data between your site and your visitors so nobody can spy on it. Scan your site to check your SSL status."

    # Dark web questions
    if any(w in msg for w in ['dark web', 'darkweb', 'leak', 'stolen', 'breach', 'pwned', 'hacked']):
        dark_finding = next((f for f in findings if 'Breach' in f.get('check', '') or 'Dark' in f.get('check', '')), None)
        if dark_finding:
            if dark_finding['status'] == 'pass':
                return f"Your domain was NOT found in any known data breach databases. ✅ This means your business data hasn't been publicly leaked as far as we can tell. Keep monitoring regularly."
            else:
                return f"⚠️ {dark_finding.get('details', '')} This means stolen data related to your business is available to hackers. Immediately: {dark_finding.get('fix', 'Change all passwords and enable 2-factor authentication.')}"
        return "The dark web is a hidden part of the internet where hackers sell stolen data. We check if your business email or domain appears in these markets. Scan your site to check!"

    # How long to fix
    if any(w in msg for w in ['how long', 'time', 'hours', 'days', 'quickly', 'fast']):
        return f"For your {len(failed)} issues: Missing security headers take about 1-2 hours for a developer to add. SSL issues take 30 minutes with your hosting provider. Port issues take 1 hour to close in your firewall. Total estimated time: half a day to fix everything critical."

    # Cost questions
    if any(w in msg for w in ['cost', 'money', 'pay', 'expensive', 'cheap', 'price', 'fee']):
        return "PRAWL is 100% free for basic scans — no login, no payment, no hidden fees. Most fixes we recommend are also free: Let's Encrypt SSL is free, security headers are free to add, closing ports costs nothing. The only cost is developer time if you need technical help."

    # What is / explain questions
    if any(w in msg for w in ['what is', 'explain', 'meaning', 'means', 'understand', 'tell me about']):
        if 'header' in msg:
            return "Security headers are invisible instructions your website sends to browsers telling them how to behave safely — like 'don't let this page be embedded in other sites' or 'only load images from trusted sources'. They prevent common attacks like clickjacking and XSS."
        if 'port' in msg:
            return "Ports are like numbered doors on your server. Port 443 is for your website (HTTPS). Port 3306 is for your database. If database ports are open to the internet, hackers can try to connect directly to your database and steal all your customer data."
        if 'ssl' in msg or 'certificate' in msg:
            return "SSL is the technology behind the padlock 🔒 you see in your browser. It encrypts all data between your website and your visitors — passwords, contact forms, payment details. Without it, anyone on the same WiFi can see everything your customers type."
        return f"I can explain any specific finding from your scan. Your website scored {score}/100 with {len(failed)} issues found. Ask me about SSL, security headers, open ports, data breaches, or any specific finding!"

    # How many issues
    if any(w in msg for w in ['how many', 'count', 'total', 'number of']):
        return f"Your scan found {len(findings)} total checks: {len(critical)} critical/high issues (fix these urgently), {len(failed) - len(critical)} medium/low warnings, and {len(passed)} checks that passed. Your overall score is {score}/100."

    # Is it safe
    if any(w in msg for w in ['safe', 'danger', 'dangerous', 'risk', 'worried', 'scared', 'protect']):
        if score >= 75:
            return f"Your website is reasonably safe with a score of {score}/100. You have {len(critical)} remaining issues to fix, but you're better protected than most small businesses. Keep scanning monthly to stay on top of new threats."
        else:
            return f"Your website score of {score}/100 puts it at {risk} risk. With {len(critical)} unresolved critical issues, there is genuine risk to your customers' data. I strongly recommend sharing this report with your developer today."

    # Passed checks
    if any(w in msg for w in ['pass', 'good', 'working', 'correct', 'ok', 'fine']):
        if passed:
            pass_names = ', '.join([f.get('check', '').replace('Header: ', '') for f in passed[:4]])
            return f"These {len(passed)} checks passed on your website: {pass_names}. These are working correctly and protecting you. Focus your energy on the {len(failed)} items that still need fixing."
        return f"Let me check your results — scan first and I'll tell you exactly what's working well on your site."

    # Thank you / done
    if any(w in msg for w in ['thank', 'thanks', 'great', 'perfect', 'awesome', 'helpful']):
        return f"You're welcome! Remember to rescan {url} in about 30 days to check for new vulnerabilities. If you need help explaining this report to your developer, download the PDF and share it with them. Stay secure! 🛡️"

    # Hello / greet
    if any(w in msg for w in ['hello', 'hi', 'hey', 'namaste', 'good morning', 'good evening']):
        return f"Hello! I'm PRAWL's AI security assistant. I've analysed {url} and found {len(failed)} issues with a score of {score}/100. Ask me anything — 'what should I fix first?', 'what does this mean?', 'how long will it take?' — I'm here to help! 🛡️"

    # Generic fallback with context
    return f"Your website {url} scored {score}/100 with {len(failed)} issues to address. I can answer questions like: 'What should I fix first?', 'What does my score mean?', 'What is SSL?', 'Is my site safe?', 'How long will fixes take?'. What would you like to know?"


def get_chat_response(user_message, scan_context, chat_history):
    """
    Main function — tries AI providers then falls back to rule-based.
    Priority: Groq (free) → Anthropic → OpenRouter → Smart Fallback
    """
    # Try Groq first (free)
    reply = chat_via_groq(user_message, scan_context, chat_history)
    if reply:
        return reply

    # Try Anthropic (paid, if key exists)
    reply = chat_via_anthropic(user_message, scan_context, chat_history)
    if reply:
        return reply

    # Try OpenRouter (free tier)
    reply = chat_via_openrouter(user_message, scan_context, chat_history)
    if reply:
        return reply

    # Always works — smart rule-based
    return smart_rule_based_chat(user_message, scan_context)