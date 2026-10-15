"""
ScamSaathi - Safe Offline URL Pattern Forensics
Analyzes URL syntax and domain structures WITHOUT making network requests.
Guaranteed 100% offline, zero-visit, zero-download sandbox analysis.
"""

import re
from urllib.parse import urlparse
from .config import INDICATOR_WEIGHTS

# Regex to safely find URLs within plain text
URL_REGEX = re.compile(
    r'(https?://[^\s<>"\']+|www\.[^\s<>"\']+\.[a-z]{2,}[^\s<>"\']*)',
    re.IGNORECASE
)

# High-risk / suspicious top-level domains frequently abused in spam/phishing campaigns
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'buzz', 'fit', 'icu', 'work', 'click', 'gq', 'cf', 'ml', 'tk',
    'live', 'loan', 'rest', 'surf', 'tokyo', 'racing', 'download', 'monster'
}

# Known URL shortener services that obscure final destinations
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'is.gd', 'cutt.ly', 'rb.gy', 't.co', 'ow.ly',
    'goo.gl', 'shorturl.at', 'bl.ink'
}

# Targeted brands frequently spoofed in Indian & global cyber fraud
TARGETED_BRANDS = [
    'sbi', 'statebank', 'hdfc', 'icici', 'axis', 'pnb', 'bob',
    'paytm', 'phonepe', 'gpay', 'googlepay', 'bhim',
    'amazon', 'flipkart', 'netflix', 'discom', 'bijli', 'tatapower',
    'adanielectricity', 'bses', 'incometax', 'epfo', 'aadhaar'
]

# File extensions associated with unauthorized mobile/desktop installations
DANGEROUS_EXTENSIONS = {'.apk', '.exe', '.bat', '.scr', '.vbs', '.msi'}

def extract_urls_from_text(text: str) -> list[str]:
    """Finds all URLs present inside a message string."""
    if not text or not isinstance(text, str):
        return []
    matches = URL_REGEX.findall(text)
    clean_urls = []
    for m in matches:
        cleaned = m.rstrip('.,;:!?)>"\'')
        if cleaned and cleaned not in clean_urls:
            clean_urls.append(cleaned)
    return clean_urls

def analyze_url_forensics(url_str: str) -> dict:
    """
    Performs static inspection on a single URL string without connecting to the network.
    
    Returns:
        {
            'url': str,
            'hostname': str,
            'is_suspicious': bool,
            'signals': list[dict],
            'url_risk_score': int,
            'summary': str
        }
    """
    if not url_str or not isinstance(url_str, str):
        return {
            'url': '',
            'hostname': '',
            'is_suspicious': False,
            'signals': [],
            'url_risk_score': 0,
            'summary': 'No URL provided.'
        }

    target = url_str.strip()
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    try:
        parsed = urlparse(target)
    except Exception:
        return {
            'url': url_str,
            'hostname': '',
            'is_suspicious': True,
            'signals': [{
                'rule': 'MALFORMED_URL',
                'name': 'Malformed or Obfuscated URL Syntax',
                'weight': 20,
                'desc': 'The submitted URL has invalid or deliberately obfuscated structure.'
            }],
            'url_risk_score': 20,
            'summary': 'Malformed URL structure detected.'
        }

    hostname = (parsed.hostname or '').lower()
    path = (parsed.path or '').lower()
    query = (parsed.query or '').lower()

    signals = []
    accumulated_risk = 0

    # 1. IP Address in Hostname
    # Attackers frequently use raw IP addresses (e.g. http://192.168.1.1/login) to bypass domain registration
    ip_match = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname)
    if ip_match:
        weight = INDICATOR_WEIGHTS['SUSPICIOUS_IP_IN_URL']
        signals.append({
            'rule': 'SUSPICIOUS_IP_IN_URL',
            'name': 'Direct IP Address Used in Hostname',
            'weight': weight,
            'desc': f'Host "{hostname}" is a numerical IP address instead of a registered domain, common in phishing and rogue portals.'
        })
        accumulated_risk += weight

    # 2. Suspicious Top-Level Domain (TLD)
    tld = hostname.split('.')[-1] if '.' in hostname else ''
    if tld in SUSPICIOUS_TLDS:
        weight = INDICATOR_WEIGHTS['SUSPICIOUS_TLD']
        signals.append({
            'rule': 'SUSPICIOUS_TLD',
            'name': f'High-Risk Top-Level Domain (.{tld})',
            'weight': weight,
            'desc': f'Domain uses ".{tld}", a TLD frequently leveraged for low-cost, disposable phishing websites.'
        })
        accumulated_risk += weight

    # 3. URL Shortener / Redirection service
    if any(shortener in hostname for shortener in URL_SHORTENERS):
        weight = INDICATOR_WEIGHTS['URL_SHORTENERS' if 'URL_SHORTENERS' in INDICATOR_WEIGHTS else 'URL_SHORTENER_OR_REDIRECT']
        signals.append({
            'rule': 'URL_SHORTENER',
            'name': 'URL Shortening / Redirection Service',
            'weight': weight,
            'desc': f'Uses shortener "{hostname}" to conceal the actual destination server.'
        })
        accumulated_risk += weight

    # 4. Brand Spoofing in Domain / Subdomains
    # e.g., "sbi-kyc-verify.com" or "paytm.support-portal.xyz"
    for brand in TARGETED_BRANDS:
        if brand in hostname:
            # Check if it's the official legitimate domain or bank/gov gTLD
            legitimate_domains = [
                f'{brand}.co.in', f'{brand}.com', f'{brand}.in',
                f'{brand}bank.com', f'{brand}bank.co.in',
                f'online{brand}.com', f'online{brand}.co.in', f'online{brand}.sbi'
            ]
            is_official = (
                any(hostname == ld or hostname.endswith('.' + ld) for ld in legitimate_domains)
                or hostname.endswith('.sbi')
                or hostname.endswith('.gov.in')
                or hostname.endswith('.nic.in')
            )
            
            # If the brand appears as a prefix/hyphenated lookalike (e.g. sbi-kyc, paytm-update)
            if not is_official and ('-' in hostname or '.' in hostname):
                weight = INDICATOR_WEIGHTS['SPOOFED_BRAND_IN_DOMAIN']
                signals.append({
                    'rule': 'SPOOFED_BRAND_IN_DOMAIN',
                    'name': f'Targeted Brand Spoofing Pattern ({brand.upper()})',
                    'weight': weight,
                    'desc': f'Domain incorporates brand name "{brand.upper()}" with unofficial hyphens or subdomains, characteristic of credential harvesting portals.'
                })
                accumulated_risk += weight
                break

    # 5. Dangerous File Downloads (APKs, executables)
    for ext in DANGEROUS_EXTENSIONS:
        if path.endswith(ext) or ext in query:
            signals.append({
                'rule': 'DANGEROUS_FILE_EXTENSION',
                'name': f'Direct Executable/App Download ({ext.upper()})',
                'weight': 35,
                'desc': f'URL points directly to an installable {ext.upper()} payload, posing a critical malware or Trojan installation hazard.'
            })
            accumulated_risk += 35
            break

    # 6. Deceptive '@' Symbol in URL
    if '@' in target:
        signals.append({
            'rule': 'DECEPTIVE_USERINFO_TRICK',
            'name': 'HTTP Userinfo (@ Deception Technique)',
            'weight': 30,
            'desc': 'URL contains "@" symbol, which tricks users into misidentifying the true target domain.'
        })
        accumulated_risk += 30

    # 7. Excessive Subdomains or Hyphen count
    subdomain_parts = hostname.split('.')
    if len(subdomain_parts) >= 4 or hostname.count('-') >= 3:
        signals.append({
            'rule': 'ANOMALOUS_DOMAIN_STRUCTURE',
            'name': 'Excessive Subdomains or Hyphenated Obfuscation',
            'weight': 15,
            'desc': 'Domain structure exhibits deep subdomains or multiple hyphens often used to mislead URL inspection.'
        })
        accumulated_risk += 15

    # Cap URL risk score at 100
    capped_score = min(accumulated_risk, 100)
    is_suspicious = capped_score >= 25

    return {
        'url': url_str,
        'hostname': hostname,
        'is_suspicious': is_suspicious,
        'signals': signals,
        'url_risk_score': capped_score,
        'summary': (
            f"Detected {len(signals)} suspicious structural signals."
            if signals else "Domain structure conforms to standard web patterns."
        )
    }
