"""
ScamSaathi - Dedicated Offline URL Threat Analysis Engine
Inspects submitted URLs WITHOUT visiting, fetching, or executing remote content.
Performs deep structural forensics across schemes, IP hosts, IDN Punycode homographs,
embedded credentials, shortening services, and anomalous domain structures.
"""

import re
from urllib.parse import urlparse, unquote

# High-risk TLDs commonly leveraged for disposable scam/phishing sites
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'buzz', 'fit', 'icu', 'work', 'click', 'gq', 'cf', 'ml', 'tk',
    'live', 'loan', 'rest', 'surf', 'tokyo', 'racing', 'download', 'monster',
    'quest', 'beauty', 'hair', 'skin', 'cam', 'sbs', 'cfd', 'date', 'faith'
}

# Known URL shortener services that conceal target destinations
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'is.gd', 'cutt.ly', 'rb.gy', 't.co', 'ow.ly',
    'goo.gl', 'shorturl.at', 'bl.ink', 'tiny.cc', 'rebrand.ly', 'v.gd',
    'qr.net', 'shorte.st', 'trib.al', 'buff.ly', 'adf.ly'
}

# Targeted financial, utility, and government brands frequently spoofed
TARGETED_BRANDS = [
    'sbi', 'statebank', 'hdfc', 'icici', 'axis', 'pnb', 'bob',
    'paytm', 'phonepe', 'gpay', 'googlepay', 'bhim',
    'amazon', 'flipkart', 'netflix', 'discom', 'bijli', 'tatapower',
    'adanielectricity', 'bses', 'incometax', 'epfo', 'aadhaar', 'uidai'
]

# Sensitive path keywords associated with credential harvesting
SENSITIVE_PATHS = [
    'login', 'signin', 'verify', 'verification', 'update', 'kyc', 'pan',
    'password', 'credential', 'banking', 'secure', 'account', 'auth',
    'confirm', 'bill', 'payment', 'wallet', 'token'
]

# Dangerous file extensions
DANGEROUS_EXTENSIONS = {'.apk', '.exe', '.bat', '.scr', '.vbs', '.msi', '.cmd', '.jar'}

def normalize_url(raw_url: str) -> tuple[str, bool]:
    """
    Normalizes a user-submitted URL string.
    Returns (normalized_url, had_scheme).
    """
    url = raw_url.strip()
    # Strip dangerous control chars
    url = re.sub(r'[\r\n\t]', '', url)
    
    scheme_match = re.match(r'^([a-zA-Z][a-zA-Z0-9+.-]*):', url)
    if scheme_match:
        scheme_prefix = scheme_match.group(1).lower()
        if scheme_prefix in ['javascript', 'data', 'vbscript', 'file', 'mailto', 'about', 'tel']:
            return url, True
        if url.startswith(f"{scheme_prefix}://"):
            return url, True

    # Default to http:// for parsing if scheme was omitted
    return 'http://' + url, False

def analyze_dedicated_url(submitted_url: str) -> dict:
    """
    Performs comprehensive, 100% offline static structural analysis on a URL.
    
    Guarantees:
    - Zero HTTP/DNS requests made to the destination.
    - No execution of scripts or downloads of remote payloads.
    - Graceful error handling on malformed syntax without server crashes.
    - Explicit disclaimer: clean structure != verified harmlessness.
    """
    if not submitted_url or not isinstance(submitted_url, str):
        return {
            'original_url': '',
            'normalized_url': '',
            'hostname': '',
            'scheme': '',
            'is_https': False,
            'is_valid_format': False,
            'risk_score': 0,
            'severity': 'Low',
            'detected_indicators': [{
                'id': 'EMPTY_INPUT',
                'name': 'Empty URL Input',
                'severity': 'Low',
                'weight': 0,
                'explanation': 'No URL was provided for analysis.'
            }],
            'compound_signals': [],
            'summary': 'Empty input provided. Please enter a URL to inspect.',
            'safe_next_steps': ['Enter a valid web URL or IP to begin safe offline inspection.']
        }

    raw_input = submitted_url.strip()
    normalized_url, had_scheme = normalize_url(raw_input)

    # Validate length limit
    if len(raw_input) > 2048:
        return {
            'original_url': raw_input[:100] + '...',
            'normalized_url': normalized_url[:100] + '...',
            'hostname': '',
            'scheme': '',
            'is_https': False,
            'is_valid_format': False,
            'risk_score': 40,
            'severity': 'Medium',
            'detected_indicators': [{
                'id': 'EXCESSIVE_URL_LENGTH',
                'name': 'Abnormally Long URL (>2048 characters)',
                'severity': 'Medium',
                'weight': 40,
                'explanation': 'The submitted URL exceeds safe length standards, often used in buffer overflow or URL evasion tactics.'
            }],
            'compound_signals': [],
            'summary': 'URL exceeds safe length bounds.',
            'safe_next_steps': ['Do not click or load abnormally long, obfuscated URLs in any browser.']
        }

    # Attempt URL Parsing
    try:
        parsed = urlparse(normalized_url)
    except Exception as parse_err:
        return {
            'original_url': raw_input,
            'normalized_url': normalized_url,
            'hostname': '',
            'scheme': '',
            'is_https': False,
            'is_valid_format': False,
            'risk_score': 35,
            'severity': 'Medium',
            'detected_indicators': [{
                'id': 'UNPARSEABLE_URL_SYNTAX',
                'name': 'Malformed URL Structure',
                'severity': 'Medium',
                'weight': 35,
                'explanation': f'URL syntax violates RFC 3986 standards: {str(parse_err)}.'
            }],
            'compound_signals': [],
            'summary': 'Malformed URL structure detected.',
            'safe_next_steps': ['Discard malformed links as they may attempt browser exploitation or obfuscation.']
        }

    scheme = (parsed.scheme or '').lower()
    netloc = parsed.netloc or ''
    hostname = (parsed.hostname or '').lower()
    path = parsed.path or ''
    query = parsed.query or ''
    try:
        port = parsed.port
    except (ValueError, TypeError):
        port = None

    indicators = []
    compound_signals = []
    accumulated_risk = 0

    # 1. Scheme Validation & Non-HTTPS Inspection
    is_https = (scheme == 'https')
    if scheme in ['javascript', 'data', 'vbscript', 'file']:
        weight = 50
        indicators.append({
            'id': 'DANGEROUS_SCHEME',
            'name': f'High-Risk / Scripting Scheme ({scheme}:)',
            'severity': 'Critical',
            'weight': weight,
            'explanation': f'URL uses the "{scheme}:" scheme which can execute code or inject local payloads directly within the browser context.'
        })
        accumulated_risk += weight
    elif not is_https:
        weight = 20
        indicators.append({
            'id': 'NON_HTTPS_SCHEME',
            'name': f'Insecure Plaintext Scheme ({scheme.upper()})',
            'severity': 'Medium',
            'weight': weight,
            'explanation': 'Communication over plaintext HTTP lacks TLS/SSL encryption, exposing any submitted data to interception or eavesdropping.'
        })
        accumulated_risk += weight

    # 2. Invalid or Missing Hostname Formatting
    is_valid_format = True
    if not hostname or ' ' in hostname or ('.' not in hostname and hostname != 'localhost'):
        is_valid_format = False
        weight = 30
        indicators.append({
            'id': 'INVALID_HOSTNAME_FORMAT',
            'name': 'Invalid or Incomplete Hostname Format',
            'severity': 'Medium',
            'weight': weight,
            'explanation': 'Hostname does not contain a standard valid domain name or recognized top-level domain.'
        })
        accumulated_risk += weight

    # 3. Suspicious Use of Raw IP Addresses
    is_ip = False
    # Check IPv4
    ipv4_match = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname)
    if ipv4_match:
        # Validate octet ranges
        octets = [int(p) for p in hostname.split('.')]
        if all(0 <= o <= 255 for o in octets):
            is_ip = True
    # Check IPv6
    elif hostname.startswith('[') and hostname.endswith(']'):
        is_ip = True

    if is_ip:
        weight = 40
        indicators.append({
            'id': 'NUMERIC_IP_HOST',
            'name': 'Direct IP Address Used Instead of Domain',
            'severity': 'High',
            'weight': weight,
            'explanation': f'Destination "{hostname}" bypasses DNS domain registration using a raw numerical IP address, frequently utilized in short-lived phishing servers and rogue relays.'
        })
        accumulated_risk += weight

    # 4. Embedded Username or Password Information (HTTP Basic Auth Deception)
    has_embedded_credentials = False
    if parsed.username or parsed.password or '@' in netloc:
        has_embedded_credentials = True
        weight = 35
        # Redact actual credentials from explanation
        indicators.append({
            'id': 'EMBEDDED_CREDENTIALS_TRICK',
            'name': 'Embedded User Information / "@" Deception Trick',
            'severity': 'High',
            'weight': weight,
            'explanation': 'URL contains "@" or embedded user credentials. Attackers use this trick to display a legitimate-looking name before "@" while the browser connects to the domain following "@".'
        })
        accumulated_risk += weight

    # 5. Punycode & Internationalized Domain Names (IDN Homograph Attacks)
    has_punycode = False
    if 'xn--' in hostname:
        has_punycode = True
        weight = 35
        # Try to decode punycode safely for transparent display
        try:
            decoded_host = hostname.encode('ascii').decode('idna')
        except Exception:
            decoded_host = hostname

        indicators.append({
            'id': 'PUNYCODE_IDN_HOMOGRAPH',
            'name': 'Punycode / Internationalized Domain Name (IDN)',
            'severity': 'High',
            'weight': weight,
            'explanation': f'Domain uses Punycode ("{hostname}" -> "{decoded_host}"). Attackers frequently exploit visually identical foreign characters (Cyrillic, Greek) to impersonate trusted brands.'
        })
        accumulated_risk += weight

    # 6. URL Shortening Services
    is_shortener = any(shortener in hostname for shortener in URL_SHORTENERS)
    if is_shortener:
        weight = 25
        indicators.append({
            'id': 'URL_SHORTENING_SERVICE',
            'name': 'URL Shortening / Redirection Service',
            'severity': 'Medium',
            'weight': weight,
            'explanation': f'Uses link shortening service "{hostname}" to obscure the true server destination, headers, and destination path.'
        })
        accumulated_risk += weight

    # 7. Unusual Domain & Subdomain Structures
    # A) Suspicious TLD
    tld = hostname.split('.')[-1] if '.' in hostname else ''
    is_suspicious_tld = tld in SUSPICIOUS_TLDS
    if is_suspicious_tld:
        weight = 25
        indicators.append({
            'id': 'SUSPICIOUS_TLD',
            'name': f'High-Risk Disposable TLD (.{tld})',
            'severity': 'Medium',
            'weight': weight,
            'explanation': f'Domain registered on ".{tld}", a top-level domain statistically associated with low-cost spam and malicious infrastructure.'
        })
        accumulated_risk += weight

    # B) Excessive Subdomains
    subdomain_parts = [p for p in hostname.split('.') if p]
    if len(subdomain_parts) >= 4 and not is_ip:
        weight = 20
        indicators.append({
            'id': 'EXCESSIVE_SUBDOMAINS',
            'name': f'Deep Subdomain Nesting ({len(subdomain_parts)} levels)',
            'severity': 'Medium',
            'weight': weight,
            'explanation': f'Host "{hostname}" contains {len(subdomain_parts)} domain segments. Attackers create multi-level subdomains to mimic legitimate enterprise URLs.'
        })
        accumulated_risk += weight

    # C) Excessive Hyphens
    hyphen_count = hostname.count('-')
    if hyphen_count >= 3:
        weight = 20
        indicators.append({
            'id': 'EXCESSIVE_HYPHENS',
            'name': f'Multiple Hyphenated Delimiters ({hyphen_count} hyphens)',
            'severity': 'Medium',
            'weight': weight,
            'explanation': f'Hostname contains {hyphen_count} hyphens, a common pattern in typosquatting and fake service portals (e.g., sbi-online-kyc-update).'
        })
        accumulated_risk += weight

    # D) Targeted Brand Spoofing in Domain / Subdomain
    has_brand_spoof = False
    for brand in TARGETED_BRANDS:
        if brand in hostname:
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
            if not is_official and ('-' in hostname or '.' in hostname):
                has_brand_spoof = True
                weight = 35
                indicators.append({
                    'id': 'BRAND_SPOOFING_IN_DOMAIN',
                    'name': f'Targeted Brand Spoofing ({brand.upper()})',
                    'severity': 'High',
                    'weight': weight,
                    'explanation': f'Domain incorporates recognized institution "{brand.upper()}" within an unverified domain structure.'
                })
                accumulated_risk += weight
                break

    # E) Non-Standard Port
    if port and port not in [80, 443]:
        weight = 20
        indicators.append({
            'id': 'NON_STANDARD_PORT',
            'name': f'Non-Standard Port Service (:{port})',
            'severity': 'Medium',
            'weight': weight,
            'explanation': f'URL targets uncommon web port :{port}, typically indicating private proxies, development setups, or non-certified servers.'
        })
        accumulated_risk += weight

    # F) Direct Executable or APK Download in Path
    lowered_path = path.lower()
    for ext in DANGEROUS_EXTENSIONS:
        if lowered_path.endswith(ext) or ext in query.lower():
            weight = 40
            indicators.append({
                'id': 'DANGEROUS_DOWNLOAD_PAYLOAD',
                'name': f'Direct Executable/Payload Link ({ext.upper()})',
                'severity': 'Critical',
                'weight': weight,
                'explanation': f'Path directly references an installable {ext.upper()} executable. Fake apps (e.g. malicious electricity or banking APKs) are distributed this way.'
            })
            accumulated_risk += weight
            break

    # 8. Detection of Suspicious Combinations (Compound URL Signals)
    # Compound A: Non-HTTPS + Raw IP
    if not is_https and is_ip:
        boost = 25
        compound_signals.append({
            'name': 'NON_HTTPS_RAW_IP',
            'title': 'Compound Threat: Insecure Plaintext Connection to Raw IP Address',
            'boost': boost,
            'severity': 'Critical'
        })
        accumulated_risk += boost

    # Compound B: Non-HTTPS + Sensitive Credential Path
    path_has_sensitive = any(s in lowered_path for s in SENSITIVE_PATHS)
    if not is_https and path_has_sensitive:
        boost = 20
        compound_signals.append({
            'name': 'INSECURE_CREDENTIAL_PATH',
            'title': 'Compound Threat: Plaintext HTTP Request for Login / Account Credentials',
            'boost': boost,
            'severity': 'High'
        })
        accumulated_risk += boost

    # Compound C: Brand Spoofing + Disposable TLD
    if has_brand_spoof and is_suspicious_tld:
        boost = 25
        compound_signals.append({
            'name': 'BRAND_SPOOF_ON_SUSPICIOUS_TLD',
            'title': 'Compound Threat: Financial/Gov Brand Name Hosted on High-Risk Disposable TLD',
            'boost': boost,
            'severity': 'Critical'
        })
        accumulated_risk += boost

    # Compound D: Punycode + Brand Lookalike
    if has_punycode and any(brand in hostname for brand in TARGETED_BRANDS):
        boost = 30
        compound_signals.append({
            'name': 'PUNYCODE_BRAND_HOMOGRAPH',
            'title': 'Compound Threat: Homograph Attack Spoofing Brand via Unicode Lookalikes',
            'boost': boost,
            'severity': 'Critical'
        })
        accumulated_risk += boost

    # Compound E: Shortener + Sensitive Path/Keywords
    if is_shortener and path_has_sensitive:
        boost = 15
        compound_signals.append({
            'name': 'SHORTENER_MASKING_CREDENTIALS',
            'title': 'Compound Threat: Shortened Link Obscuring Sensitive Account Target',
            'boost': boost,
            'severity': 'High'
        })
        accumulated_risk += boost

    # Calculate final transparent score (0 - 100)
    # If no indicators at all were triggered, score is 0.
    if not indicators and not compound_signals:
        final_score = 0
    else:
        final_score = max(5, min(100, accumulated_risk))

    # Assign Severity
    if final_score >= 81:
        severity = 'Critical'
    elif final_score >= 56:
        severity = 'High'
    elif final_score >= 26:
        severity = 'Medium'
    else:
        severity = 'Low'

    # Explanations & Safe Next Steps
    # Critical requirement: Never claim a URL is safe merely because no suspicious pattern was detected!
    safe_next_steps = []
    if final_score >= 81:
        summary = f"Critical Risk ({final_score}/100): High-confidence malicious URL indicators identified. Strong probability of phishing, credential harvesting, or rogue payload distribution."
        safe_next_steps = [
            "DO NOT navigate to this URL under any circumstances.",
            "DO NOT download, install, or grant permissions to any files (especially .APK or .EXE) from this source.",
            "If this link arrived via SMS or messaging apps claiming to be your bank or utility provider, report it to 1930 immediately.",
            "Block the sender and delete the message containing this link."
        ]
    elif final_score >= 56:
        summary = f"High Risk ({final_score}/100): Suspicious structural patterns detected, such as brand lookalikes, raw IPs, or deceptive userinfo."
        safe_next_steps = [
            "Avoid visiting this destination. The domain structure closely mirrors deceptive phishing setups.",
            "If you need to access this service, open a clean browser tab and type the official verified web address manually.",
            "Never input passwords, OTPs, or debit/credit card details on unverified web addresses."
        ]
    elif final_score >= 26:
        summary = f"Medium Risk ({final_score}/100): Moderate anomalies observed (such as an unencrypted HTTP scheme, disposable TLD, or link shortener)."
        safe_next_steps = [
            "Exercise caution: The link uses an insecure transport (HTTP) or an obfuscating shortener.",
            "If using a shortened link, expand the destination using an offline preview before considering navigation.",
            "Ensure a valid SSL padlock and official certificate exist before interacting with any web page."
        ]
    else:
        # LOW / ZERO SCORE - CRITICAL SECURITY REQUIREMENT:
        # Must clearly state that clean heuristics do NOT equal certified safety!
        summary = f"Low Risk Heuristics ({final_score}/100): No suspicious structural anomalies, IP addresses, punycode, or spoofing patterns detected."
        safe_next_steps = [
            "Caution: Absence of suspicious syntax does NOT guarantee that the destination server is free from recent compromise or malicious intent.",
            "Always inspect the destination address bar carefully for unexpected redirects after landing.",
            "Verify that the SSL certificate holder matches the legitimate organization you intend to interact with.",
            "Never share 6-digit OTPs, UPI PINs, or NetBanking passwords on any web page."
        ]

    return {
        'original_url': raw_input,
        'normalized_url': normalized_url,
        'hostname': hostname,
        'scheme': scheme,
        'is_https': is_https,
        'is_valid_format': is_valid_format,
        'risk_score': final_score,
        'severity': severity,
        'detected_indicators': indicators,
        'compound_signals': compound_signals,
        'summary': summary,
        'safe_next_steps': safe_next_steps
    }
