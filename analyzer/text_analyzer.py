"""
ScamSaathi - Text Threat Indicator Analysis Engine
Matches linguistic patterns, psychological coercion, credential harvesting,
and fraud heuristics across English and Hindi.
"""

import re
from .config import INDICATOR_DICTIONARIES, COMPOUND_RULES

def analyze_text_indicators(text: str, has_url_threat: bool = False) -> dict:
    """
    Scans a message for cyber threat indicators across 6 primary fraud vectors:
    1. OTP & Credential Theft
    2. Advance Payment / Recruitment Deposit
    3. Unrealistic Earnings & Task/Prize Claims
    4. Urgency & Artificial Deadline Coercion
    5. Utility Cutoff / Legal Threat
    6. Authority & Banking Impersonation
    
    Avoids single-keyword false positives by matching contextual regexes
    rather than naive substring searches.
    """
    if not text or not isinstance(text, str):
        return {
            'detected_indicators': [],
            'compound_threats': [],
            'categories_triggered': [],
            'base_text_score': 0
        }

    detected_indicators = []
    detected_ids = set()
    categories_set = set()
    total_base_weight = 0

    # Scan against each configurable indicator dictionary
    for ind_id, ind_data in INDICATOR_DICTIONARIES.items():
        matched = False
        matched_snippet = None

        for pattern_str in ind_data['patterns']:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            match = pattern.search(text)
            if match:
                matched = True
                matched_snippet = match.group(0).strip()
                break

        if matched:
            detected_ids.add(ind_id)
            categories_set.add(ind_data['category'])
            weight = ind_data['weight']
            total_base_weight += weight

            detected_indicators.append({
                'id': ind_id,
                'name': ind_data['title'],
                'category': ind_data['category'],
                'weight': weight,
                'explanation': ind_data['explanation'],
                'matched_snippet': matched_snippet,
                'severity': 'HIGH' if weight >= 30 else ('MEDIUM' if weight >= 20 else 'LOW')
            })

    # Evaluate Compound Threat Rules
    # If a URL threat is detected externally, add virtual flag for compound checks
    if has_url_threat:
        detected_ids.add('SUSPICIOUS_URL_PRESENT')

    compound_threats = []
    compound_boost_total = 0

    for rule in COMPOUND_RULES:
        # Check if all required indicators for this compound rule are satisfied
        if all(req_id in detected_ids for req_id in rule['requires']):
            compound_threats.append({
                'name': rule['name'],
                'label': rule['label'],
                'boost': rule['boost'],
                'severity': 'CRITICAL' if rule['boost'] >= 25 else 'HIGH'
            })
            compound_boost_total += rule['boost']

    return {
        'detected_indicators': detected_indicators,
        'compound_threats': compound_threats,
        'categories_triggered': sorted(list(categories_set)),
        'base_text_score': total_base_weight + compound_boost_total
    }
