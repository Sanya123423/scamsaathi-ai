"""
ScamSaathi - Transparent Risk Scoring & Threat Assessment Engine
Calculates explainable risk scores (0-100), assigns severity tiers,
and clearly distinguishes suspicious indicators from verified malicious activity.
"""

from typing import Dict, Any, List, Optional
from .config import SEVERITY_THRESHOLDS
from .text_analyzer import analyze_text_indicators
from .url_analyzer import analyze_url_forensics, extract_urls_from_text
from .recommendations import generate_recommendations
from .privacy import redact_sensitive_pii

try:
    from ml.classifier import predict_message
except ImportError:
    def predict_message(text: str) -> Dict[str, Any]:
        return {
            "status": "unavailable",
            "is_experimental": True,
            "predicted_category": "Model Unavailable",
            "predicted_class_id": 0,
            "model_confidence": 0.0,
            "model_architecture": "TF-IDF + LogisticRegression",
            "explanation": "ML module not installed or unavailable.",
            "disclaimer": "Machine learning operating in fallback mode."
        }

class ThreatAssessment:
    def __init__(
        self,
        risk_score: int,
        severity: str,
        threat_type: str,
        explanation_summary: str,
        detected_indicators: List[Dict[str, Any]],
        threat_categories: List[str],
        recommended_actions: List[str],
        url_analysis: Dict[str, Any],
        redacted_message: str,
        scoring_breakdown: Dict[str, Any],
        ml_assessment: Optional[Dict[str, Any]] = None
    ):
        self.risk_score = risk_score
        self.severity = severity
        self.threat_type = threat_type
        self.explanation_summary = explanation_summary
        self.detected_indicators = detected_indicators
        self.threat_categories = threat_categories
        self.recommended_actions = recommended_actions
        self.url_analysis = url_analysis
        self.redacted_message = redacted_message
        self.scoring_breakdown = scoring_breakdown
        self.ml_assessment = ml_assessment or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            'risk_score': self.risk_score,
            'severity': self.severity,
            'threat_type': self.threat_type,
            'explanation_summary': self.explanation_summary,
            'detected_indicators': self.detected_indicators,
            'threat_categories': self.threat_categories,
            'recommended_actions': self.recommended_actions,
            'url_analysis': self.url_analysis,
            'redacted_message': self.redacted_message,
            'scoring_breakdown': self.scoring_breakdown,
            'ml_assessment': self.ml_assessment
        }

def determine_severity(score: int) -> str:
    """Assigns severity rating based on configurable thresholds."""
    if score >= SEVERITY_THRESHOLDS['CRITICAL'][0]:
        return 'Critical'
    if score >= SEVERITY_THRESHOLDS['HIGH'][0]:
        return 'High'
    if score >= SEVERITY_THRESHOLDS['MEDIUM'][0]:
        return 'Medium'
    return 'Low'

def calculate_risk_score(message: str, submitted_url: str = '') -> ThreatAssessment:
    """
    Core threat evaluation function.
    
    Adheres strictly to requirement 9 & 10:
    - Never treats a single isolated weak keyword as conclusive proof of fraud.
    - Clearly distinguishes suspicious indicators from verified malicious activity.
    - Aggregates text forensics, static URL analysis, and compound threat multipliers.
    """
    message_text = (message or '').strip()
    url_target = (submitted_url or '').strip()

    # Step 1: Privacy Redaction
    privacy_result = redact_sensitive_pii(message_text)
    redacted_text = privacy_result['sanitized_text']

    # Step 2: Extract or Inspect URLs
    target_url = url_target
    if not target_url and message_text:
        extracted = extract_urls_from_text(message_text)
        if extracted:
            target_url = extracted[0]

    url_result = analyze_url_forensics(target_url) if target_url else {
        'url': '',
        'hostname': '',
        'is_suspicious': False,
        'signals': [],
        'url_risk_score': 0,
        'summary': 'No URL submitted or detected.'
    }

    has_url_threat = url_result['is_suspicious']
    url_score = url_result['url_risk_score']

    # Step 3: Analyze Text Indicators
    text_result = analyze_text_indicators(message_text, has_url_threat=has_url_threat)
    detected_indicators = text_result['detected_indicators']
    compound_threats = text_result['compound_threats']
    categories = text_result['categories_triggered']
    base_text_score = text_result['base_text_score']

    # Add URL signals into detected indicators for unified reporting
    for url_sig in url_result['signals']:
        detected_indicators.append({
            'id': url_sig['rule'],
            'name': url_sig['name'],
            'category': 'URL Forensics',
            'weight': url_sig['weight'],
            'explanation': url_sig['desc'],
            'matched_snippet': url_result.get('url', ''),
            'severity': 'HIGH' if url_sig['weight'] >= 30 else 'MEDIUM'
        })
        if 'URL Forensics' not in categories:
            categories.append('URL Forensics')

def combine_rule_and_ml_evidence(
    rule_score: int,
    ml_assessment: Dict[str, Any],
    indicators_count: int,
    has_compound_threats: bool
) -> tuple[int, Dict[str, Any]]:
    """
    Documented Hybrid Risk Assessment Fusion Function.
    Combines deterministic rule-based heuristics with probabilistic ML predictions.
    
    Principles:
    1. Deterministic Heuristics are Primary (80% Weight):
       Rules (regex, keywords, URL structural anomalies) provide reliable, explainable anchors.
    2. ML as Auxiliary Contextual Signal (20% Weight):
       ML confidence provides semantic sentiment/language alignment without overriding verified rules.
    3. Probabilistic Disclaimer:
       Model confidence represents statistical feature proximity, NOT real-world criminality probability.
    """
    if not ml_assessment or ml_assessment.get("status") != "active":
        return rule_score, {
            "fusion_mode": "rule_only",
            "rule_weight": 1.0,
            "ml_weight": 0.0,
            "rule_score": rule_score,
            "ml_signal_points": None,
            "fused_score": rule_score
        }

    confidence = ml_assessment.get("model_confidence", 0.5)
    pred_class = ml_assessment.get("predicted_class_id", 0)

    if pred_class == 1:  # Suspicious
        ml_points = round(confidence * 100)
    else:  # Legitimate
        ml_points = round((1.0 - confidence) * 100)

    if rule_score == 0:
        # Do not allow ML alone to produce high alerts on benign text
        if pred_class == 1 and confidence >= 0.85:
            fused = 28
        else:
            fused = 0
    else:
        blended = round(0.80 * rule_score + 0.20 * ml_points)
        # Prevent ML from suppressing critical/high rule alerts
        if rule_score >= 56:
            fused = max(56, min(100, blended))
        else:
            fused = max(0, min(100, blended))

    # Preserve single-keyword dampening safeguard
    if indicators_count == 1 and not has_compound_threats and rule_score <= 24:
        fused = min(fused, 24)

    return fused, {
        "fusion_mode": "hybrid_weighted",
        "rule_weight": 0.80,
        "ml_weight": 0.20,
        "rule_score": rule_score,
        "ml_signal_points": ml_points,
        "fused_score": fused
    }

def calculate_risk_score(message: str, submitted_url: str = '') -> ThreatAssessment:
    """
    Core threat evaluation function.
    
    Adheres strictly to requirements:
    - Never treats a single isolated weak keyword as conclusive proof of fraud.
    - Clearly distinguishes suspicious indicators from verified malicious activity.
    - Aggregates text forensics, static URL analysis, and compound threat multipliers.
    - Evaluates ML classification separately and fuses it using a documented weighting function.
    """
    message_text = (message or '').strip()
    url_target = (submitted_url or '').strip()

    # Step 1: Privacy Redaction
    privacy_result = redact_sensitive_pii(message_text)
    redacted_text = privacy_result['sanitized_text']

    # Step 2: Extract or Inspect URLs
    target_url = url_target
    if not target_url and message_text:
        extracted = extract_urls_from_text(message_text)
        if extracted:
            target_url = extracted[0]

    url_result = analyze_url_forensics(target_url) if target_url else {
        'url': '',
        'hostname': '',
        'is_suspicious': False,
        'signals': [],
        'url_risk_score': 0,
        'summary': 'No URL submitted or detected.'
    }

    has_url_threat = url_result['is_suspicious']
    url_score = url_result['url_risk_score']

    # Step 3: Analyze Text Indicators
    text_result = analyze_text_indicators(message_text, has_url_threat=has_url_threat)
    detected_indicators = text_result['detected_indicators']
    compound_threats = text_result['compound_threats']
    categories = text_result['categories_triggered']
    base_text_score = text_result['base_text_score']

    # Add URL signals into detected indicators for unified reporting
    for url_sig in url_result['signals']:
        detected_indicators.append({
            'id': url_sig['rule'],
            'name': url_sig['name'],
            'category': 'URL Forensics',
            'weight': url_sig['weight'],
            'explanation': url_sig['desc'],
            'matched_snippet': url_result.get('url', ''),
            'severity': 'HIGH' if url_sig['weight'] >= 30 else 'MEDIUM'
        })
        if 'URL Forensics' not in categories:
            categories.append('URL Forensics')

    # Step 3.5: Machine Learning Inference (Kept strictly separate from rules)
    ml_assessment = predict_message(message_text) if message_text else {
        "status": "empty_input",
        "is_experimental": True,
        "predicted_category": "No Message Content",
        "predicted_class_id": 0,
        "model_confidence": 0.0,
        "model_architecture": "TF-IDF + LogisticRegression",
        "explanation": "No text content submitted for statistical vectorization.",
        "disclaimer": "Model confidence represents corpus statistical proximity, NOT verified mathematical probability of criminality."
    }

    # Step 4: Transparent Rule-Based Score Calculation
    raw_rule_score = base_text_score + (url_score if not message_text else int(url_score * 0.75))

    # Single-indicator dampening safeguard:
    if len(detected_indicators) == 1 and not compound_threats:
        first_id = detected_indicators[0]['id']
        if first_id != 'OTP_OR_PIN_REQUEST':
            raw_rule_score = min(raw_rule_score, 24)

    # Clean message safeguard:
    if not detected_indicators and not compound_threats and not has_url_threat:
        rule_score = 0
    else:
        rule_score = max(0, min(100, raw_rule_score))

    # Step 4.5: Combine Rule-Based Evidence with ML Prediction
    final_score, fusion_details = combine_rule_and_ml_evidence(
        rule_score=rule_score,
        ml_assessment=ml_assessment,
        indicators_count=len(detected_indicators),
        has_compound_threats=bool(compound_threats)
    )

    severity = determine_severity(final_score)

    # Step 5: Threat Classification & Summary
    has_otp = any(i['id'] == 'OTP_OR_PIN_REQUEST' for i in detected_indicators)
    has_advance_fee = any(i['id'] == 'ADVANCE_FEE_OR_DEPOSIT' for i in detected_indicators)
    has_utility = any(i['id'] == 'DISCONNECTION_OR_LEGAL_THREAT' for i in detected_indicators)

    if final_score >= 81:
        if has_otp:
            threat_type = "Critical Credential Phishing Threat"
            summary = "Critical risk: Imminent credential harvesting attempt detected requesting sensitive authentication tokens."
        elif has_utility:
            threat_type = "Critical Utility Cutoff Extortion Scam"
            summary = "Critical risk: High-coercion electricity disconnection scam combining impersonation with urgent financial threats."
        elif has_advance_fee:
            threat_type = "Critical Advance-Fee / Task Scam"
            summary = "Critical risk: Fraudulent scheme demanding advance registration deposit for promised tasks or earnings."
        else:
            threat_type = "Critical Cyber Threat Pattern"
            summary = "Critical risk: Multiple high-confidence fraud indicators detected in compound combination."
    elif final_score >= 56:
        threat_type = "High-Risk Threat Indicators"
        summary = "High risk: Suspicious pattern of urgency, impersonation, or unverified link detected. Proceed with extreme caution."
    elif final_score >= 26:
        threat_type = "Suspicious Communication Pattern"
        summary = "Medium risk: Contains warning signals common in unsolicited marketing or mild social engineering."
    else:
        threat_type = "Benign / Low Risk Content"
        summary = "Low risk: No malicious urgency, credential requests, or spoofed links identified."

    # Step 6: Generate Safety Recommendations
    recommendations = generate_recommendations(
        categories=categories,
        has_otp_threat=has_otp,
        has_url_threat=has_url_threat,
        has_advance_fee=has_advance_fee,
        has_utility_threat=has_utility,
        severity=severity
    )

    scoring_breakdown = {
        'rule_score': rule_score,
        'text_score': base_text_score,
        'url_score': url_score,
        'compound_threats_count': len(compound_threats),
        'indicators_count': len(detected_indicators),
        'dampened_for_single_keyword': (len(detected_indicators) == 1 and rule_score <= 24),
        'fusion': fusion_details
    }

    return ThreatAssessment(
        risk_score=final_score,
        severity=severity,
        threat_type=threat_type,
        explanation_summary=summary,
        detected_indicators=detected_indicators,
        threat_categories=categories,
        recommended_actions=recommendations,
        url_analysis=url_result,
        redacted_message=redacted_text,
        scoring_breakdown=scoring_breakdown,
        ml_assessment=ml_assessment
    )
