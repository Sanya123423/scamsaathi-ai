"""
ScamSaathi - Privacy & Sanitization Engine
Redacts personal identifying information (PII) before storage, logging, or reporting.
"""

import re

# PII Matching Patterns
PHONE_PATTERN = re.compile(r'(?:\+?91[\s\-]?)?[6-9]\d{9}\b')
CARD_PATTERN = re.compile(r'\b(?:\d{4}[\s\-]?){3}\d{4}\b')
PAN_PATTERN = re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b', re.IGNORECASE)
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
OTP_CODE_PATTERN = re.compile(r'\b(?:otp\s*is\s*|code\s*:\s*)(\d{4,8})\b', re.IGNORECASE)

def redact_sensitive_pii(text: str) -> dict:
    """
    Sanitizes user input by masking identifiable phone numbers, card digits,
    PANs, emails, and explicit OTP tokens.
    
    Returns:
        {
            'sanitized_text': str,
            'redactions_made': int,
            'redaction_types': list[str]
        }
    """
    if not text or not isinstance(text, str):
        return {
            'sanitized_text': '',
            'redactions_made': 0,
            'redaction_types': []
        }

    redacted = text
    types_detected = []
    count = 0

    # 1. Card Numbers
    if CARD_PATTERN.search(redacted):
        redacted = CARD_PATTERN.sub('[REDACTED_CARD_NUMBER]', redacted)
        types_detected.append('Payment Card')
        count += 1

    # 2. PAN Numbers
    if PAN_PATTERN.search(redacted):
        redacted = PAN_PATTERN.sub('[REDACTED_PAN]', redacted)
        types_detected.append('Tax PAN ID')
        count += 1

    # 3. Email Addresses
    if EMAIL_PATTERN.search(redacted):
        redacted = EMAIL_PATTERN.sub('[REDACTED_EMAIL]', redacted)
        types_detected.append('Email Address')
        count += 1

    # 4. Phone Numbers (Mask middle digits e.g. 98****3210)
    def mask_phone(match):
        nonlocal count
        count += 1
        raw = match.group(0)
        digits = re.sub(r'\D', '', raw)
        if len(digits) >= 10:
            last10 = digits[-10:]
            return f"{last10[:2]}******{last10[-2:]}"
        return '[REDACTED_PHONE]'

    if PHONE_PATTERN.search(redacted):
        redacted = PHONE_PATTERN.sub(mask_phone, redacted)
        types_detected.append('Mobile Number')

    # 5. Standalone OTP phrases
    if OTP_CODE_PATTERN.search(redacted):
        redacted = OTP_CODE_PATTERN.sub('OTP is [REDACTED_CODE]', redacted)
        types_detected.append('OTP Code')
        count += 1

    return {
        'sanitized_text': redacted,
        'redactions_made': count,
        'redaction_types': types_detected
    }
