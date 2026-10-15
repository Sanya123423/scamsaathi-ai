"""
ScamSaathi - Unit & Integration Test Suite
Verifies:
1. Normal / Benign messages (Low risk)
2. Ambiguous messages (Rule 9: Avoid treating single keyword as fraud)
3. Electricity cutoff scams
4. Job & Advance-fee scams
5. Banking credential phishing
6. Hindi / Hinglish linguistic threat indicators
7. Safe static URL forensics (zero network calls)
8. Flask API endpoints (/api/analyze, /api/scan, input validation)
"""

import unittest
import json
from app import app
from analyzer.scoring import calculate_risk_score
from analyzer.url_analyzer import analyze_url_forensics
from analyzer.privacy import redact_sensitive_pii

class TestThreatDetectionEngine(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    # 1. Normal / Benign Message
    def test_normal_benign_message(self):
        msg = "Hi Rahul, our project status meeting is scheduled for 3:00 PM tomorrow in conference room B."
        assessment = calculate_risk_score(msg)
        self.assertEqual(assessment.severity, 'Low')
        self.assertLessEqual(assessment.risk_score, 25)
        self.assertEqual(len(assessment.detected_indicators), 0)

    # 2. Ambiguous Message with Single Keyword (Requirement 9)
    def test_ambiguous_message_does_not_falsely_flag(self):
        # Contains the word "urgent", but no scam/credential context
        msg1 = "Urgent reminder: please submit the team status report before end of day."
        assessment1 = calculate_risk_score(msg1)
        self.assertEqual(assessment1.severity, 'Low', "Single urgency word must remain Low severity")
        self.assertLessEqual(assessment1.risk_score, 25)

        # Contains word "payment", but in benign context
        msg2 = "Thank you, payment for your regular monthly broadband bill was received."
        assessment2 = calculate_risk_score(msg2)
        self.assertEqual(assessment2.severity, 'Low', "Normal payment confirmation must remain Low severity")

    # 3. High-Risk Electricity Cutoff Scam
    def test_electricity_disconnection_scam(self):
        msg = "Dear Customer, Your electricity power will be disconnected at 9:30 PM tonight due to unpaid bill. Immediately contact our electricity officer at 9876543210."
        assessment = calculate_risk_score(msg)
        self.assertIn(assessment.severity, ['High', 'Critical'])
        self.assertGreaterEqual(assessment.risk_score, 56)
        
        # Verify explainable indicators
        indicator_ids = [i['id'] for i in assessment.detected_indicators]
        self.assertIn('DISCONNECTION_OR_LEGAL_THREAT', indicator_ids)
        self.assertIn('URGENCY_OR_DEADLINE', indicator_ids)
        self.assertIn('IMPERSONATION_AUTHORITY', indicator_ids)

    # 4. High-Risk Job & Advance Fee Scam
    def test_telegram_job_scam(self):
        msg = "Congratulations! Part-time remote job available. Earn ₹5000 daily by simply subscribing YouTube channels. Pay ₹500 registration deposit to start. Contact manager on Telegram."
        assessment = calculate_risk_score(msg)
        self.assertIn(assessment.severity, ['High', 'Critical'])
        self.assertGreaterEqual(assessment.risk_score, 56)
        
        indicator_ids = [i['id'] for i in assessment.detected_indicators]
        self.assertIn('UNREALISTIC_EARNINGS', indicator_ids)
        self.assertIn('ADVANCE_FEE_OR_DEPOSIT', indicator_ids)

    # 5. Critical Banking OTP & Credential Harvesting
    def test_banking_credential_theft_critical(self):
        msg = "Dear SBI customer, your NetBanking account has been suspended. Share your 6-digit OTP and password immediately to verify your account."
        url = "http://192.168.1.50/sbi-kyc-update.xyz/login"
        assessment = calculate_risk_score(msg, url)
        self.assertEqual(assessment.severity, 'Critical')
        self.assertGreaterEqual(assessment.risk_score, 81)
        
        indicator_ids = [i['id'] for i in assessment.detected_indicators]
        self.assertIn('OTP_OR_PIN_REQUEST', indicator_ids)
        self.assertIn('SUSPICIOUS_IP_IN_URL', indicator_ids)

    # 6. Hindi / Hinglish Message Analysis
    def test_hindi_language_detection(self):
        # Devanagari Hindi
        msg_hindi = "प्रिय ग्राहक, बिजली बिल जमा नहीं हुआ है। आज रात बिजली काट दी जाएगी। तुरंत अधिकारी से संपर्क करें।"
        assessment_hindi = calculate_risk_score(msg_hindi)
        self.assertGreaterEqual(assessment_hindi.risk_score, 50)
        indicator_ids = [i['id'] for i in assessment_hindi.detected_indicators]
        self.assertIn('DISCONNECTION_OR_LEGAL_THREAT', indicator_ids)

        # Hinglish (Romanized Hindi)
        msg_hinglish = "Bijli kat di jayegi aaj raat 9:30 baje. Turant bijli adhikari ko call karein."
        assessment_hinglish = calculate_risk_score(msg_hinglish)
        self.assertGreaterEqual(assessment_hinglish.risk_score, 50)

    # 7. Safe Static URL Forensics
    def test_safe_url_forensics(self):
        # Suspicious numeric IP
        res_ip = analyze_url_forensics("http://103.21.244.1/sbi/login.php")
        self.assertTrue(res_ip['is_suspicious'])
        self.assertTrue(any(s['rule'] == 'SUSPICIOUS_IP_IN_URL' for s in res_ip['signals']))

        # Suspicious disposable TLD
        res_tld = analyze_url_forensics("http://update-secure-bank.xyz")
        self.assertTrue(res_tld['is_suspicious'])
        self.assertTrue(any(s['rule'] == 'SUSPICIOUS_TLD' for s in res_tld['signals']))

        # Brand lookalike spoofing
        res_brand = analyze_url_forensics("http://sbi-netbanking-verify.org")
        self.assertTrue(res_brand['is_suspicious'])

        # Benign official URL
        res_safe = analyze_url_forensics("https://www.onlinesbi.sbi")
        self.assertFalse(res_safe['is_suspicious'])
        self.assertEqual(res_safe['url_risk_score'], 0)

    # 8. Privacy Masking
    def test_privacy_redaction(self):
        raw = "Call officer at 9876543210 or enter card 4111-2222-3333-4444 with OTP is 482910."
        redacted = redact_sensitive_pii(raw)
        self.assertNotIn("4111-2222-3333-4444", redacted['sanitized_text'])
        self.assertIn("[REDACTED_CARD_NUMBER]", redacted['sanitized_text'])
        self.assertNotIn("482910", redacted['sanitized_text'])
        self.assertGreater(redacted['redactions_made'], 0)

    # 9. Flask API Endpoints
    def test_api_analyze_endpoint(self):
        payload = {
            "message": "Urgent: Electricity bill unpaid. Power will disconnect tonight.",
            "url": "http://bijli-bill-pay.xyz"
        }
        response = self.app.post('/api/analyze',
                                 data=json.dumps(payload),
                                 content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('risk_score', data)
        self.assertIn('severity', data)
        self.assertIn('detected_indicators', data)
        self.assertIn('recommended_actions', data)

    def test_api_scan_alias_endpoint(self):
        payload = {"message": "Hello test"}
        response = self.app.post('/api/scan',
                                 data=json.dumps(payload),
                                 content_type='application/json')
        self.assertEqual(response.status_code, 200)

    def test_api_empty_validation_error(self):
        response = self.app.post('/api/analyze',
                                 data=json.dumps({"message": "", "url": ""}),
                                 content_type='application/json')
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn('error', data)

    def test_api_stats_endpoint(self):
        response = self.app.get('/api/stats')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('total_scans', data)
        self.assertIn('high_critical_count', data)

if __name__ == '__main__':
    unittest.main()
