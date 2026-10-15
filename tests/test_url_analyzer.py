"""
ScamSaathi - Dedicated URL Analyzer Test Suite
Verifies:
1. Normal HTTPS URL (Low risk, clear safety disclaimer)
2. Insecure non-HTTPS scheme (HTTP)
3. Dangerous scripting schemes (javascript:, data:)
4. Suspicious numeric IP hosts
5. URL shortening services
6. Unusual domain & subdomain structures (excessive subdomains, hyphens, suspicious TLDs)
7. Punycode / IDN homograph indicators
8. Embedded credentials & "@" userinfo deception
9. Direct executable (.apk, .exe) payload URLs
10. Suspicious compound combinations
11. Malformed and edge-case inputs (no crashes)
12. API Endpoint POST /api/check-url
"""

import unittest
import json
from app import app
from analyzer.url_checker import analyze_dedicated_url

class TestDedicatedURLAnalyzer(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    # 1. Normal HTTPS URL
    def test_ordinary_https_url(self):
        url = "https://www.wikipedia.org"
        report = analyze_dedicated_url(url)
        self.assertEqual(report['severity'], 'Low')
        self.assertLessEqual(report['risk_score'], 25)
        self.assertTrue(report['is_https'])
        self.assertEqual(report['normalized_url'], 'https://www.wikipedia.org')
        
        # Security Requirement: Must NOT claim clean URL is completely safe
        self.assertTrue(any('does NOT guarantee' in step for step in report['safe_next_steps']))

    # 2. Insecure Non-HTTPS Scheme
    def test_insecure_http_scheme(self):
        url = "http://example.com/about"
        report = analyze_dedicated_url(url)
        self.assertFalse(report['is_https'])
        ind_ids = [i['id'] for i in report['detected_indicators']]
        self.assertIn('NON_HTTPS_SCHEME', ind_ids)

    # 3. Dangerous Scripting Scheme
    def test_dangerous_script_scheme(self):
        url = "javascript:alert(document.cookie)"
        report = analyze_dedicated_url(url)
        ind_ids = [i['id'] for i in report['detected_indicators']]
        self.assertIn('DANGEROUS_SCHEME', ind_ids)
        self.assertGreaterEqual(report['risk_score'], 50)

    # 4. Suspicious Numeric IP Address
    def test_numeric_ip_host(self):
        url = "http://192.168.1.100/login"
        report = analyze_dedicated_url(url)
        self.assertIn(report['severity'], ['High', 'Critical'])
        ind_ids = [i['id'] for i in report['detected_indicators']]
        self.assertIn('NUMERIC_IP_HOST', ind_ids)
        # Check compound Non-HTTPS + Raw IP
        compound_names = [c['name'] for c in report['compound_signals']]
        self.assertIn('NON_HTTPS_RAW_IP', compound_names)

    # 5. URL Shortening Service
    def test_url_shortening_service(self):
        url = "https://bit.ly/3xY9Abc"
        report = analyze_dedicated_url(url)
        ind_ids = [i['id'] for i in report['detected_indicators']]
        self.assertIn('URL_SHORTENING_SERVICE', ind_ids)

    # 6. Unusual Domain Structure: Suspicious TLD & Excessive Hyphens
    def test_suspicious_tld_and_hyphens(self):
        url = "http://verify-account-security-update.xyz/login"
        report = analyze_dedicated_url(url)
        ind_ids = [i['id'] for i in report['detected_indicators']]
        self.assertIn('SUSPICIOUS_TLD', ind_ids)
        self.assertIn('EXCESSIVE_HYPHENS', ind_ids)

    # 7. Punycode IDN Homograph
    def test_punycode_idn_homograph(self):
        url = "http://xn--sbi-9qa.com/netbanking"
        report = analyze_dedicated_url(url)
        ind_ids = [i['id'] for i in report['detected_indicators']]
        self.assertIn('PUNYCODE_IDN_HOMOGRAPH', ind_ids)

    # 8. Embedded Credentials / "@" Trick
    def test_embedded_credentials_trick(self):
        url = "http://google.com:supersecret@evil-attacker.com/session"
        report = analyze_dedicated_url(url)
        ind_ids = [i['id'] for i in report['detected_indicators']]
        self.assertIn('EMBEDDED_CREDENTIALS_TRICK', ind_ids)

    # 9. Direct Executable / APK Download
    def test_direct_apk_download(self):
        url = "http://bijli-bill-payment.net/discom-app.apk"
        report = analyze_dedicated_url(url)
        ind_ids = [i['id'] for i in report['detected_indicators']]
        self.assertIn('DANGEROUS_DOWNLOAD_PAYLOAD', ind_ids)
        self.assertIn(report['severity'], ['High', 'Critical'])

    # 10. Suspicious Compound Combinations (Brand Spoof + Disposable TLD)
    def test_brand_spoof_on_suspicious_tld(self):
        url = "http://sbi-kyc-portal.xyz/login"
        report = analyze_dedicated_url(url)
        self.assertEqual(report['severity'], 'Critical')
        compound_names = [c['name'] for c in report['compound_signals']]
        self.assertIn('BRAND_SPOOF_ON_SUSPICIOUS_TLD', compound_names)

    # 11. Malformed and Edge-Case Inputs (Must not crash)
    def test_malformed_inputs_handled_safely(self):
        # Empty string
        res_empty = analyze_dedicated_url("")
        self.assertEqual(res_empty['severity'], 'Low')
        self.assertFalse(res_empty['is_valid_format'])

        # Invalid spaces
        res_space = analyze_dedicated_url("http://invalid domain with spaces.com")
        self.assertFalse(res_space['is_valid_format'])

        # Just characters without TLD
        res_no_tld = analyze_dedicated_url("justarandomstring")
        self.assertFalse(res_no_tld['is_valid_format'])

    # 12. API Endpoint POST /api/check-url
    def test_api_check_url_endpoint(self):
        payload = {"url": "http://192.168.1.1/update"}
        response = self.app.post('/api/check-url',
                                 data=json.dumps(payload),
                                 content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('normalized_url', data)
        self.assertIn('detected_indicators', data)
        self.assertIn('risk_score', data)
        self.assertIn('severity', data)
        self.assertIn('summary', data)
        self.assertIn('safe_next_steps', data)

    def test_api_check_url_empty_validation(self):
        response = self.app.post('/api/check-url',
                                 data=json.dumps({"url": ""}),
                                 content_type='application/json')
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn('error', data)

if __name__ == '__main__':
    unittest.main()
