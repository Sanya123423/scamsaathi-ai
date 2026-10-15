"""
ScamSaathi - Machine Learning Classifier Test Suite
Verifies:
1. Model artifact loading via joblib
2. Handling of missing, whitespace, and None inputs
3. Prediction accuracy on clearly labeled suspicious and legitimate examples
4. Separation of ML prediction from rule-based findings
5. Presence of statistical disclaimers (not probability of criminality)
6. Hybrid fusion weighting (80% rules, 20% ML) with safeguards
7. Graceful fallback when model is unavailable
"""

import unittest
from ml.classifier import load_classifier, predict_message
from analyzer.scoring import combine_rule_and_ml_evidence, calculate_risk_score

class TestMLClassifier(unittest.TestCase):

    # 1. Model Loading
    def test_model_loading(self):
        pipeline = load_classifier()
        self.assertIsNotNone(pipeline, "scam_classifier.joblib should load successfully")
        self.assertTrue(hasattr(pipeline, 'predict'), "Pipeline must possess predict() method")
        self.assertTrue(hasattr(pipeline, 'predict_proba'), "Pipeline must possess predict_proba() method")

    # 2. Missing & Empty Inputs
    def test_missing_and_empty_inputs(self):
        res_empty = predict_message("")
        self.assertEqual(res_empty['status'], 'empty_input')
        self.assertEqual(res_empty['model_confidence'], 0.0)

        res_spaces = predict_message("    \n\t  ")
        self.assertEqual(res_spaces['status'], 'empty_input')

        res_none = predict_message(None)
        self.assertEqual(res_none['status'], 'empty_input')

    # 3. Prediction on Suspicious Example
    def test_prediction_suspicious_message(self):
        msg = "Dear customer your electricity power will be disconnected at 9:30 PM tonight due to unpaid bill. Call officer at 9876543210."
        res = predict_message(msg)
        self.assertEqual(res['status'], 'active')
        self.assertEqual(res['predicted_category'], 'Suspicious / Scam')
        self.assertEqual(res['predicted_class_id'], 1)
        self.assertGreaterEqual(res['model_confidence'], 0.5)
        self.assertIn('Logistic regression', res['explanation'])

    # 4. Prediction on Legitimate Example
    def test_prediction_legitimate_message(self):
        msg = "Hi Rahul, our project status meeting is scheduled for 3:00 PM tomorrow in conference room B."
        res = predict_message(msg)
        self.assertEqual(res['status'], 'active')
        self.assertEqual(res['predicted_category'], 'Legitimate / Benign')
        self.assertEqual(res['predicted_class_id'], 0)
        self.assertGreaterEqual(res['model_confidence'], 0.5)

    # 5. Statistical Disclaimer Requirement
    def test_statistical_disclaimer_present(self):
        msg = "Test sample message"
        res = predict_message(msg)
        self.assertIn('disclaimer', res)
        self.assertIn('NOT a verified real-world mathematical probability', res['disclaimer'])

    # 6. Hybrid Risk Fusion Function
    def test_hybrid_risk_fusion(self):
        # Case A: Critical rule score (85) with ML confirming suspicious (0.90)
        ml_suspicious = {
            'status': 'active',
            'predicted_class_id': 1,
            'model_confidence': 0.90
        }
        fused_score, details = combine_rule_and_ml_evidence(
            rule_score=85,
            ml_assessment=ml_suspicious,
            indicators_count=3,
            has_compound_threats=True
        )
        self.assertGreaterEqual(fused_score, 80)
        self.assertEqual(details['fusion_mode'], 'hybrid_weighted')

        # Case B: Clean message (rule_score = 0) with legitimate ML prediction
        ml_legit = {
            'status': 'active',
            'predicted_class_id': 0,
            'model_confidence': 0.85
        }
        fused_score_clean, _ = combine_rule_and_ml_evidence(
            rule_score=0,
            ml_assessment=ml_legit,
            indicators_count=0,
            has_compound_threats=False
        )
        self.assertEqual(fused_score_clean, 0)

        # Case C: ML unavailable fallback mode
        ml_unavailable = {'status': 'unavailable'}
        fallback_score, fb_details = combine_rule_and_ml_evidence(
            rule_score=60,
            ml_assessment=ml_unavailable,
            indicators_count=2,
            has_compound_threats=False
        )
        self.assertEqual(fallback_score, 60)
        self.assertEqual(fb_details['fusion_mode'], 'rule_only')

    # 7. End-to-End ThreatAssessment Integration
    def test_threat_assessment_returns_ml_block(self):
        msg = "Earn 5000 daily with part time Telegram job. Pay 500 fee."
        assessment = calculate_risk_score(msg)
        as_dict = assessment.to_dict()
        self.assertIn('ml_assessment', as_dict)
        self.assertEqual(as_dict['ml_assessment']['status'], 'active')
        self.assertIn('model_confidence', as_dict['ml_assessment'])
        self.assertIn('predicted_category', as_dict['ml_assessment'])

if __name__ == '__main__':
    unittest.main()
