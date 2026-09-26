"""
Automated Test Suite for Phishing URL Detection System.
Tests Flask routes, URL feature extraction, ML inference, and SQLite operations.
"""

import sys
import unittest
from app import app
from database.db import get_dashboard_stats, get_all_scans, clear_all_scans
from utils.url_features import extract_features, extract_feature_vector, FEATURE_NAMES


class TestPhishingDetector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def setUp(self):
        clear_all_scans()

    def test_01_feature_extraction(self):
        """Test extraction of 18 cybersecurity features on sample URLs."""
        url = "http://192.168.1.105/paypal/signin.php?token=9284"
        features = extract_features(url)
        self.assertEqual(len(FEATURE_NAMES), 18)
        self.assertEqual(features["has_ip_address"], 1)
        self.assertEqual(features["has_https"], 0)
        self.assertGreaterEqual(features["suspicious_word_count"], 1)

        vector = extract_feature_vector(url)
        self.assertEqual(len(vector), 18)
        print("[+] Test 1 Passed: Feature extraction produces complete 18-element vector.")

    def test_02_dashboard_route(self):
        """Test GET / renders dashboard with 200 status."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Phishing URL", response.data)
        self.assertIn(b"Total URLs Analyzed", response.data)
        print("[+] Test 2 Passed: Dashboard route loads successfully.")

    def test_03_analyze_safe_url(self):
        """Test analysis of legitimate URL."""
        response = self.client.post("/analyze", data={"url": "https://www.google.com/search?q=cybersecurity"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SAFE URL (LIKELY SAFE)", response.data)
        self.assertIn(b"LOW RISK", response.data)
        print("[+] Test 3 Passed: Safe URL classified correctly as LOW RISK / Likely Safe.")

    def test_04_analyze_phishing_url(self):
        """Test analysis of phishing URL with IP address and keyword."""
        response = self.client.post("/analyze", data={"url": "http://192.168.1.105/paypal/signin.php?cmd=login_submit"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"PHISHING URL DETECTED", response.data)
        self.assertIn(b"HIGH RISK", response.data)
        print("[+] Test 4 Passed: Malicious IP URL classified correctly as HIGH RISK / Phishing.")

    def test_05_analyze_invalid_url(self):
        """Test input validation on empty and malformed URLs."""
        response = self.client.post("/analyze", data={"url": ""}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"URL field cannot be empty", response.data)
        print("[+] Test 5 Passed: Empty input validation handled gracefully.")

    def test_06_scan_history_and_search(self):
        """Test SQLite persistence, searching, and filtering in /history."""
        # Insert two scans
        self.client.post("/analyze", data={"url": "https://www.google.com"})
        self.client.post("/analyze", data={"url": "http://paypal.com.verification-center.account-security.tk/login.php"})

        # Verify history page
        response = self.client.get("/history")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"google.com", response.data)

        # Search test
        search_res = self.client.get("/history?q=google")
        self.assertEqual(search_res.status_code, 200)
        self.assertIn(b"google.com", search_res.data)

        # Filter test
        filter_res = self.client.get("/history?filter=phishing")
        self.assertEqual(filter_res.status_code, 200)
        self.assertIn(b"Phishing", filter_res.data)
        print("[+] Test 6 Passed: History persistence, search, and filtering verified.")

    def test_07_documentation_route_removed(self):
        """Test GET /about and /documentation return 404 since page is removed."""
        about_res = self.client.get("/about")
        self.assertEqual(about_res.status_code, 404)
        doc_res = self.client.get("/documentation")
        self.assertEqual(doc_res.status_code, 404)
        print("[+] Test 7 Passed: Documentation route verified as removed (404).")

    def test_08_api_endpoints(self):
        """Test JSON REST endpoints /api/stats and /api/scan."""
        stats_res = self.client.get("/api/stats")
        self.assertEqual(stats_res.status_code, 200)
        stats_json = stats_res.get_json()
        self.assertEqual(stats_json["status"], "success")

        scan_res = self.client.post("/api/scan", json={"url": "https://github.com"})
        self.assertEqual(scan_res.status_code, 200)
        scan_json = scan_res.get_json()
        self.assertTrue(scan_json["success"])
        self.assertIn("risk_score", scan_json)
        print("[+] Test 8 Passed: REST API endpoints operational.")


if __name__ == "__main__":
    unittest.main()
