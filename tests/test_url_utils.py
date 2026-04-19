"""
Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import unittest

from tests._env import ensure_test_env

ensure_test_env()

from services.common.url_utils import MAX_URL_LENGTH, is_safe_http_url


class UrlUtilsTests(unittest.TestCase):
    def test_accepts_http_and_https_urls(self):
        self.assertTrue(is_safe_http_url("http://example.com/path"))
        self.assertTrue(is_safe_http_url("https://example.com"))
        self.assertTrue(is_safe_http_url("https://8.8.8.8/health"))

    def test_rejects_invalid_or_non_http_urls(self):
        self.assertFalse(is_safe_http_url(""))
        self.assertFalse(is_safe_http_url(None))
        self.assertFalse(is_safe_http_url(object()))
        self.assertFalse(is_safe_http_url("ftp://example.com"))
        self.assertFalse(is_safe_http_url("https:///missing-host"))
        self.assertFalse(is_safe_http_url("http://[::1"))

    def test_accepts_trimmed_valid_urls(self):
        self.assertTrue(is_safe_http_url("  https://example.com/path  "))

    def test_rejects_local_and_private_targets(self):
        self.assertFalse(is_safe_http_url("http://localhost:8080"))
        self.assertFalse(is_safe_http_url("http://service.local/path"))
        self.assertFalse(is_safe_http_url("http://127.0.0.1/admin"))
        self.assertFalse(is_safe_http_url("http://10.0.0.10/api"))
        self.assertFalse(is_safe_http_url("http://169.254.1.2/metadata"))
        self.assertFalse(is_safe_http_url("http://240.0.0.1/metadata"))
        self.assertFalse(is_safe_http_url("http://[::1]/health"))

    def test_rejects_too_long_urls(self):
        path = "a" * 2100
        self.assertFalse(is_safe_http_url(f"https://example.com/{path}"))

    def test_accepts_exact_max_length_url(self):
        base = "https://example.com/"
        remaining = MAX_URL_LENGTH - len(base)
        self.assertGreaterEqual(remaining, 1)
        exact = base + ("a" * remaining)
        self.assertEqual(len(exact), MAX_URL_LENGTH)
        self.assertTrue(is_safe_http_url(exact))

    def test_rejects_non_fqdn_hosts(self):
        self.assertFalse(is_safe_http_url("http://internal-service/path"))


if __name__ == "__main__":
    unittest.main()
