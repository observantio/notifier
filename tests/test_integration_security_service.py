"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import unittest
from unittest.mock import patch

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from fastapi import HTTPException

from services.alerting.integration_security_service import (
    is_jira_sso_available,
    normalize_jira_auth_mode,
    normalize_visibility,
    validate_jira_credentials,
)


class IntegrationSecurityServiceTests(unittest.TestCase):
    def test_normalize_visibility_maps_public_to_tenant(self):
        self.assertEqual(normalize_visibility('public'), 'tenant')
        self.assertEqual(normalize_visibility('group'), 'group')
        self.assertEqual(normalize_visibility('invalid'), 'private')

    def test_normalize_jira_auth_mode_rejects_unsupported(self):
        with self.assertRaises(HTTPException):
            normalize_jira_auth_mode('oauth')

    def test_normalize_jira_auth_mode_sso_requires_oidc(self):
        with patch('services.alerting.integration_security_service.is_jira_sso_available', return_value=False):
            with self.assertRaises(HTTPException):
                normalize_jira_auth_mode('sso')

    def test_validate_jira_credentials_api_token_mode(self):
        validate_jira_credentials(
            base_url='https://jira.example.com',
            auth_mode='api_token',
            email='user@example.com',
            api_token='token123',
            bearer_token=None,
        )

        with self.assertRaises(HTTPException):
            validate_jira_credentials(
                base_url='https://jira.example.com',
                auth_mode='api_token',
                email='',
                api_token='token123',
                bearer_token=None,
            )

    def test_is_jira_sso_available_missing_config_attrs_does_not_crash(self):
        with patch(
            "services.alerting.integration_security_service.config",
            object(),
        ):
            self.assertFalse(is_jira_sso_available())


if __name__ == '__main__':
    unittest.main()
