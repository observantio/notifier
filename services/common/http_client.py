"""
Shared HTTP client utilities for making requests to external services, including functions for handling authentication,
error handling, and response parsing. This module provides a common interface for making HTTP requests to services like
Keycloak for user provisioning and token validation, abstracting away the details of the HTTP interactions and allowing
for easier integration with different authentication providers.

Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import httpx

from config import config


def create_async_client(timeout_seconds: float) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout_seconds),
        limits=httpx.Limits(
            max_connections=config.http_client_max_connections,
            max_keepalive_connections=config.http_client_max_keepalive_connections,
            keepalive_expiry=config.http_client_keepalive_expiry,
        ),
    )
