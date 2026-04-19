"""
Utilities for checking if URLs are valid and properly formatted, including functions to validate URL formats, ensure
that URLs have a scheme (defaulting to https:// if missing), and create configured HTTP clients for making requests
to external services. This module provides common URL-related utilities that can be used across different parts of
the application when working with URLs for external services, such as authentication providers or API endpoints.

Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import ipaddress
from urllib.parse import urlparse

ALLOWED_SCHEMES = frozenset({"http", "https"})
MAX_URL_LENGTH = 2048


def is_safe_http_url(value: str | None) -> bool:
    raw_value = value.strip() if isinstance(value, str) else ""
    is_valid = bool(raw_value and len(raw_value) <= MAX_URL_LENGTH)
    parsed = None
    if is_valid:
        try:
            parsed = urlparse(raw_value)
        except ValueError:
            is_valid = False

    hostname = parsed.hostname if parsed else None
    if is_valid and parsed:
        is_valid = bool(parsed.scheme in ALLOWED_SCHEMES and hostname and parsed.netloc and "." in hostname)
    if is_valid and hostname:
        is_valid = hostname not in ("localhost",) and not hostname.endswith(".local")

    if is_valid and hostname:
        try:
            ip = ipaddress.ip_address(hostname)
            is_valid = not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
        except ValueError:
            pass
    return is_valid
