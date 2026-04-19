"""
Middleware components for Notifier API.

Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from .concurrency_limit import ConcurrencyLimitMiddleware
from .dependencies import get_current_user, require_any_permission, require_any_permission_with_scope
from .headers import security_headers_middleware
from .request_size_limit import RequestSizeLimitMiddleware
from .resilience import with_retry, with_timeout

__all__ = [
    "ConcurrencyLimitMiddleware",
    "RequestSizeLimitMiddleware",
    "get_current_user",
    "require_any_permission",
    "require_any_permission_with_scope",
    "security_headers_middleware",
    "with_retry",
    "with_timeout",
]
