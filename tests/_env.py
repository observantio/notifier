"""

Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

import atexit
import os
import shutil
import sys
import tempfile
from pathlib import Path


_TEST_SQLITE_DIR = Path(tempfile.mkdtemp(prefix="observantio-notifier-tests-"))
_TEST_SQLITE_URL = f"sqlite:///{_TEST_SQLITE_DIR / 'notifier.sqlite3'}"
_TEST_DATABASE_INITIALIZED = False

atexit.register(shutil.rmtree, _TEST_SQLITE_DIR, ignore_errors=True)
def ensure_test_env() -> None:
    global _TEST_DATABASE_INITIALIZED

    service_root = Path(__file__).resolve().parents[1]
    if str(service_root) not in sys.path:
        sys.path.insert(0, str(service_root))

    use_temp_sqlite = os.getenv("USE_TEMP_SQLITE_TEST_DB", "").strip().lower() in {"1", "true", "yes", "on"}
    if use_temp_sqlite:
        os.environ["DATABASE_URL"] = _TEST_SQLITE_URL
        os.environ["NOTIFIER_DATABASE_URL"] = _TEST_SQLITE_URL
    else:
        os.environ.setdefault("DATABASE_URL", "postgresql://safeuser:safePass_123@db:5432/watchdog")
        os.environ.setdefault("NOTIFIER_DATABASE_URL", os.environ["DATABASE_URL"])

    os.environ.setdefault("JWT_ALGORITHM", "RS256")
    os.environ.setdefault("JWT_PRIVATE_KEY", "test-private-key")
    os.environ.setdefault("JWT_PUBLIC_KEY", "test-public-key")
    os.environ.setdefault("JWT_AUTO_GENERATE_KEYS", "false")

    database_url = os.environ.get("NOTIFIER_DATABASE_URL", os.environ.get("DATABASE_URL", ""))
    if _TEST_DATABASE_INITIALIZED or not database_url.startswith("sqlite"):
        return

    from database import init_database, init_db

    init_database(database_url)
    init_db()
    _TEST_DATABASE_INITIALIZED = True
