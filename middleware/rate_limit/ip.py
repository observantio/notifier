"""
IP-based rate limiter for Be Notified middleware.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Optional

from fastapi import Request

from config import config


def _valid_ip(value: str) -> Optional[str]:
    candidate = (value or "").strip()
    if not candidate:
        return None
    try:
        ip_address(candidate)
        return candidate
    except ValueError:
        return None


def client_ip(request: Request) -> str:
    def _trusted_proxy_peer() -> bool:
        if not config.trust_proxy_headers:
            return False
        trusted_cidrs = getattr(config, "trusted_proxy_cidrs", []) or []
        if not trusted_cidrs:
            return True

        direct = (request.client.host if request.client else "").strip()
        validated = _valid_ip(direct)
        if not validated:
            return False

        try:
            peer_ip = ip_address(validated)
            for cidr in trusted_cidrs:
                try:
                    if peer_ip in ip_network(cidr, strict=False):
                        return True
                except ValueError:
                    continue
        except ValueError:
            return False
        return False

    if _trusted_proxy_peer():
        forwarded_for = (request.headers.get("x-forwarded-for") or "").strip()
        if forwarded_for:
            first = forwarded_for.split(",", 1)[0].strip()
            valid_first = _valid_ip(first)
            if valid_first:
                return valid_first

        real_ip = (request.headers.get("x-real-ip") or "").strip()
        valid_real_ip = _valid_ip(real_ip)
        if valid_real_ip:
            return valid_real_ip

    direct = (request.client.host if request.client else "unknown").strip()
    return _valid_ip(direct) or "unknown"
