"""
IP-based rate limiter for Be Notified middleware.

Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network

from fastapi import Request

from config import config


def _valid_ip(value: str) -> str | None:
    candidate = (value or "").strip()
    if not candidate:
        return None
    try:
        ip_address(candidate)
        return candidate
    except ValueError:
        return None


def _trusted_proxy_networks(trusted_cidrs: list[str]) -> list[IPv4Network | IPv6Network]:
    networks: list[IPv4Network | IPv6Network] = []
    for cidr in trusted_cidrs:
        try:
            networks.append(ip_network(cidr, strict=False))
        except ValueError:
            continue
    return networks


def client_ip(request: Request) -> str:
    direct = (request.client.host if request.client else "").strip()
    candidate = _valid_ip(direct)

    if config.trust_proxy_headers and candidate:
        trusted_cidrs = getattr(config, "trusted_proxy_cidrs", []) or []
        trusted_peer = not trusted_cidrs
        if not trusted_peer:
            peer_ip: IPv4Address | IPv6Address | None = None
            try:
                peer_ip = ip_address(direct)
            except ValueError:
                pass
            if peer_ip is not None:
                trusted_peer = any(peer_ip in network for network in _trusted_proxy_networks(trusted_cidrs))

        if trusted_peer:
            forwarded_for = (request.headers.get("x-forwarded-for") or "").strip()
            first = _valid_ip(forwarded_for.split(",", 1)[0].strip()) if forwarded_for else None
            if first:
                return first

            real_ip = _valid_ip((request.headers.get("x-real-ip") or "").strip())
            if real_ip:
                return real_ip

    return candidate or "unknown"
