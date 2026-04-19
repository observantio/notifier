"""
Transport utilities for notification services, providing functions to perform HTTP requests with retry logic for
transient failures and to send emails using SMTP with similar retry mechanisms. This module includes error handling to
determine whether exceptions are transient and should be retried, as well as logging of failures to facilitate
troubleshooting. The transport utilities ensure that notification sending operations are resilient to temporary issues
such as network errors or service unavailability, while also integrating with the overall notification system to provide
reliable delivery of alerts and messages.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

import asyncio
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any, cast

import aiosmtplib
import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from config import config
from custom_types.json import JSONValue

logger = logging.getLogger(__name__)

DEFAULT_RETRY_ON_STATUS: frozenset[int] = frozenset({429, 500, 502, 503, 504})
QueryParamValue = str | int | float | bool


@dataclass(frozen=True)
class SmtpDeliveryConfig:
    hostname: str
    port: int
    username: str | None = None
    password: str | None = None
    start_tls: bool = False
    use_tls: bool = False


@dataclass(frozen=True)
class HttpPostRequest:
    client: httpx.AsyncClient
    url: str
    json: Mapping[str, JSONValue] | None = None
    headers: dict[str, str] | None = None
    params: dict[str, QueryParamValue] | None = None
    retry_on_status: frozenset[int] | set[int] = DEFAULT_RETRY_ON_STATUS


def _coerce_smtp_config(
    smtp: SmtpDeliveryConfig | object | None,
    legacy_args: tuple[object, ...],
    legacy_kwargs: Mapping[str, object],
) -> SmtpDeliveryConfig:
    if isinstance(smtp, SmtpDeliveryConfig):
        return smtp

    values: list[object] = []
    if smtp is not None:
        values.append(smtp)
    values.extend(legacy_args)

    kwargs = dict(legacy_kwargs)
    hostname_value = values[0] if values else kwargs.pop("hostname", "")
    port_value = values[1] if len(values) > 1 else kwargs.pop("port", 0)
    username_value = values[2] if len(values) > 2 else kwargs.pop("username", None)
    password_value = values[3] if len(values) > 3 else kwargs.pop("password", None)
    start_tls_value = values[4] if len(values) > 4 else kwargs.pop("start_tls", False)
    use_tls_value = values[5] if len(values) > 5 else kwargs.pop("use_tls", False)

    hostname = str(hostname_value or "").strip()
    if not hostname:
        raise ValueError("SMTP hostname is required")

    try:
        port = int(cast(int | str | bytes | bytearray, port_value))
    except (TypeError, ValueError) as exc:
        raise ValueError("SMTP port must be an integer") from exc

    username = str(username_value).strip() if username_value is not None else ""

    return SmtpDeliveryConfig(
        hostname=hostname,
        port=port,
        username=username or None,
        password=str(password_value) if password_value is not None else None,
        start_tls=bool(start_tls_value),
        use_tls=bool(use_tls_value),
    )


def _is_transient_http(exc: BaseException, retry_on_status: frozenset[int]) -> bool:
    if isinstance(exc, httpx.RequestError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code if exc.response else 0
        return status in retry_on_status
    return False


def _is_transient_smtp(exc: BaseException) -> bool:
    if isinstance(exc, aiosmtplib.errors.SMTPException):
        code = getattr(exc, "code", None)
        return isinstance(code, int) and 400 <= code < 500
    return False


async def post_with_retry(request: HttpPostRequest) -> httpx.Response:
    retry_set = frozenset(request.retry_on_status)

    @retry(
        retry=retry_if_exception(lambda exc: _is_transient_http(exc, retry_set)),
        stop=stop_after_attempt(config.max_retries),
        wait=wait_exponential(multiplier=config.retry_backoff),
        reraise=True,
    )
    async def _attempt() -> httpx.Response:
        try:
            resp = await request.client.post(
                request.url,
                json=request.json,
                headers=request.headers,
                params=request.params,
                timeout=config.default_timeout,
            )
            resp.raise_for_status()
            return resp
        except Exception as exc:
            logger.warning("HTTP POST failed, retrying: %s", request.url, exc_info=exc)
            raise

    return await _attempt()


@retry(
    retry=retry_if_exception(_is_transient_smtp),
    stop=stop_after_attempt(config.max_retries),
    wait=wait_exponential(multiplier=config.retry_backoff),
    reraise=True,
)
async def send_smtp_with_retry(
    message: EmailMessage,
    *legacy_args: object,
    smtp: SmtpDeliveryConfig | object | None = None,
    **legacy_kwargs: object,
) -> object:
    smtp_config = _coerce_smtp_config(smtp, legacy_args, legacy_kwargs)
    try:
        async with asyncio.timeout(config.default_timeout):
            smtp_send = cast(Any, aiosmtplib.send)
            try:
                return await smtp_send(
                    message,
                    hostname=smtp_config.hostname,
                    port=smtp_config.port,
                    username=smtp_config.username,
                    password=smtp_config.password,
                    start_tls=smtp_config.start_tls,
                    use_tls=smtp_config.use_tls,
                )
            except TypeError as exc:
                if "positional argument" not in str(exc):
                    raise
                kwargs = {
                    "message": message,
                    "hostname": smtp_config.hostname,
                    "port": smtp_config.port,
                    "username": smtp_config.username,
                    "password": smtp_config.password,
                    "start_tls": smtp_config.start_tls,
                    "use_tls": smtp_config.use_tls,
                }
                return await smtp_send(
                    **kwargs,
                )
    except Exception as exc:
        logger.warning("SMTP send failed, retrying: %s:%s (%s)", smtp_config.hostname, smtp_config.port, exc)
        raise
