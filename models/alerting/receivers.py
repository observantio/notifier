"""
Module defines Pydantic models for alerting-related data structures used in the API layer.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
"""

from pydantic import BaseModel, ConfigDict, Field

from custom_types.json import JSONDict

DESC_RECEIVER_NAME = "Receiver name"
DESC_RECEIVER_EMAIL_CONFIGS = "Email configurations for this receiver"
DESC_RECEIVER_SLACK_CONFIGS = "Slack configurations for this receiver"
DESC_RECEIVER_WEBHOOK_CONFIGS = "Webhook configurations for this receiver"
DESC_RECEIVER_PAGERDUTY_CONFIGS = "PagerDuty configurations for this receiver"
DESC_RECEIVER_TEAMS_CONFIGS = "Teams configurations for this receiver"
DESC_ALERTMANAGER_VERSION = "AlertManager version"
DESC_ALERTMANAGER_UPTIME = "AlertManager uptime"
DESC_ALERTMANAGER_CONFIG_HASH = "Configuration hash"
DESC_ALERTMANAGER_CLUSTER_STATUS = "Cluster status information"


class Receiver(BaseModel):
    name: str = Field(..., description=DESC_RECEIVER_NAME, examples=["primary-oncall"])
    email_configs: list[JSONDict] = Field(
        default_factory=list,
        alias="emailConfigs",
        description=DESC_RECEIVER_EMAIL_CONFIGS,
        examples=[[{"to": "oncall@example.com"}]],
    )
    slack_configs: list[JSONDict] = Field(
        default_factory=list,
        alias="slackConfigs",
        description=DESC_RECEIVER_SLACK_CONFIGS,
        examples=[[{"channel": "#alerts"}]],
    )
    webhook_configs: list[JSONDict] = Field(
        default_factory=list,
        alias="webhookConfigs",
        description=DESC_RECEIVER_WEBHOOK_CONFIGS,
        examples=[[{"url": "https://hooks.example.internal/alerts"}]],
    )
    pagerduty_configs: list[JSONDict] = Field(
        default_factory=list,
        alias="pagerdutyConfigs",
        description=DESC_RECEIVER_PAGERDUTY_CONFIGS,
        examples=[[{"routing_key": "pd-key"}]],
    )
    msteams_configs: list[JSONDict] = Field(
        default_factory=list,
        alias="msteamsConfigs",
        description=DESC_RECEIVER_TEAMS_CONFIGS,
        examples=[[{"webhook_url": "https://teams.example.internal/webhook"}]],
    )
    model_config = ConfigDict(use_enum_values=True, populate_by_name=True)


class AlertManagerStatus(BaseModel):
    version: str = Field(..., description=DESC_ALERTMANAGER_VERSION, examples=["0.28.1"])
    uptime: str = Field(..., description=DESC_ALERTMANAGER_UPTIME, examples=["72h15m"])
    config_hash: str = Field(
        ..., alias="configHash", description=DESC_ALERTMANAGER_CONFIG_HASH, examples=["sha256:abc123"]
    )
    config: JSONDict = Field(
        default_factory=dict,
        description="Alertmanager configuration details",
        examples=[{"route": {"receiver": "primary-oncall"}}],
    )
    cluster: JSONDict = Field(..., description=DESC_ALERTMANAGER_CLUSTER_STATUS, examples=[{"status": "ready"}])
    model_config = ConfigDict(use_enum_values=True, populate_by_name=True)
