<div align="center">

# Observantio's Notifier

  <img src="assets/triangle.png" alt="Notifier triangle icon" width="150" />

  <p>
    <a href="https://github.com/observantio/watchdog/blob/main/README.md">
      <img src="https://img.shields.io/badge/Control%20Plane-Watchdog-0f766e?style=flat-square&logo=github&logoColor=white" alt="Watchdog" />
    </a>
    <a href="https://github.com/observantio/watchdog/blob/main/USER%20GUIDE.md">
      <img src="https://img.shields.io/badge/Operator%20Guide-Docs-16a34a?style=flat-square&logo=readthedocs&logoColor=white" alt="Docs" />
    </a>
  </p>
  <p>
    <a href="https://github.com/observantio/notifier/actions/workflows/ci.yml">
      <img src="https://github.com/observantio/notifier/actions/workflows/ci.yml/badge.svg?branch=main" alt="Notifier CI" />
    </a>
  </p>
</div>
<div>
  <p>
    <strong>Internal alerting and incident workflow engine for multi-tenant observability teams</strong>
  </p>
  <p>
    Notifier is the alerting domain service in the Observantio stack. It owns durable workflow state for alert rules, silences, channels, incidents, Jira synchronization, and inbound Alertmanager webhooks, turning raw alert traffic into actionable operator workflows.
  </p>
</div>

## What This Service Owns

- Alertmanager-facing APIs for alerts, silences, status, receivers, and webhooks.
- Persistent alert rule management with visibility controls and Mimir sync.
- Notification channel management for email, Slack, Teams, webhook, and PagerDuty.
- Incident lifecycle management, including assignee changes, notes, summary views, and state transitions.
- Jira integration discovery, configuration, issue linking, and comment synchronization.
- Internal-only request validation between Watchdog and Notifier.

## Runtime Overview

Be Notified is intended to run on the internal network only.

| Detail | Value |
| --- | --- |
| Service name | `Notifier` |
| Default host | `127.0.0.1` |
| Default port | `4319` |
| Docs path | `/docs` when `ENABLE_API_DOCS=true` |
| Health | `/health` |
| Readiness | `/ready` |
| Main API prefix | `/internal/v1/api/alertmanager` |
| Webhook prefix | `/internal/v1/alertmanager` |

The service initializes its database on startup, wires request-size and concurrency middleware, then exposes the internal API used by the main Watchdog control plane.

## Security Model

Most requests must come from another trusted internal service.

Required controls:

- `X-Service-Token`: must match `NOTIFIER_EXPECTED_SERVICE_TOKEN` or `GATEWAY_INTERNAL_SERVICE_TOKEN`.
- `Authorization: Bearer <context-jwt>`: required by permission-protected routes so tenant, user, role, and group context can be enforced.
- `INBOUND_WEBHOOK_TOKEN`: required for public-style Alertmanager webhook ingress and validated by the alerting service.

Paths exempt from the service-token middleware:

- `/health`
- `/ready`
- `/docs`, `/redoc`, `/openapi.json` when docs are enabled
- webhook ingress routes under `/internal/v1/alertmanager/alerts/*`

This service should not be exposed directly to the public internet. It may need outward connectivity to send alerts to channels

## API Surface

Main route groups:

- Alerts: list, group, create, and delete Alertmanager alerts.
- Silences: list, get, create, update, delete, and hide silences.
- Rules: import, list, read, create, update, delete, hide, test, and metrics-name discovery.
- Channels: list, read, create, update, delete, hide, and test notification channels.
- Incidents: list, summarize, and patch incidents.
- Jira: integration config, project discovery, issue-type discovery, incident linking, and note/comment sync.
- Access maintenance: group-share pruning for visibility cleanup.
- Webhooks: inbound alert webhooks and severity-specific ingress endpoints.

The route layout is split across these internal domains:

- `routers/observability/alerts/*`
- `routers/observability/incidents.py`
- `routers/observability/jira/*`

## Core Dependencies

Be Notified depends on:

- PostgreSQL for persistent state.
- Alertmanager for alert and silence operations.
- Mimir for rule synchronization and metric discovery.
- SMTP or third-party mail providers for incident and onboarding email notifications.
- Optional Jira integration for linked incident workflows.

## Environment Variables

The full configuration surface lives in `config.py`. These are the variables most developers need first.

### Required or Strongly Recommended

```env
DATABASE_URL=postgresql://user:strongPassword@db:5432/observantio
NOTIFIER_DATABASE_URL=postgresql://user:strongPassword@db:5432/observantio
NOTIFIER_EXPECTED_SERVICE_TOKEN=replace-with-a-long-random-shared-secret
INBOUND_WEBHOOK_TOKEN=replace-with-a-long-random-webhook-secret
GATEWAY_INTERNAL_SERVICE_TOKEN=replace-with-a-long-random-shared-secret
MIMIR_URL=http://mimir:9009
ALERTMANAGER_URL=http://alertmanager:9093
JWT_ALGORITHM=RS256
```

### Frequently Used Operational Settings

```env
HOST=127.0.0.1
PORT=4319
LOG_LEVEL=info
ENABLE_API_DOCS=true
DEFAULT_TIMEOUT=30
MAX_REQUEST_BYTES=1048576
MAX_CONCURRENT_REQUESTS=200
CONCURRENCY_ACQUIRE_TIMEOUT=1.0
RATE_LIMIT_PUBLIC_PER_MINUTE=120
```

### Internal Context JWT Settings

```env
NOTIFIER_CONTEXT_VERIFY_KEY=replace-with-shared-jwt-verification-key
NOTIFIER_CONTEXT_SIGNING_KEY=replace-with-shared-jwt-signing-key
NOTIFIER_CONTEXT_ISSUER=watchdog-main
NOTIFIER_CONTEXT_AUDIENCE=notifier
NOTIFIER_CONTEXT_ALGORITHM=HS256
NOTIFIER_CONTEXT_REPLAY_TTL_SECONDS=180
```

### Email Settings

The service supports assignment, welcome, and temporary-password emails. The exact keys depend on the flow. Examples:

```env
INCIDENT_ASSIGNMENT_EMAIL_ENABLED=true
INCIDENT_ASSIGNMENT_SMTP_HOST=smtp.example.com
INCIDENT_ASSIGNMENT_SMTP_PORT=587
INCIDENT_ASSIGNMENT_SMTP_USERNAME=mailer
INCIDENT_ASSIGNMENT_SMTP_PASSWORD=super-secret
INCIDENT_ASSIGNMENT_FROM=alerts@example.com

USER_WELCOME_EMAIL_ENABLED=true
USER_WELCOME_SMTP_HOST=smtp.example.com
PASSWORD_RESET_EMAIL_ENABLED=true
APP_LOGIN_URL=https://observantio.example.com/login
```

### Optional Hardening

```env
TRUST_PROXY_HEADERS=false
TRUSTED_PROXY_CIDRS=
WEBHOOK_IP_ALLOWLIST=
AUTH_PUBLIC_IP_ALLOWLIST=
GRAFANA_PROXY_IP_ALLOWLIST=
ALLOWLIST_FAIL_OPEN=false
```

## Local Development

### 1. Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

### 2. Configure environment

Set the environment variables above. At minimum, provide a real database URL and internal service secrets. The config validation rejects obviously weak example credentials in normal runs.

### 3. Run the service

```bash
python main.py
```

Or with uvicorn:

```bash
uvicorn main:app --host 127.0.0.1 --port 4319 --reload
```

### 4. Run tests

```bash
pytest -q
```

To run coverage for service modules:

```bash
pytest -q --cov=services --cov-report=term-missing
```

The service `pyproject.toml` now carries the developer-facing pytest, coverage, and mypy defaults so local editors and Python tooling can discover the service configuration from a standard entry point.

## Docker

Build and run the service locally:

```bash
docker build -t notifier:latest .
docker run --rm -it \
    -p 4319:4319 \
    --env-file .env \
    --name notifier \
    notifier:latest
```

In the mono-repo, prefer the root `docker-compose.yml` and root environment files as the deployment source of truth.

## Request Flow

Typical incident flow:

1. Alertmanager sends alerts to Be Notified webhook endpoints.
2. Be Notified validates inbound webhook security.
3. Alert payloads are normalized into incident state and stored.
4. Rules, silences, channels, and incidents are filtered by tenant and group visibility.
5. Assignee changes, notes, and state transitions can trigger emails and Jira synchronization.
6. Rule changes are pushed back to Mimir so the alert source of truth stays aligned.

## Developer Notes

- `main.py` performs database setup at startup.
- `services/alertmanager_service.py` is the core orchestrator for Alertmanager, silences, webhook security, and Mimir rule sync.
- `services/storage_db_service.py` is the high-level storage facade over rules, channels, incidents, and hidden-resource state.
- `services/notification_service.py` handles assignment and account email flows.
- `services/jira_service.py` and `routers/observability/jira/*` cover Jira integration lifecycle and incident linkage.

## Troubleshooting

Common startup issues:

- `Service token not configured`: set `NOTIFIER_EXPECTED_SERVICE_TOKEN` or `GATEWAY_INTERNAL_SERVICE_TOKEN`.
- `Unsafe DATABASE_URL detected`: replace placeholder credentials with a real credentialed DSN.
- Readiness returns `503`: database connectivity is failing.
- Webhooks return `401`: `INBOUND_WEBHOOK_TOKEN` does not match the incoming header or bearer token.

## License

Licensed under the Apache License 2.0.

Preserve the existing notices and attribution headers in redistributed copies.
