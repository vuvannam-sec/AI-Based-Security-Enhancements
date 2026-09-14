# Security Policy

## Project security model

This repository is a local research prototype. Its safest supported deployment is a single Linux development host or isolated VM with all HTTP services bound to loopback.

The Enforcer is privileged: it can place processes in cgroups, change CPU or memory limits, and send `SIGKILL` to a validated PID. Treat it as a local control plane rather than a general-purpose network service.

## Control-plane authentication

State-changing endpoints require the bearer token stored in `AISEC_CONTROL_TOKEN`. The bundled launcher creates a random token for the session when the variable is unset and passes the same value to the Sensor, Enforcer, Orchestrator, ML service, and dashboard.

The token reduces accidental or unauthorized local API use, but it is not a complete remote-security design:

- HTTP traffic is not encrypted;
- there is no user identity, RBAC, token rotation protocol, or audit-grade credential store;
- a process with sufficient access to the service environment can obtain the token;
- root on the host is outside this prototype's threat model.

Keep the services on `127.0.0.1` unless you have added an appropriate authenticated and encrypted front end.

## Privileged operations

The Enforcer rejects PIDs `<= 2`, refuses to target itself or its parent process, validates cgroup resource-limit formats, and requires the control token for action/release requests. These checks reduce dangerous API mistakes; they do not make arbitrary remote exposure safe.

Synthetic-data generation and model retraining also require the control token. File paths supplied to those endpoints are constrained to the configured data directory (`AISEC_DATA_DIR`, default `data/`).

## Generated and local-only files

Do not commit:

- `.env` or local environment overrides;
- API tokens, credentials, private keys, or certificates containing private material;
- generated datasets or model artifacts;
- local logs, coverage files, virtual environments, or editor state.

The root `.gitignore` covers common forms of these files, but it is not a secret scanner. Review staged changes before every public push.

## Reporting a vulnerability

Avoid posting working exploit instructions, tokens, private information, or other sensitive reproduction material in a public issue. Report enough non-sensitive context to identify the affected component and impact, then coordinate detailed reproduction privately with the repository owner.

## Supported versions

The project currently follows the `main` branch rather than maintaining security-supported release lines. Security fixes are applied to the latest revision.
