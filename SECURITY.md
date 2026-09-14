# Security Policy

## Scope

This repository is a research and teaching prototype. It contains a privileged Enforcer service that can change cgroup limits and terminate processes. Treat that service as a local control-plane component, not as a network-facing API.

## Safe deployment assumptions

- Keep the Sensor, ML, Orchestrator, and especially Enforcer APIs bound to loopback unless you are working in an isolated lab.
- Do not expose port `8002` to an untrusted network.
- Run the project only on systems you own or are explicitly authorized to test.
- Review any change that increases the Enforcer's privileges or expands its network reach.
- Do not commit credentials, API keys, private keys, `.env` files, production datasets, or host-specific secrets.

The provided launcher defaults to `127.0.0.1`. Changing `HOST` or `UI_HOST` is an explicit opt-in and may widen the attack surface.

## Reporting a vulnerability

Please do not publish exploit details, credentials, or sensitive host information in a public GitHub issue.

For repository-level issues that can be described safely, open an issue with the minimum information needed to reproduce the problem. For sensitive findings, contact the repository owner privately through an appropriate GitHub contact channel before disclosure.

## Supported versions

The default branch is the only version actively maintained.
