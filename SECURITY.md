# Security policy

This repository contains a defensive Linux monitoring prototype with a privileged enforcement component. Treat it as lab software unless you have independently hardened it for your environment.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting / Security Advisory flow for this repository when available:

https://github.com/vuvannam-sec/AI-Based-Security-Enhancements/security/advisories/new

Do not include working exploit details, credentials, private host information, or other sensitive material in a public issue.

If private reporting is unavailable, open a minimal public issue that describes the affected component and impact without publishing sensitive reproduction details.

## Operational guidance

- Keep the service stack bound to loopback unless remote access has been deliberately secured.
- Do not expose the Enforcer API directly to an untrusted network. It can throttle and terminate processes and may run with elevated privileges.
- Run demonstrations in a VM or other environment you control.
- Do not use real secrets, production credentials, or private datasets in synthetic examples or committed configuration.
- If a credential is ever committed, rotate/revoke it first. Removing it from the latest tree is not sufficient because Git history may retain previous versions.
- Review generated data and logs before sharing them; process telemetry can contain usernames, paths, command lines, IP addresses, and other environment-specific information.

## Scope

Security reports about the repository's own code, unsafe defaults, privilege boundaries, data handling, and service exposure are in scope.

Reports about using the demo utilities against systems you do not own or have permission to test are out of scope. The manual simulators are intended only for controlled local validation.
