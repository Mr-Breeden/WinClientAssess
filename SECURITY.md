# Security Policy

## Supported versions

The current accepted project baseline is **WCA v2.1.0**. Security reports should identify the affected release and, where safe, reproduce the issue against the latest available version. Older release lines should not be assumed to receive maintenance updates.

## Reporting a security issue

Please do **not** open a public issue containing an undisclosed vulnerability, client data, assessment evidence, secrets, or proprietary installer content.

If the repository supports GitHub Private Vulnerability Reporting / Security Advisories, use that channel. Otherwise contact the project maintainer through the organization's approved private security-reporting channel.

Include, when safe to do so:

- Windows Client Assessment version;
- Windows version/architecture;
- affected module/file;
- minimal reproduction steps;
- expected vs actual behavior;
- sanitized logs or traceback;
- whether the issue can expose tester/client information or cause unintended execution.

Do not attach real client installers, access tokens, credentials, or confidential assessment results unless an approved private exchange method has been established.

## Assessment-tool safety

Windows Client Assessment is designed for authorized security testing. A framework bug that causes unintended execution, persistence, destructive file changes, secret disclosure, or cross-assessment evidence mixing should be treated as a security issue even if it occurs only in a testing environment.
