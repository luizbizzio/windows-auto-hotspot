# Security Policy

## Supported Versions

This project is currently maintained on the latest version in the `main` branch.

| Version | Supported |
| --- | --- |
| Latest (main) | ✅ |
| Older versions | ❌ |

If you are using an older copy, please update before reporting a security issue.

## Reporting a Vulnerability

If you find a security issue, please **do not open a public GitHub issue**.

Please report it privately by using **GitHub Security Advisories** for this repository (preferred), or by contacting the maintainer directly.

When reporting, include:

- What you found
- Steps to reproduce
- Windows version
- PowerShell version
- Whether the script was installed with `-Install`
- Screenshots or logs (remove private information first)

## What to Expect

I will review the report as soon as possible and try to:

- Confirm whether it is a real vulnerability
- Reproduce the issue
- Prepare a fix
- Publish an update

Please note that response times may vary.

## Scope

This project is a local Windows automation script that manages Mobile Hotspot based on Ethernet status.

Security reports are especially helpful for issues related to:

- Privilege escalation
- Unsafe command execution
- Unsafe file handling
- Insecure scheduled task configuration
- Shortcut abuse
- Remote code execution risks
- Unsafe update or download behavior (for `-SourceUrl` installs)

## Out of Scope / Not a Security Issue

The following are usually **not** security vulnerabilities by themselves:

- Script requiring Administrator privileges (expected for install/uninstall)
- Windows Mobile Hotspot limitations or bugs
- Local network behavior of your router or ISP
- Misconfiguration on the user's machine
- Antivirus false positives without malicious behavior evidence

## Safe Usage Recommendations

For users, basic safety tips:

- Download the script only from the official repository
- Review the script before running if possible
- Use HTTPS URLs only when using `-SourceUrl`
- Do not run modified copies from unknown sources
- Keep Windows and PowerShell updated

## Disclosure

Please allow time for a fix before sharing details publicly.

Responsible disclosure helps protect everyone using the project.
