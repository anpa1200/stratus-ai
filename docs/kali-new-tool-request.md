# Kali Linux New Tool Request: StratusAI

Submit under **New Tool Requests** at <https://bugs.kali.org/>.

## Summary

stratus-ai - cloud and external security assessment with optional AI synthesis

## Description

[Name] - StratusAI

[Version] - 0.2.0

[Homepage] - https://github.com/anpa1200/stratus-ai

[Download] - https://github.com/anpa1200/stratus-ai/releases/tag/v0.2.0

[Author] - Andrey Pautov

[Licence] - MIT

[Description] - StratusAI performs AWS, GCP, and external exposure security
assessments. The Kali core package supports external scanning and raw JSON
output without an AI API key. Cloud provider SDK and AI integrations are
optional.

[Dependencies] - Python 3, Click, Requests. Recommended: nmap, dnsutils,
python3-boto3, python3-google-auth.

[Similar tools] - ScoutSuite, prowler, cloudfox, nmap

[Activity] - Actively maintained with 125 automated tests and CI.

[How to use] - Offline/core example:
`stratus-ai --mode external --target example.org --no-ai`.

[Packaged] - Debian/Kali package metadata, autopkgtest, and a man page are
included upstream.

After Kali creates the issue, configure
[status notifications](kali-status-notifications.md).
