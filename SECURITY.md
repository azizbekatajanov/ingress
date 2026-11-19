# Security policy

## Reporting a vulnerability

Please **don't open a public issue** for a security problem.

Report it privately through GitHub: **Security → Report a vulnerability** on
[github.com/azizbekatajanov/ingress](https://github.com/azizbekatajanov/ingress/security/advisories/new).
Only the maintainer can see the report.

Please include:

- the Ingress version (About screen) and OS/architecture;
- what an attacker needs (local user? network position? a malicious gateway?) and what they get;
- steps or a proof of concept, if you have one.

What to expect:

- an acknowledgement within **5 working days**;
- an assessment and a plan (fix, mitigation, or why it isn't a vulnerability) within **14 days**;
- a fixed release, a GitHub Security Advisory and, for serious issues, a CVE. You're credited in the advisory unless you ask not to be.

Please give us a reasonable time to ship a fix before you disclose publicly. 90 days is the default, or sooner once a fixed release is out.

## Supported versions

Only the **latest release** gets security fixes. Ingress updates itself on macOS. On Linux, install the new `.deb`/`.tar.gz`.

## Scope

In scope:

- the Ingress app (this repository);
- the VPN client builds Ingress downloads from [ingress-deps](https://github.com/azizbekatajanov/ingress-deps), and the patches applied there;
- the release, update and install pipeline (`install.sh`, update manifest signing, component manifest).

Bugs in upstream openconnect, openfortivpn or sstp-client that our patches don't touch belong upstream. We still want to hear about them so we can ship a fixed build.

## How Ingress handles security

What runs as root, which hosts Ingress talks to, where secrets are stored and how to verify a download: see [docs/security.md](docs/security.md) (Russian: [docs/security.ru.md](docs/security.ru.md)).
