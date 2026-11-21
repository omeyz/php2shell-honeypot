# Advance notice to the provider (template)

Send this before exposing the honeypot. Fill the bracketed fields.

---

Subject: Advance notice: security research honeypot on [account / project]

Hello,

I am running a deliberately vulnerable research host on my account to collect
threat intelligence on CVE-2026-109618 and CVE-2026-109619, the PHP flaws
patched 2026-10-21. I want to notify you before it is exposed and confirm this
is acceptable under your terms.

Scope:
- Project / account: [id]
- Gateway, public: [ip]
- Honeypot: private address only, no public IP, reachable only on TCP 80
  through the gateway
- Start date: [date]

Containment:
- Outbound traffic is denied by default at the gateway. Only DNS to a single
  pinned resolver and rate-limited web traffic are permitted, both logged.
- Mail ports are blocked outright. No mail can leave the host.
- Outbound connections to private, link-local, carrier-NAT and metadata
  ranges are blocked, so the host cannot reach your network or mine.
- A watchdog trips an automatic kill switch if egress exceeds [n] bytes per
  minute. I can also isolate the host manually with one command.
- The host is reverted to a clean snapshot after each observation window.
- Full packet capture is retained off-host for incident response.

I am the only operator. I will not redistribute malware or illegal content
recovered from the host. I will report illegal content to you and to the
appropriate authority rather than retain it.

I am reachable at [email] and [phone] at any hour if you need it taken down.

Is this acceptable, and is there anything you would like changed?

[name]

---

Keep the reply. If they decline, do not deploy.
