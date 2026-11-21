# PHP2Shell high-interaction honeypot

Threat-intel honeypot for CVE-2026-109618 / CVE-2026-109619, patched
2026-10-21. The goal is to observe the full post-exploitation chain against a
genuinely vulnerable PHP box while making it useless as a weapon against
anyone else.

**This repository contains no exploit.** It builds a target and the
containment around it, plus detection and analysis for traffic that arrives.

## Current state

The design was built and verified end to end on Google Cloud. See
`ops/LESSONS.md` for what running it taught, including the failures that are
now encoded in the scripts. `ops/gcp-deploy.sh expose` and `unexpose` take a
deployment live or close it again.

## Shape

```
internet ──▶ GATEWAY (public IP)            ──▶ HONEYPOT (private only)
             • nftables: deny by default        • Debian 12
             • DNAT :80 to the honeypot         • Apache mod_php + prefork
             • full pcap of honeypot traffic    • PHP 8.4 BELOW 8.4.27
             • rsyslog collector                • stock WordPress
             • egress watchdog + kill switch    • auditd execve logging
                                                • no public IP, no keys
```

The honeypot has no public address. Everything it sends or receives crosses
the gateway, which is the only place that decides what is allowed out.

## Why these choices

- **Two VMs, not containers.** An attacker who gets root should be inside a
  kernel we are willing to discard, not sharing ours.
- **Port 80, no TLS.** Exploit traffic stays plaintext in the capture. TLS
  would hide the thing we are trying to collect.
- **mod_php with prefork and `MaxConnectionsPerChild 0`.** Long-lived workers
  that serve many requests are the configuration PHP named as highest risk,
  and the condition the published chain needs. Capturing it is the point.
- **Capture on the gateway.** Root on the honeypot can rewrite its own logs.
  The pcap is off-box, so losing the host does not lose the evidence.
- **Egress denied by default, blocked attempts logged.** A refused pivot is
  still intel. An allowed one is someone else's incident.

## Build order

1. **Provider.** Two VMs on a private network, snapshots, and a published
   abuse contact. Read `ops/provider-notes.md` before creating anything.
   On Google Cloud read `ops/gcp-notes.md` first and deploy with
   `ops/gcp-deploy.sh`, which handles the metadata-credential problem that
   is specific to GCP.
2. **Gateway.** Copy `gateway/honeypot.env.example` to
   `gateway/honeypot.env`, fill it in, then as root:
   ```
   gateway/install-gateway.sh
   nft list ruleset | head -40
   ```
   `ADMIN_CIDR` must be your own address. The renderer refuses a default route.
3. **Honeypot.** On the private-only VM, as root:
   ```
   GATEWAY_PRIV_IP=10.99.0.2 honeypot/setup-honeypot.sh
   ```
   It refuses to run if the host has a non-private global address.
4. **On GCP only:** confirm SSH through the gateway still works, then run
   `honeypot/lock-metadata.sh` on the honeypot. A rooted VM can otherwise
   mint a cloud credential from the metadata server.
5. **Snapshot the clean state** before exposing anything: `ops/snapshot.sh`,
   or `ops/gcp-deploy.sh snapshot clean-build`.
6. **Notify the provider** using `ops/ABUSE-NOTICE.md`.
7. **Open the door.** This is the only step that invites attackers, so it is
   deliberately kept separate from everything above.

## Running it

- Watch for arrivals: `tail -F /var/lib/honeypot/remote/*.log`
- Blocked egress, the interesting signal:
  `journalctl -k | grep EGRESS-.*BLOCK`
- Score captured requests:
  ```
  tshark -r hp-xxx.pcap -Y http.request -T json > reqs.json
  analysis/extract_php2shell.py --tshark reqs.json > findings.jsonl
  ```
- Kill it now: `honeypot-killswitch "reason"`. Re-arm with `honeypot-rearm`
  only after you have imaged and reverted.
- Prove the kill switch works: `honeypot-killswitch-verify`. Do not test it
  by curling the honeypot from the gateway, because that path goes through
  the output hook and is meant to keep working.

## Observation cycle

Let a compromise run a few hours, then image the disk, then revert to the
clean snapshot. A box left owned indefinitely becomes someone's
infrastructure, and the longer it runs the more the intel is about the
squatter than the vulnerability.

## Tests

```
bash tests/test-parser.sh
docker build -t hp-nftcheck tests/
docker run --rm --net=none --cap-add=NET_ADMIN -v "$PWD":/w -w /w \
  hp-nftcheck bash /w/tests/test-gateway.sh
```

The gateway suite loads the real ruleset inside a throwaway network
namespace, so it verifies the firewall rather than just parsing it.

## Limits

- The egress allowance is deliberately narrow, so some malware will fail to
  stage and you will see a truncated chain. That is the trade for not hosting
  an attack platform.
- The parser's scores are heuristics. Legitimate `session.upload_progress`
  traffic scores as "suspicious" by design. Treat it as a baseline, not a hit.
- Public reporting on the root cause is still inconsistent. Describe what you
  captured, and attribute mechanism claims to the source you took them from.

## Setup

Nothing here holds a secret. Fill these in for your own deployment:

| Where | Value |
|---|---|
| `gateway/honeypot.env` (copy of `honeypot.env.example`) | `ADMIN_CIDR` (your own IP, never `0.0.0.0/0`), interfaces, private IPs, resolver, watchdog limits |
| `ops/gcp-deploy.sh` environment | `HP_PROJECT` (a dedicated project), `HP_ADMIN_CIDR`; optional `HP_REGION`, `HP_ZONE`, `HP_SUBNET_CIDR`, `HP_GW_IP`, `HP_HONEY_IP` |
| `honeypot/setup-honeypot.sh` environment | `GATEWAY_PRIV_IP`; optional `HP_SITE_TITLE` (bait WordPress title), `HP_SNAPSHOT`, `HP_PHP_VERSION`, `HP_PHP_PKG_VER` |
| `ops/ABUSE-NOTICE.md` | the bracketed fields before you send it |

`203.0.113.0/24` addresses in examples and tests are the RFC 5737
documentation range.

## License

MIT. See [LICENSE](LICENSE).
