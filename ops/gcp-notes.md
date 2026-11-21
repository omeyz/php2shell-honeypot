# Google Cloud: what changes

GCP is a good fit for this, with one serious caveat and one real advantage.

## The caveat: the metadata server hands out credentials

A rooted VM can ask the metadata server at `169.254.169.254` for an OAuth
access token belonging to the service account attached to that instance. The
token then works against your project from anywhere. Netskope and others have
documented this as a standard pivot: command execution on the instance,
token from metadata, then the Cloud CLI against the project.

Two facts make this worse than it sounds:

- Deleting a service account's keys does not revoke an already-issued token.
  It stays valid until it expires, up to an hour. Only deleting the service
  account itself revokes it.
- **VPC firewall rules cannot block metadata traffic.** Communication between
  an instance and its own metadata server is on Google's always-allowed list,
  so an egress deny rule for `169.254.169.254` does nothing. (This comes from
  vendor documentation rather than Google's own firewall docs. Verify it at
  cloud.google.com/firewall/docs before you rely on either direction.)

So the control cannot be a firewall rule. It has to be that there is no
credential to steal:

1. Create the honeypot with `--no-service-account --no-scopes`. No attached
   identity, no token to mint. This is the control that matters.
2. Block TCP to `169.254.169.254` inside the guest as defence in depth
   (`honeypot/lock-metadata.sh`). Do this **after** you have confirmed SSH
   access through the gateway, because it breaks the Google guest agent and
   SSH key syncing.
3. Run the honeypot in a **dedicated project**, with its own billing, not
   under a Workspace organization that holds anything real.

## The advantage: a wall root cannot touch

VPC firewall rules are enforced outside the guest, so an attacker with root
on the honeypot cannot flush them the way they can flush nftables. On a plain
VPS the in-guest firewall is the only egress control and it dies with the
host. Here the deny-all egress rule survives the compromise.

That makes the containment two-layered:

| Layer | Enforced by | Survives root on honeypot |
|---|---|---|
| VPC egress rules | Google, outside the guest | yes |
| Gateway nftables | the gateway VM | yes |
| Honeypot nftables | the honeypot itself | no |

The gateway still does the rate limiting and the logging, because VPC rules
cannot throttle. The VPC layer is the hard boundary; the gateway is the
instrument.

## Which account to use

Do not build this under a client or company Workspace identity. A suspension
or an abuse finding lands on the organization, not just the project. Use a
personal account with a fresh project and its own billing account:

```
gcloud auth login
gcloud projects create php2shell-hp-<suffix>
gcloud billing projects link php2shell-hp-<suffix> --billing-account=<id>
```

## Other GCP specifics

- **No Cloud NAT.** The honeypot reaches the internet through the gateway
  instance via a custom route, not through NAT. Creating a Cloud NAT would
  give it a second egress path that bypasses the gateway entirely.
- **`--can-ip-forward` on the gateway.** Without it GCP drops forwarded
  packets regardless of what nftables says.
- **DNS must be pinned.** GCP's resolver is the metadata server. Once that is
  blocked in-guest, set `/etc/resolv.conf` to the pinned resolver, which the
  deploy script does.
- **Egress is billed.** Cap it with a budget alert. The bandwidth watchdog
  limits the damage but is not a billing control.
- **Firewall rule logging is the tamper-proof record.** Blocked egress to odd
  ports is dropped at the VPC layer and never reaches the gateway, so those
  attempts appear only in Cloud Logging, not in the gateway's kernel log.
  Both deny rules are created with logging on.

## Policy

Google does not require notice for penetration testing of your own projects.
Its security FAQ says "you are not required to contact us", subject to the
Acceptable Use Policy and to ensuring your tests only affect your projects.
Nothing in the policy addresses honeypots specifically, and I could not
retrieve the current AUP text, only an archived 2025 version.

A honeypot is not a penetration test, so that FAQ is adjacent rather than
on point. The exposure here is that your host will be used to attack
others if containment fails, which is what the AUP's unauthorized-access and
disruption clauses cover. Read the current AUP at cloud.google.com/terms/aup
yourself, and keep the containment design on hand in case abuse asks.
