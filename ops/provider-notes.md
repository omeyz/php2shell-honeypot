# Provider selection

## Requirements

- Two VMs on a private network, only one with a public IP
- Snapshots and fast restore via API
- A published abuse contact with a human behind it
- Hourly billing, so a burned box is cheap to replace

## Recommendation

Hetzner Cloud. Two small instances plus a private network is a few euros a
month, snapshots are API-driven, and the private network gives the honeypot a
private-only NIC.

DigitalOcean and Vultr work the same way if you prefer them. Nothing here is
provider-specific except `ops/snapshot.sh`.

## Before you create anything

Neither Hetzner's terms nor DigitalOcean's acceptable use policy mentions
honeypots. What I could confirm from their published text:

- Hetzner's terms forbid DDoS participation and open relays outright, and
  section 5.4 broadly requires customers to refrain from abusive and illegal
  actions. A separate "system policies" page is referenced that I did not
  read.
- DigitalOcean's acceptable use policy states it is not exhaustive and
  reserves remedial action for uses it does not describe.

That is permitted-unless-told-otherwise territory, which is not good enough
for a box you intend to let strangers root. **Get written confirmation from
the provider's abuse team before exposing the honeypot**, using
`ABUSE-NOTICE.md`. Keep the reply.

The containment in this repo is also the argument you make to them: egress
denied by default, mail blocked outright, bandwidth watchdog, kill switch,
and scheduled reverts.

## Do not

- Put this on a personal workstation, a laptop, or anything on an office LAN.
- Join it to a mesh VPN (Tailscale or similar). If any node advertises
  internal subnets, a honeypot on that network is a door into them.
- Reuse any SSH key, password, or hostname pattern from real infrastructure.
