# Lessons from running it

Notes from a real deployment of this honeypot on Google Cloud (two small VMs: a gateway and
an isolated target). Details of any particular running instance are deliberately not kept here.

## Not verified

That the flaw is actually exploitable. Confirming it would mean running an
exploit, which this repo does not contain. What is established is that the
package predates the fix, mod_php with long-lived prefork workers is the
active SAPI, and `session.upload_progress` is enabled.

## The open judgement call

Honeypot egress is capped at 6 new connections a minute. That truncates some
malware chains: a dropper that fetches ten payloads will fail partway, and
you will see the attempt but not the full tooling. Widening it buys richer
intel and raises the odds the box becomes someone else's attack platform.
`EGRESS_BYTES_PER_MIN` in `/etc/honeypot.env` and the `limit rate` in the
gateway ruleset are the two dials.

## Things learned the hard way, now encoded

- GCP reserves `x.x.x.1` as the subnet gateway, so the gateway VM sits on .2.
- Cloud VMs have a single NIC, so firewall rules that discriminate by
  interface cannot tell inbound bait from honeypot egress. Everything keys on
  addresses instead, and the DNAT keys on the gateway's own address or it
  would also redirect the honeypot's outbound HTTP back at itself.
- The gateway DNATs the destination only, so the honeypot sees the attacker's
  real source IP. That needs a VPC ingress rule on the honeypot whose source
  is `0.0.0.0/0`, which is not an exposure because the honeypot has no
  external address.
- The steady-state egress throttle is too tight for `apt`, hence
  `provision-mode.sh`. It must be off before exposure.
- WordPress makes outbound calls on page load. Throttled, that made the
  landing page take 26 seconds. `WP_HTTP_BLOCK_EXTERNAL` fixes it and means
  any egress observed afterwards is the attacker's, not the CMS's.
- The kill switch lives in the forward chain, so probing the honeypot from
  the gateway still succeeds while it is engaged. That is correct, and it is
  why the verifier drives traffic from the honeypot instead.
- **Pinning admin SSH to one residential IP is a self-inflicted lockout.**
  The guest ruleset bakes in `ADMIN_CIDR`, so when the IP drifted there was
  no way back in -- the VPC rule was not the thing blocking it. Recovered
  with a metadata startup script plus a hard reset, then widened to Google's
  IAP range, which is stable and still requires IAM auth to traverse.
- **`/etc/honeypot.env` is SOURCED, so a multi-value `ADMIN_CIDR` must be
  quoted.** Unquoted braces became a shell brace-group and every script that
  sources the file died, including the watchdog holding the disk guard and
  the egress kill switch. It failed silently for a minute before being
  caught.
- **`/etc/resolv.conf` is a symlink into `/run`.** Writing through it landed
  on tmpfs, `chattr +i` is unsupported there, `|| true` swallowed the error,
  and systemd-resolved later restored the metadata resolver -- which we
  block. DNS died hours after a build-time check had passed, taking all
  egress with it. Now a static file on disk, with the immutable flag
  verified rather than assumed.
- **imfile latches a log by inode.** `access.log` was recreated during the
  build, so the monitor read a dead inode and live requests stopped shipping
  off-box with no error anywhere. Fixed with `reopenOnTruncate` and a
  `copytruncate` rotation override. A build-time "logs are shipping" check
  would not have caught this; only an end-to-end marker after the fact did.
- **Rate-limit the log, never the verdict.** The metadata block logged every
  packet, and the guest agent's constant polling produced enough volume to
  push real Apache lines out of the UDP queue. The fix puts `limit rate` on a
  verdict-free log rule that falls through to an unconditional reject --
  putting it on the reject rule itself would have let packets over the limit
  stop matching and made metadata reachable again.
- A drill that reports `000` for both a blocked request and a dead SSH will
  read as a containment failure when it is really a lost box. The verifier
  now settles that first and exits 2 as inconclusive.

## Cost

Two `e2-small` instances plus a 10 GB disk each, roughly \$25 to \$30 a month
if left running, plus egress and three snapshots. Delete with
`ops/gcp-deploy.sh teardown`; snapshots survive teardown.
