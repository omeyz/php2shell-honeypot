#!/usr/bin/env bash
# Build the PHP2Shell honeypot on Google Cloud.
#
#   gcp-deploy.sh network     VPC, subnet, routes, firewall rules
#   gcp-deploy.sh gateway     the public-facing gateway VM
#   gcp-deploy.sh honeypot    the private-only target VM
#   gcp-deploy.sh expose      open TCP 80 to the world: this is going live
#   gcp-deploy.sh unexpose    close it again
#   gcp-deploy.sh status      show what exists
#   gcp-deploy.sh snapshot <label>
#   gcp-deploy.sh revert <snapshot>
#   gcp-deploy.sh teardown    delete everything in the project
#
# Read ops/gcp-notes.md first. The honeypot is created with no service
# account on purpose: a rooted VM can mint an OAuth token from the metadata
# server, and VPC firewall rules cannot block metadata traffic.
set -euo pipefail

PROJECT=${HP_PROJECT:?set HP_PROJECT to a DEDICATED project, not a client one}
REGION=${HP_REGION:-us-west1}
ZONE=${HP_ZONE:-us-west1-a}
SUBNET_CIDR=${HP_SUBNET_CIDR:-10.99.0.0/24}
GW_IP=${HP_GW_IP:-10.99.0.2}   # .1 is reserved by GCP as the subnet gateway
HONEY_IP=${HP_HONEY_IP:-10.99.0.10}
RESOLVER=${HP_RESOLVER:-1.1.1.1}
SSH_PORT=${HP_SSH_PORT:-22}   # moving this also means reconfiguring sshd;
                              # the real control is ADMIN_CIDR, not the port
ADMIN_CIDR=${HP_ADMIN_CIDR:?set HP_ADMIN_CIDR to your own address, e.g. 203.0.113.4/32}
MACHINE=${HP_MACHINE:-e2-small}
IMAGE_FAMILY=${HP_IMAGE_FAMILY:-debian-12}
IMAGE_PROJECT=${HP_IMAGE_PROJECT:-debian-cloud}

NET=hp-vpc
SUBNET=hp-subnet
GW=hp-gw
TARGET=hp-target

case "$ADMIN_CIDR" in
  */0) echo "refusing: HP_ADMIN_CIDR must not be a default route" >&2; exit 1;;
esac

g() { gcloud --project="$PROJECT" "$@"; }

cmd_network() {
  echo "== VPC and subnet =="
  g compute networks create "$NET" --subnet-mode=custom
  g compute networks subnets create "$SUBNET" \
      --network="$NET" --region="$REGION" --range="$SUBNET_CIDR" \
      --enable-flow-logs

  # Public web ingress is NOT created here. It is the one change that invites
  # attackers, so it lives in the `expose` subcommand on its own.
  echo "== ingress: admin SSH to the gateway, from you only =="
  g compute firewall-rules create hp-allow-admin-ssh \
      --network="$NET" --direction=INGRESS --action=ALLOW \
      --rules="tcp:$SSH_PORT" --source-ranges="$ADMIN_CIDR" --target-tags="$GW" \
      --priority=900

  echo "== ingress: honeypot may reach the gateway (routing + syslog) =="
  g compute firewall-rules create hp-allow-target-to-gw \
      --network="$NET" --direction=INGRESS --action=ALLOW \
      --rules=all --source-ranges="$SUBNET_CIDR" --target-tags="$GW" \
      --priority=1000

  echo "== ingress: admin SSH to the honeypot, from the gateway only =="
  g compute firewall-rules create hp-allow-gw-to-target \
      --network="$NET" --direction=INGRESS --action=ALLOW \
      --rules=tcp:22 --source-ranges="$SUBNET_CIDR" \
      --target-tags="$TARGET" --priority=1000

  # The gateway DNATs the destination but NOT the source, so the honeypot
  # sees the attacker's real IP. That is deliberate: its own Apache logs are
  # then directly correlatable with the gateway pcap. The cost is that this
  # rule cannot be scoped to the subnet, because the source is the whole
  # internet. It is not an exposure: the honeypot has no external address,
  # so the only path to port 80 is through the gateway.
  echo "== ingress: web to the honeypot, source preserved =="
  g compute firewall-rules create hp-allow-web-to-target \
      --network="$NET" --direction=INGRESS --action=ALLOW \
      --rules=tcp:80 --source-ranges=0.0.0.0/0 \
      --target-tags="$TARGET" --priority=1000

  # Egress. Lower priority number wins in GCP, so the allows must sit above
  # the catch-all deny. This is the layer root on the honeypot cannot flush.
  echo "== egress: honeypot to the subnet =="
  g compute firewall-rules create hp-allow-target-eg-subnet \
      --network="$NET" --direction=EGRESS --action=ALLOW \
      --rules=all --destination-ranges="$SUBNET_CIDR" \
      --target-tags="$TARGET" --priority=800

  echo "== egress: honeypot DNS to the pinned resolver only =="
  g compute firewall-rules create hp-allow-target-eg-dns \
      --network="$NET" --direction=EGRESS --action=ALLOW \
      --rules=udp:53,tcp:53 --destination-ranges="$RESOLVER/32" \
      --target-tags="$TARGET" --priority=900

  echo "== egress: honeypot web, so a second stage can be observed =="
  g compute firewall-rules create hp-allow-target-eg-web \
      --network="$NET" --direction=EGRESS --action=ALLOW \
      --rules=tcp:80,tcp:443 --destination-ranges=0.0.0.0/0 \
      --target-tags="$TARGET" --priority=1000 --enable-logging

  echo "== egress: deny everything else from the honeypot, logged =="
  g compute firewall-rules create hp-deny-target-eg-all \
      --network="$NET" --direction=EGRESS --action=DENY \
      --rules=all --destination-ranges=0.0.0.0/0 \
      --target-tags="$TARGET" --priority=65000 --enable-logging

  cat <<'NOTE'

Note: mail, SSH-out and odd-port pivots are dropped at the VPC layer and
never reach the gateway, so those attempts appear in Cloud Logging rather
than the gateway's kernel log. Query them with:

  gcloud logging read 'jsonPayload.rule_details.reference:"hp-deny-target-eg-all"' \
    --limit=50 --format=json

NOTE
}

cmd_gateway() {
  echo "== gateway VM =="
  # --can-ip-forward is mandatory: without it GCP drops forwarded packets
  # no matter what nftables says.
  g compute instances create "$GW" \
      --zone="$ZONE" --machine-type="$MACHINE" \
      --subnet="$SUBNET" --private-network-ip="$GW_IP" \
      --can-ip-forward --tags="$GW" \
      --image-family="$IMAGE_FAMILY" --image-project="$IMAGE_PROJECT" \
      --no-service-account --no-scopes \
      --metadata=block-project-ssh-keys=TRUE

  echo "== default route for the honeypot, via the gateway =="
  # Priority 100 beats the VPC's own default route (1000), and --tags scopes
  # it to the honeypot so the gateway keeps its normal egress.
  g compute routes create hp-target-default-via-gw \
      --network="$NET" --destination-range=0.0.0.0/0 \
      --next-hop-instance="$GW" --next-hop-instance-zone="$ZONE" \
      --tags="$TARGET" --priority=100

  cat <<EOF

Gateway created. Next:
  1. SSH in and install the gateway stack:
       gcloud --project=$PROJECT compute ssh $GW --zone=$ZONE
       # copy this repo over, then as root:
       #   cp gateway/honeypot.env.example gateway/honeypot.env
       #   edit it: PUB_IF and PRIV_IF are both ens4 on GCP (single NIC),
       #            HONEY_IP=$HONEY_IP, ADMIN_CIDR=$ADMIN_CIDR,
       #            SSH_PORT=$SSH_PORT, RESOLVER=$RESOLVER
       #   gateway/install-gateway.sh
  2. Only then create the honeypot: it has no internet path until the
     gateway is masquerading.
EOF
}

cmd_honeypot() {
  echo "== honeypot VM: no external IP, NO service account =="
  # --no-service-account --no-scopes is the control that matters. A rooted VM
  # with an attached service account can mint an OAuth token from the
  # metadata server, and that token cannot be firewalled off.
  g compute instances create "$TARGET" \
      --zone="$ZONE" --machine-type="$MACHINE" \
      --subnet="$SUBNET" --private-network-ip="$HONEY_IP" \
      --no-address --tags="$TARGET" \
      --image-family="$IMAGE_FAMILY" --image-project="$IMAGE_PROJECT" \
      --no-service-account --no-scopes \
      --metadata=block-project-ssh-keys=TRUE,enable-oslogin=FALSE

  cat <<EOF

Honeypot created with no external address. It reaches the internet only
through $GW.

  1. Pin DNS, since the metadata resolver is going away:
       printf 'nameserver $RESOLVER\n' > /etc/resolv.conf
  2. Build the bait (via the gateway as a jump host):
       GATEWAY_PRIV_IP=$GW_IP honeypot/setup-honeypot.sh
  3. CONFIRM you can still SSH in through the gateway.
  4. Then, and only then, cut it off from the metadata server:
       honeypot/lock-metadata.sh
     This breaks the Google guest agent and SSH key syncing, which is why it
     is last and why step 3 is not optional.
  5. Snapshot the clean state:
       ops/gcp-deploy.sh snapshot clean-build
EOF
}

cmd_expose() {
  echo "This opens TCP 80 on the gateway to the entire internet, which is"
  echo "what makes the honeypot live bait. Before you do it:"
  echo "  - the clean snapshot exists"
  echo "  - honeypot/lock-metadata.sh has run and metadata is unreachable"
  echo "  - the provider notice has been sent"
  echo "  - gateway/provision-mode.sh status reports OFF"
  printf 'Type expose to proceed: '
  read -r a; [ "$a" = expose ] || exit 1
  g compute firewall-rules create hp-allow-web-in \
      --network="$NET" --direction=INGRESS --action=ALLOW \
      --rules=tcp:80 --source-ranges=0.0.0.0/0 --target-tags="$GW" \
      --priority=1000 --enable-logging
  ip=$(g compute instances describe "$GW" --zone="$ZONE" \
       --format='value(networkInterfaces[0].accessConfigs[0].natIP)')
  echo "live at http://$ip/"
}

cmd_unexpose() {
  g compute firewall-rules delete hp-allow-web-in --quiet
  echo "public web ingress removed; the honeypot is no longer reachable"
}

cmd_status() {
  echo "== instances =="
  g compute instances list --filter="name~'^hp-'" \
     --format='table(name,status,networkInterfaces[0].networkIP,networkInterfaces[0].accessConfigs[0].natIP,serviceAccounts[0].email)'
  echo "== firewall =="
  g compute firewall-rules list --filter="network~'$NET'" \
     --format='table(name,direction,priority,allowed[].map().firewall_rule().list(),denied[].map().firewall_rule().list(),logConfig.enable)'
  echo "== routes =="
  g compute routes list --filter="network~'$NET'" \
     --format='table(name,destRange,priority,nextHopInstance,tags.list())'
}

cmd_snapshot() {
  label=${1:?usage: snapshot <label>}
  g compute disks snapshot "$TARGET" --zone="$ZONE" \
      --snapshot-names="hp-${label}-$(date +%Y%m%d-%H%M%S)"
  g compute snapshots list --format='table(name,diskSizeGb,creationTimestamp)'
}

cmd_revert() {
  snap=${1:?usage: revert <snapshot-name>}
  echo "This deletes $TARGET and rebuilds it from $snap."
  echo "Image the current disk first if you still need the evidence."
  printf 'Type yes to proceed: '
  read -r a; [ "$a" = yes ] || exit 1
  g compute instances delete "$TARGET" --zone="$ZONE" --quiet
  g compute disks create "$TARGET" --zone="$ZONE" --source-snapshot="$snap"
  g compute instances create "$TARGET" \
      --zone="$ZONE" --machine-type="$MACHINE" \
      --subnet="$SUBNET" --private-network-ip="$HONEY_IP" \
      --no-address --tags="$TARGET" --disk="name=$TARGET,boot=yes,auto-delete=no" \
      --no-service-account --no-scopes \
      --metadata=block-project-ssh-keys=TRUE,enable-oslogin=FALSE
  echo "reverted. Re-arm the gateway if the kill switch is tripped: honeypot-rearm"
}

cmd_teardown() {
  echo "This deletes every hp-* resource in project $PROJECT."
  printf 'Type the project name to confirm: '
  read -r a
  [ "$a" = "$PROJECT" ] || { echo "mismatch, aborting" >&2; exit 1; }
  g compute instances delete "$TARGET" "$GW" --zone="$ZONE" --quiet || true
  g compute routes delete hp-target-default-via-gw --quiet || true
  for r in hp-allow-web-in hp-allow-admin-ssh hp-allow-target-to-gw \
           hp-allow-gw-to-target hp-allow-web-to-target \
           hp-allow-target-eg-subnet \
           hp-allow-target-eg-dns hp-allow-target-eg-web \
           hp-deny-target-eg-all; do
    g compute firewall-rules delete "$r" --quiet || true
  done
  g compute networks subnets delete "$SUBNET" --region="$REGION" --quiet || true
  g compute networks delete "$NET" --quiet || true
  echo "torn down. Snapshots are kept; list them with: gcloud compute snapshots list"
}

case "${1:-}" in
  network)  cmd_network;;
  gateway)  cmd_gateway;;
  honeypot) cmd_honeypot;;
  expose)   cmd_expose;;
  unexpose) cmd_unexpose;;
  status)   cmd_status;;
  snapshot) shift; cmd_snapshot "$@";;
  revert)   shift; cmd_revert "$@";;
  teardown) cmd_teardown;;
  *) sed -n '2,12p' "$0"; exit 1;;
esac
