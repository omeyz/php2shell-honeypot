#!/usr/bin/env bash
# Snapshot and roll back the honeypot VM. Provider shim.
#
#   snapshot.sh create <label>   take a snapshot
#   snapshot.sh list             list snapshots
#   snapshot.sh revert <id>      roll the honeypot back to a snapshot
#
# Run from your workstation, never from the honeypot itself.
set -euo pipefail
: "${HP_PROVIDER:?set HP_PROVIDER=hetzner|digitalocean|vultr}"
: "${HP_SERVER_ID:?set HP_SERVER_ID to the honeypot VM id}"

case "$HP_PROVIDER" in
  hetzner)
    : "${HCLOUD_TOKEN:?set HCLOUD_TOKEN}"
    B=https://api.hetzner.cloud/v1
    api() {
      curl -fsS -H "Authorization: Bearer $HCLOUD_TOKEN" \
           -H "Content-Type: application/json" "$@"
    }
    case "${1:-}" in
      create)
        api -X POST "$B/servers/$HP_SERVER_ID/actions/create_image" \
            -d "{\"type\":\"snapshot\",\"description\":\"${2:-honeypot-clean}\"}" | jq .
        ;;
      list)
        api "$B/images?type=snapshot" | jq '.images[] | {id, description, created}'
        ;;
      revert)
        id=${2:?snapshot id required}
        echo "This replaces the honeypot disk with snapshot $id." >&2
        printf 'Image the current disk first? Type yes to proceed: ' >&2
        read -r a; [ "$a" = yes ] || exit 1
        api -X POST "$B/servers/$HP_SERVER_ID/actions/rebuild" \
            -d "{\"image\":$id}" | jq .
        ;;
      *) echo "usage: $0 {create <label>|list|revert <id>}" >&2; exit 1;;
    esac
    ;;
  gcp|google)
    echo "Use ops/gcp-deploy.sh, which knows the honeypot's disk and flags:" >&2
    echo "  ops/gcp-deploy.sh snapshot <label>" >&2
    echo "  ops/gcp-deploy.sh revert <snapshot-name>" >&2
    exit 2
    ;;
  digitalocean)
    echo "Use the provider CLI:" >&2
    echo "  doctl compute droplet-action snapshot $HP_SERVER_ID --snapshot-name <label>" >&2
    echo "  doctl compute droplet-action restore  $HP_SERVER_ID --image-id <id>" >&2
    exit 2
    ;;
  vultr)
    echo "Use the provider CLI:" >&2
    echo "  vultr-cli snapshot create --instance $HP_SERVER_ID --description <label>" >&2
    echo "  vultr-cli instance restore $HP_SERVER_ID --snapshot <id>" >&2
    exit 2
    ;;
  *) echo "unknown HP_PROVIDER: $HP_PROVIDER" >&2; exit 1;;
esac
