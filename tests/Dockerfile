# Throwaway image for the gateway self-test. Loading nftables rules needs a
# kernel and CAP_NET_ADMIN, so the suite runs here with --net=none against an
# isolated network namespace and touches nothing on the host.
FROM debian:12-slim
RUN apt-get update -qq \
 && apt-get install -y -qq nftables shellcheck jq python3 iproute2
