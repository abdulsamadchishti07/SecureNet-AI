#!/usr/bin/env sh
# Always enter a fresh network namespace before the harness can create firewall rules.
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"
if [ "${1:-}" = "--help" ]; then
    exec .venv/bin/python scripts/netns_multi_attack_lab.py --help
fi
for tool in nft ip ping nsenter unshare readlink; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Missing utility: $tool" >&2; exit 1; }
done
PARENT_NETNS="$(readlink /proc/self/ns/net)"
if [ "$(id -u)" -eq 0 ]; then
    exec unshare --net .venv/bin/python scripts/netns_multi_attack_lab.py --parent-netns "$PARENT_NETNS" "$@"
fi
exec unshare --user --map-root-user --net .venv/bin/python scripts/netns_multi_attack_lab.py --parent-netns "$PARENT_NETNS" "$@"
