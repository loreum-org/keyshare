#!/bin/sh
# Make /data writable, drop to the keyshare user, then run keyshare-mcp serve.
# The server process is not root. Root is only used for the volume chown.
set -eu

if [ "$(id -u)" = 0 ]; then
  mkdir -p /data
  chown keyshare:keyshare /data
  exec setpriv --reuid=keyshare --regid=keyshare --init-groups --inh-caps=-all -- "$0" "$@"
fi

if [ -n "${KEYSHARE_TOML:-}" ]; then
  printf '%s\n' "$KEYSHARE_TOML" > /tmp/keyshare.toml
  exec keyshare-mcp serve /tmp/keyshare.toml
fi

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

exec keyshare-mcp serve /etc/keyshare/keyshare.toml
