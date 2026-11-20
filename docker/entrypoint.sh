#!/bin/sh
# Make /data writable, drop to the keyshare user, then run keyshare-mcp serve.
# The server process is not root. Root is only used for the volume chown.
set -eu

if [ "$(id -u)" = 0 ]; then
  mkdir -p /data
  # The write below runs as uid 10001. A root-owned directory on the volume
  # would make that write fail, so hand it over before dropping privileges.
  if [ -n "${HL_AGENT_JSON:-}" ]; then
    mkdir -p /data/hyperliquid
    chown keyshare:keyshare /data/hyperliquid
  fi
  chown keyshare:keyshare /data
  exec setpriv --reuid=keyshare --regid=keyshare --init-groups --inh-caps=-all -- "$0" "$@"
fi

# Railway's custom start command is arguments to this entrypoint. When
# KEYSHARE_TOML is set, the branch below execs serve and never runs those
# arguments, so a start command cannot plant the agent key. Write it here,
# after the drop to uid 10001, and do not print the value.
if [ -n "${HL_AGENT_JSON:-}" ]; then
  mkdir -p /data/hyperliquid
  tmp=/data/hyperliquid/filltape.agent.json.tmp
  rm -f "$tmp"
  ( umask 077; printf '%s\n' "$HL_AGENT_JSON" > "$tmp" )
  chmod 600 "$tmp"
  mv -f "$tmp" /data/hyperliquid/filltape.agent.json
  unset HL_AGENT_JSON
fi

if [ -n "${KEYSHARE_TOML:-}" ]; then
  printf '%s\n' "$KEYSHARE_TOML" > /tmp/keyshare.toml
  exec keyshare-mcp serve /tmp/keyshare.toml
fi

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

exec keyshare-mcp serve /etc/keyshare/keyshare.toml
