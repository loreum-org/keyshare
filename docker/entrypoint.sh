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

# The signed policy can come from variables too. Written to the volume, where the
# Railway config reads it; a later file on the volume replaces it until the next start.
# A newer version already on the volume (hot-loaded since) is kept: writing the older
# variable back would be refused as a rollback and the server would not start.
policy_version() {
  # Top-level `version = N`, before the first [table].
  awk '/^[[:space:]]*\[/ { exit } /^[[:space:]]*version[[:space:]]*=/ { sub(/^[^=]*=[[:space:]]*/, ""); if (match($0, /^[0-9]+/)) print substr($0, 1, RLENGTH); exit }' "$1" 2>/dev/null
}
if [ -n "${KEYSHARE_POLICY:-}" ] && [ -f /data/policy.toml ]; then
  printf '%s\n' "$KEYSHARE_POLICY" > /data/policy.env.tmp
  on_volume=$(policy_version /data/policy.toml)
  from_env=$(policy_version /data/policy.env.tmp)
  rm -f /data/policy.env.tmp
  if [ -n "$on_volume" ] && [ -n "$from_env" ] && [ "$on_volume" -gt "$from_env" ]; then
    echo "keeping policy version $on_volume on /data; KEYSHARE_POLICY has older version $from_env" >&2
    unset KEYSHARE_POLICY KEYSHARE_POLICY_SIG
  fi
fi
if [ -n "${KEYSHARE_POLICY:-}" ]; then
  printf '%s\n' "$KEYSHARE_POLICY" > /data/policy.toml.tmp
  mv -f /data/policy.toml.tmp /data/policy.toml
  if [ -n "${KEYSHARE_POLICY_SIG:-}" ]; then
    printf '%s\n' "$KEYSHARE_POLICY_SIG" > /data/policy.toml.sig.tmp
    mv -f /data/policy.toml.sig.tmp /data/policy.toml.sig
  fi
fi

if [ -n "${KEYSHARE_TOML:-}" ]; then
  printf '%s\n' "$KEYSHARE_TOML" > /tmp/keyshare.toml
  exec keyshare-mcp serve /tmp/keyshare.toml
fi

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

exec keyshare-mcp serve /etc/keyshare/keyshare.toml
