#!/bin/sh
set -eu

: "${OPERATOR_PUBKEY:?OPERATOR_PUBKEY must be set}"

install -d -m 700 /data/hostkeys
install -d -m 750 -o ctl -g keyreader /data/state
key=/data/hostkeys/ssh_host_ed25519_key
[ -f "$key" ] || ssh-keygen -q -t ed25519 -N '' -f "$key"
echo "relay host key: $(cat "$key.pub")"

printf '%s\n' "$OPERATOR_PUBKEY" > /etc/ssh/operator_keys
chmod 644 /etc/ssh/operator_keys

crond -b
exec /usr/sbin/sshd -D -e
