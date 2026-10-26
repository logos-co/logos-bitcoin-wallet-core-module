#!/usr/bin/env bash
# Replays patches/bip157 onto bip157 0.8.0 as published and holds them to an allowlist.
# Usage: patch-bip157.sh <pristine crate dir> <out dir> [patch dir]
set -euo pipefail

pristine=$(cd "$1" && pwd)
mkdir -p "$2"
out=$(cd "$2" && pwd)
patches=$(cd "${3:-$(dirname "$0")/../../patches/bip157}" && pwd)

# The files our patches may touch, each for a reason; a patch touching any other file fails
# the build until it is added here (README, "Kyoto patches").
allowed=(
  src/chain/chain.rs      # 1: no conflict when the tip moves; 4: a rescan keeps the filter headers
  src/chain/graph.rs      # 4: the filter state a rescan resets
  src/network/peer.rs     # 2: the batch deadline; 5: each dial's outcome, gossip
  src/network/mod.rs      # 2: the batch deadline setting; 5: why a connect failed
  src/builder.rs          # 2: Builder::filter_batch_timeout; 5: Builder::report_peers
  src/network/outbound.rs # 3: the version nonce
  src/messages.rs         # 5: Info::Dial, Info::Addresses, DialOutcome
  src/lib.rs              # 5: the report_peers setting; DialOutcome, AddrV2Message exported
  src/node.rs             # 5: getaddr while reporting peers; handshakes in flight end first
  src/network/peer_map.rs # 5: a failed connect reported; which peers are mid-handshake
  src/network/socks.rs    # 5: the SOCKS5 reply code kept
  src/network/error.rs    # 5: Socks5Error::Reply
)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp -R "$pristine"/. "$work"/
chmod -R u+w "$work"
cd "$work"
git init -q .
git config user.email build@logos.invalid
git config user.name logos-bitcoin-wallet-core-module
git add -A
git commit -q -m "bip157 0.8.0 as published"
base=$(git rev-parse HEAD)
git am -q "$patches"/*.patch

for f in $(git diff --name-only "$base" HEAD); do
  case " ${allowed[*]} " in
    *" $f "*) ;;
    *) echo "ERROR: a bip157 patch touches an unlisted file: $f" >&2
       echo "Add it to allowed in tools/kyoto/patch-bip157.sh, with a reason." >&2
       exit 1 ;;
  esac
done

rm -rf .git
cp -R . "$out"/
echo "bip157: $(ls "$patches"/*.patch | wc -l | tr -d ' ') patches applied within the allowlist"
