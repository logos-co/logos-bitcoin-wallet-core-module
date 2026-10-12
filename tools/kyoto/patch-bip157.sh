#!/usr/bin/env bash
# Replays patches/bip157 onto bip157 0.7.0 as published and holds them to an allowlist.
# Usage: patch-bip157.sh <pristine crate dir> <out dir> [patch dir]
set -euo pipefail

pristine=$(cd "$1" && pwd)
mkdir -p "$2"
out=$(cd "$2" && pwd)
patches=$(cd "${3:-$(dirname "$0")/../../patches/bip157}" && pwd)

# The files our patches may touch, each for a reason; a patch touching any other file fails
# the build until it is added here (README, "Kyoto patches").
allowed=(
  src/chain/chain.rs      # 1, 2: the filter-header vote; 5: a rescan keeps the filter headers
  src/chain/graph.rs      # 5: the filter state a rescan resets
  src/chain/mod.rs        # 1: one vote per peer
  src/network/peer.rs     # 1, 3: unsolicited cfheaders, the batch deadline; 6: each dial's outcome, gossip
  src/network/mod.rs      # 3: the batch deadline setting; 6: why a connect failed
  src/builder.rs          # 3: Builder::filter_batch_timeout; 6: Builder::report_peers
  src/network/outbound.rs # 4: the version nonce
  src/messages.rs         # 6: Info::Dial, Info::Addresses, DialOutcome
  src/lib.rs              # 6: the report_peers setting; DialOutcome, AddrV2Message exported
  src/node.rs             # 6: getaddr while reporting peers; handshakes in flight end first
  src/network/peer_map.rs # 6: a failed connect reported; which peers are mid-handshake
  src/network/socks.rs    # 6: the SOCKS5 reply code kept
  src/network/error.rs    # 6: Socks5Error::Reply
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
git commit -q -m "bip157 0.7.0 as published"
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
