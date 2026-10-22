#!/usr/bin/env bash
# Replays patches/bdk_kyoto onto bdk_kyoto 0.18.1 as published and holds them to an allowlist.
# Usage: patch-bdk_kyoto.sh <pristine crate dir> <out dir> [patch dir]
set -euo pipefail

pristine=$(cd "$1" && pwd)
mkdir -p "$2"
out=$(cd "$2" && pwd)
patches=$(cd "${3:-$(dirname "$0")/../../patches/bdk_kyoto}" && pwd)

# The files our patches may touch, each for a reason; a patch touching any other file fails
# the build until it is added here (README, "Kyoto patches").
allowed=(
  src/lib.rs      # 1: matched blocks oldest first; 2: updates before the tip, and the height scanned;
                  # 3: widening in place; 4: a matched block reorganized away is skipped
  src/builder.rs  # 3: a node built from a given chain state
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
git commit -q -m "bdk_kyoto 0.18.1 as published"
base=$(git rev-parse HEAD)
git am -q "$patches"/*.patch

for f in $(git diff --name-only "$base" HEAD); do
  case " ${allowed[*]} " in
    *" $f "*) ;;
    *) echo "ERROR: a bdk_kyoto patch touches an unlisted file: $f" >&2
       echo "Add it to allowed in tools/kyoto/patch-bdk_kyoto.sh, with a reason." >&2
       exit 1 ;;
  esac
done

rm -rf .git
cp -R . "$out"/
echo "bdk_kyoto: $(ls "$patches"/*.patch | wc -l | tr -d ' ') patches applied within the allowlist"
