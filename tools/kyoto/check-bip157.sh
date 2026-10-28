#!/usr/bin/env bash
# Checks rust-lib/vendor/bip157 is bip157 0.8.1 plus patches/bip157, byte for byte, outside Nix.
# With --update, rewrites the vendored tree from the patches instead.
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
url=https://static.crates.io/crates/bip157/bip157-0.8.1.crate
sha=467c3414d72f1393576c2c86f13ae04dd55da722f1c364bbede5dc9805995421

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -sSfL -A cargo -o "$work/bip157.crate" "$url"
echo "$sha  $work/bip157.crate" | shasum -a 256 -c - >/dev/null
mkdir "$work/pristine"
tar xzf "$work/bip157.crate" -C "$work/pristine" --strip-components=1
bash "$repo/tools/kyoto/patch-bip157.sh" "$work/pristine" "$work/patched" "$repo/patches/bip157"

vendored=$repo/rust-lib/vendor/bip157
if [ "${1:-}" = "--update" ]; then
  rm -rf "$vendored"
  cp -R "$work/patched" "$vendored"
  echo "rewrote $vendored"
else
  diff -r "$work/patched" "$vendored"
  echo "rust-lib/vendor/bip157 matches the patches"
fi
