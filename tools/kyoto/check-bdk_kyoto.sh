#!/usr/bin/env bash
# Checks rust-lib/vendor/bdk_kyoto is bdk_kyoto 0.18.0 plus patches/bdk_kyoto, byte for byte,
# outside Nix. With --update, rewrites the vendored tree from the patches instead.
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
url=https://static.crates.io/crates/bdk_kyoto/bdk_kyoto-0.18.0.crate
sha=cb06429fe9ed238f12bff092ae5cbb34ae51e647486d148fa51744d6e4b289d5

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -sSfL -A cargo -o "$work/bdk_kyoto.crate" "$url"
echo "$sha  $work/bdk_kyoto.crate" | shasum -a 256 -c - >/dev/null
mkdir "$work/pristine"
tar xzf "$work/bdk_kyoto.crate" -C "$work/pristine" --strip-components=1
bash "$repo/tools/kyoto/patch-bdk_kyoto.sh" "$work/pristine" "$work/patched" "$repo/patches/bdk_kyoto"

vendored=$repo/rust-lib/vendor/bdk_kyoto
if [ "${1:-}" = "--update" ]; then
  rm -rf "$vendored"
  cp -R "$work/patched" "$vendored"
  echo "rewrote $vendored"
else
  diff -r "$work/patched" "$vendored"
  echo "rust-lib/vendor/bdk_kyoto matches the patches"
fi
