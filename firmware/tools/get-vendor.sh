#!/bin/sh
# Clone the pinned upstream sources listed in firmware/vendor.lock into firmware/vendor/ (shallow, exact commit).
set -eu
cd "$(dirname "$0")/.."
mkdir -p vendor
grep -v '^#' vendor.lock | while read -r name url sha; do
  [ -n "$name" ] || continue
  if [ -d "vendor/$name/.git" ] && [ "$(git -C "vendor/$name" rev-parse HEAD)" = "$sha" ]; then
    echo "$name: ok"; continue
  fi
  rm -rf "vendor/$name"
  git init -q "vendor/$name"
  git -C "vendor/$name" remote add origin "$url"
  git -C "vendor/$name" fetch -q --depth 1 origin "$sha"
  git -C "vendor/$name" checkout -q FETCH_HEAD
  echo "$name: $sha"
done
