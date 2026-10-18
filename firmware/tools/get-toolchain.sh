#!/bin/sh
# Fetch the Arm GNU Toolchain (arm-none-eabi, with newlib) for this host into firmware/.toolchain/.
# Works on macOS arm64, Linux aarch64 and Linux x86_64; no root needed.
set -eu
VER=15.3.rel2
BASE="https://gitlab.arm.com/api/v4/projects/tooling%2Fgnu-toolchains-for-arm/packages/generic/gnu-toolchain/$VER"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  HOST=darwin-arm64; SHA=f011e4832046155f06408dda6b252b21b139a8159c8529802227371f06656c60 ;;
  Linux-aarch64) HOST=aarch64;      SHA=a0dc18893171d39dec82fd8d57eeab3da836fd3df4b61978db3eccbf4a6bb948 ;;
  Linux-x86_64)  HOST=x86_64;       SHA=463df9665c246fa13bab2102115bbf83440661b6eb70b44f3dfd4712ca30037a ;;
  *) echo "unsupported host $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

DIR="$(cd "$(dirname "$0")/.." && pwd)/.toolchain"
NAME="arm-gnu-toolchain-$VER-$HOST-arm-none-eabi"
[ -x "$DIR/$NAME/bin/arm-none-eabi-gcc" ] && { echo "$DIR/$NAME/bin"; exit 0; }

mkdir -p "$DIR"
curl -fL --retry 3 -o "$DIR/$NAME.tar.xz" "$BASE/$NAME.tar.xz" >&2
if command -v sha256sum >/dev/null; then GOT=$(sha256sum "$DIR/$NAME.tar.xz" | cut -d' ' -f1)
else GOT=$(shasum -a 256 "$DIR/$NAME.tar.xz" | cut -d' ' -f1); fi
[ "$GOT" = "$SHA" ] || { echo "checksum mismatch: $GOT" >&2; rm -f "$DIR/$NAME.tar.xz"; exit 1; }
tar -xJf "$DIR/$NAME.tar.xz" -C "$DIR"
rm "$DIR/$NAME.tar.xz"
echo "$DIR/$NAME/bin"
