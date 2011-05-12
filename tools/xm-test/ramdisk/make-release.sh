#!/bin/sh

if [ "$1" = "" ]
then
  arch=""
else
  echo "Invalid architecture specified." >&2
  exit 1
fi

set -eu

tempdir=$(mktemp -d)

dir=$(dirname "$0")

cd $(dirname "$dir")

./autogen
./configure

cd "$dir"

rm -Rf buildroot
make $arch initrd.img

initrd=$(readlink "initrd.img")
prefix=$(basename "$initrd" ".img")
arch=$(echo "$prefix" | sed -e 's/.*-//')

cp "$initrd" "$tempdir"

cp "buildroot/.config" "$tempdir/$prefix-buildroot-config"
cp "buildroot/package/busybox/busybox.config" "$tempdir/$prefix-busybox-config"
cp "buildroot/toolchain/uClibc/uClibc.config" "$tempdir/$prefix-uClibc-config"

mv "buildroot" "$tempdir/buildroot-$arch"
cd $tempdir
rm -Rf "buildroot-$arch"/toolchain_build*
rm -Rf "buildroot-$arch"/build_*
tar cjf "$prefix-buildroot.tar.bz2" "buildroot-$arch"
rm -Rf "buildroot-$arch"

echo -e "\n\nYour release is in $tempdir."
