#!/bin/sh

src='./install'
if [ -d ./dist ]; then
  src='./dist/install'
fi

if ! [ -d $src ]; then
  echo "ERROR: Could not find a valid distribution directory."
  echo "       If this is a source-only release, try 'make dist'."
  exit 1
fi

dst='/'
if [ $# -ne 0 ]; then 
  dst=$1
fi

if ! [ -d $dst ]; then
  echo "ERROR: You must specify a valid install directory."
  echo "       The specified directory '$dst' is not valid."
  exit 1
fi

tmp="`mktemp -d`"

echo "Installing Xen from '$src' to '$dst'..."
(cd $src; tar -cf - * ) | tar -C "$tmp" -xf -

[ -x "$(which udevinfo)" ] && \
  UDEV_VERSION=$(udevinfo -V | sed -e 's/^[^0-9]* \([0-9]\{1,\}\)[^0-9]\{0,\}/\1/')

[ -z "$UDEV_VERSION" -a -x /sbin/udevadm ] && \
  UDEV_VERSION=$(/sbin/udevadm info -V | awk '{print $NF}')

if [ -n "$UDEV_VERSION" ] && [ $UDEV_VERSION -ge 059 ]; then
  echo " - installing for udev-based system"
  rm -rf "$tmp/etc/hotplug"
else
  echo " - installing for hotplug-based system"
  rm -rf "$tmp/etc/udev"
fi

echo " - modifying permissions"
chmod -R a+rX "$tmp"

(cd $tmp; tar -cf - *) | tar --no-same-owner -C "$dst" -xf -
rm -rf "$tmp"

echo "All done."

echo "Checking to see whether prerequisite tools are installed..."
cd $src/../check
./chk install
echo "All done."

exit 0
