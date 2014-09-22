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

(cd $tmp; tar -cf - *) | tar --no-same-owner -C "$dst" -xf -
rm -rf "$tmp"

echo "All done."

exit 0
