#!/bin/sh

if ! [ -d ./install ]; then
  echo "ERROR: You must build Xen before it can be installed."
  echo "       For example, 'make dist'."
  exit 1
fi

prefix='/'
if [ $# -ne 0 ]; then 
  prefix=$1
fi

if ! [ -d $prefix ]; then
  echo "ERROR: You must specify a valid install directory."
  echo "       The specified directory '$prefix' is not valid."
  exit 1
fi

echo "Installing Xen to '$prefix'..."
cp -fdR ./install/* $prefix
echo "All done."

exit 0
