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

echo "Installing Xen from '$src' to '$dst'..."
cd $src/boot
(echo '2.6.*' -2.6; echo '2.4.*' -2.4; echo '2.*.*' '') | while read m v
do
  l=$(eval ls -t vmlinuz-$m-xen0 2>/dev/null | head -n 1)
  [ -e "$l" ] && ln -fs "$l" vmlinuz${v}-xen0
  l=$(eval ls -t vmlinuz-$m-xenU 2>/dev/null | head -n 1)
  [ -e "$l" ] && ln -fs "$l" vmlinuz${v}-xenU
done
cd -
cp -fdRL $src/* $dst
echo "All done."

echo "Checking to see whether prerequisite tools are installed..."
cd $src/../check
./chk install
echo "All done."

exit 0
