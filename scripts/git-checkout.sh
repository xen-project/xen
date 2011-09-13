#!/bin/bash

TREE=$1
TAG=$2
DIR=$3


if test -d $TREE; then
	mkdir -p $DIR
	ROOT=$TREE
else
	if test \! -d $DIR-remote; then
		rm -rf $DIR-remote $DIR-remote.tmp;
		mkdir $DIR-remote.tmp; rmdir $DIR-remote.tmp;
		git clone $TREE $DIR-remote.tmp;
		if test "$TAG" ; then
			cd $DIR-remote.tmp
			git branch -D dummy >/dev/null 2>&1 ||:
			git checkout -b dummy $TAG
			cd ..
		fi
		mv $DIR-remote.tmp $DIR-remote
	fi
	rm -f $DIR
	ln -sf $DIR-remote $DIR
	ROOT=.
fi

set -e
cd $DIR
# is this qemu-xen-traditional?
if test -f $ROOT/xen-setup; then
	$ROOT/xen-setup $IOEMU_CONFIGURE_CROSS
# is this qemu-xen?
elif test -f $ROOT/configure; then
	cd $ROOT
	./configure --enable-xen --target-list=i386-softmmu \
		--extra-cflags="-I$XEN_ROOT/tools/include \
		-I$XEN_ROOT/tools/libxc \
		-I$XEN_ROOT/tools/xenstore" \
		--extra-ldflags="-L$XEN_ROOT/tools/libxc \
		-L$XEN_ROOT/tools/libxenstore" \
		--bindir=/usr/lib/xen/bin \
		--disable-kvm \
		$IOEMU_CONFIGURE_CROSS
fi
