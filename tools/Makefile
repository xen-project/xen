#
# Grand Unified Makefile for Xen.
#
# Keir Fraser, 6/5/2003
#
# Builds everything except Xenolinux:
#  cd xenolinux-<version>-sparse
#  ./mkbuildtree <build dir>
#  cd <build dir> && make oldconfig && make dep && make bzImage
#  (<build dir> should be a vanilla linux tree with matching version)
#
# If you get errors in tools/domctl or tools/vdmanager, then you need
# the latest Java 2 SDK on your execution path: <http://java.sun.com>
# Also, you will need Apache's 'ant' build tool: <http://ant.apache.org>
#
# If you received this source as part of a Xen release, you should find
# that appropriate versions of the build tools are already installed in
# the initial system setup.

all:	
	$(MAKE) -C balloon
	$(MAKE) -C xc
	$(MAKE) -C misc
	$(MAKE) -C examples
	$(MAKE) -C xentrace

install: all
	$(MAKE) -C balloon install
	$(MAKE) -C xc install
	$(MAKE) -C misc install
	$(MAKE) -C examples install
	$(MAKE) -C xentrace install

dist: all
	$(MAKE) -C balloon dist
	$(MAKE) -C xc dist
	$(MAKE) -C misc dist
	$(MAKE) -C examples dist
	$(MAKE) -C xentrace dist

clean:
	$(MAKE) -C balloon clean
	$(MAKE) -C xc clean
	$(MAKE) -C misc clean
	$(MAKE) -C examples clean
	$(MAKE) -C nsplitd clean
	$(MAKE) -C xentrace clean

