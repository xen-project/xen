XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS   += -static
CFLAGS   += -Wall
CFLAGS   += -Werror
CFLAGS   += -O3
CFLAGS   += -fno-strict-aliasing
CFLAGS   += -I.

all: build

build: mk-symlinks
	$(MAKE) xml_to_bin

default: all

install: all

xml_to_bin : make_include XmlToBin.java XmlToBinInterface.java SsidsEntry.java SecurityLabel.java myHandler.java
	javac XmlToBin.java

make_include : c2j_include
	./c2j_include

c2j_include: c2j_include.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

clean:
	rm -rf *.class xen c2j_include policy_version.java *.bin


LINUX_ROOT := $(XEN_ROOT)/linux-2.6-xen-sparse
mk-symlinks:
	[ -e xen/linux ] || mkdir -p xen/linux
	[ -e xen/io ]    || mkdir -p xen/io
	( cd xen >/dev/null ; \
	  ln -sf ../$(XEN_ROOT)/xen/include/public/*.h . )
	( cd xen/io >/dev/null ; \
	  ln -sf ../../$(XEN_ROOT)/xen/include/public/io/*.h . )
	( cd xen/linux >/dev/null ; \
	  ln -sf ../../$(LINUX_ROOT)/include/asm-xen/linux-public/*.h . )
