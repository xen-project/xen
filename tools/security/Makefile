XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

SRCS     = secpol_tool.c
CFLAGS   += -Wall
CFLAGS   += -Werror
CFLAGS   += -O3
CFLAGS   += -fno-strict-aliasing
CFLAGS   += -I. -I/usr/include/libxml2
CFLAGS_XML2BIN += $(shell xml2-config --cflags --libs )
#if above does not work, try  -L/usr/lib -lxml2 -lz -lpthread -lm
XML2VERSION = $(shell xml2-config --version )
VALIDATE_SCHEMA=$(shell if [[ $(XML2VERSION) < 2.6.20 ]]; then echo ""; else echo "-DVALIDATE_SCHEMA"; fi; )

ifeq ($(ACM_DEFAULT_SECURITY_POLICY),ACM_NULL_POLICY)
POLICY=null
endif
ifeq ($(ACM_DEFAULT_SECURITY_POLICY),ACM_CHINESE_WALL_POLICY)
POLICY=chwall
endif
ifeq ($(ACM_DEFAULT_SECURITY_POLICY),ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY)
POLICY=ste
endif
ifeq ($(ACM_DEFAULT_SECURITY_POLICY),ACM_CHINESE_WALL_AND_SIMPLE_TYPE_ENFORCEMENT_POLICY)
POLICY=chwall_ste
endif
POLICYFILE=./policies/$(POLICY)/$(POLICY).bin

ifeq ($(ACM_SECURITY),y)
all: build

install:all

default:all
else
all:

install:

default:
endif

build: mk-symlinks
	$(MAKE) secpol_tool
	$(MAKE) secpol_xml2bin
	$(MAKE) get_decision
	chmod 700 ./setlabel.sh
	chmod 700 ./updategrub.sh
	chmod 700 ./getlabel.sh

secpol_tool : secpol_tool.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

secpol_xml2bin : secpol_xml2bin.c secpol_xml2bin.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CFLAGS_XML2BIN) $(VALIDATE_SCHEMA) -o $@ $<

clean:
	rm -rf secpol_tool secpol_xml2bin xen get_decision

policy_clean:
	rm -rf policies/*/*.bin policies/*/*.map

mrproper: clean policy_clean


$(POLICYFILE) : build
	@./secpol_xml2bin $(POLICY) > /dev/null

boot_install: $(POLICYFILE)
	@cp $(POLICYFILE) /boot
	@./updategrub.sh $(POLICY) $(PWD)/$(XEN_ROOT)

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
