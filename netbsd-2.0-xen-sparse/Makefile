#
#
#

.PHONY: clean config install netbsd

TOPDIR		?= $(shell pwd)
NETBSD_RELEASE	?= $(patsubst netbsd-%-xen%,%,$(notdir $(TOPDIR)))
NETBSD_VER	?= $(patsubst netbsd-%-xen%,%,$(notdir $(TOPDIR)))

clean:
	@mkdir -p compile/XEN
	cd compile/XEN && TOPDIR=$(TOPDIR) NETBSD_VER=$(NETBSD_VER) ../../nbmake-xen cleandir

config:
	@mkdir -p compile/XEN
	cd compile/XEN && TOPDIR=$(TOPDIR) NETBSD_VER=$(NETBSD_VER) ../../nbconfig-xen XEN

netbsd:
	cd compile/XEN && TOPDIR=$(TOPDIR) NETBSD_VER=$(NETBSD_VER) ../../nbmake-xen dependall

install:
	@mkdir -p $(dir $(INSTALL_PATH)/$(INSTALL_NAME))
	install -c compile/XEN/netbsd $(INSTALL_PATH)/$(INSTALL_NAME)
