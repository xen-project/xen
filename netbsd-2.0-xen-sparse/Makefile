#
#
#

.PHONY: clean config install netbsd

TOPDIR		?= $(shell pwd)
NETBSD_RELEASE	?= $(patsubst netbsd-%-xen%,%,$(notdir $(TOPDIR)))
NETBSD_VER	?= $(patsubst netbsd-%-xen%,%,$(notdir $(TOPDIR)))
NETBSD_KERNEL	?= XEN

clean:
	@mkdir -p compile/$(NETBSD_KERNEL)
	cd compile/$(NETBSD_KERNEL) && TOPDIR=$(TOPDIR) NETBSD_VER=$(NETBSD_VER) ../../nbmake-xen cleandir

config:
	@mkdir -p compile/$(NETBSD_KERNEL)
	cd compile/$(NETBSD_KERNEL) && TOPDIR=$(TOPDIR) NETBSD_VER=$(NETBSD_VER) ../../nbconfig-xen $(NETBSD_KERNEL)

netbsd:
	cd compile/$(NETBSD_KERNEL) && TOPDIR=$(TOPDIR) NETBSD_VER=$(NETBSD_VER) ../../nbmake-xen dependall

install:
	@mkdir -p $(dir $(INSTALL_PATH)/$(INSTALL_NAME))
	install -c compile/$(NETBSD_KERNEL)/netbsd $(INSTALL_PATH)/$(INSTALL_NAME)
