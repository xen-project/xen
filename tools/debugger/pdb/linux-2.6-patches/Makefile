XEN_ROOT   = ../../../..
LINUX_DIR  = linux-2.6.12-xenU
KDIR       = $(XEN_ROOT)/$(LINUX_DIR)
PATCH_DIR  = $(CURDIR)

.PHONY: patches 
patches : patches-done

patches-done :
	( for i in *.patch ; do ( cd $(KDIR) ; patch -p1 < $(PATCH_DIR)/$$i || exit 1 ) ; done )
	touch $@
