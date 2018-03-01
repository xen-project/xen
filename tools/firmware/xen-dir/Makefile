XEN_ROOT = $(CURDIR)/../../..

all: xen-shim

.PHONY: FORCE
FORCE:

D=xen-root

# Minimun set of files / directories go get Xen to build
LINK_DIRS=config xen
LINK_FILES=Config.mk

DEP_DIRS=$(foreach i, $(LINK_DIRS), $(XEN_ROOT)/$(i))
DEP_FILES=$(foreach i, $(LINK_FILES), $(XEN_ROOT)/$(i))

linkfarm.stamp: $(DEP_DIRS) $(DEP_FILES) FORCE
	mkdir -p $(D)
	rm -f linkfarm.stamp.tmp
	set -e; \
	$(foreach d, $(LINK_DIRS), \
		 (mkdir -p $(D)/$(d); \
		  cd $(D)/$(d); \
		  find $(XEN_ROOT)/$(d)/ -type d |\
			sed 's,^$(XEN_ROOT)/$(d)/,,g' | xargs mkdir -p .);) \
	$(foreach d, $(LINK_DIRS), \
		(cd $(XEN_ROOT); \
		 find $(d) ! -type l -type f \
		 $(addprefix ! -name , '*.[isoa]' '.*.d' '.*.d2')) \
		 >> linkfarm.stamp.tmp ; ) \
	$(foreach f, $(LINK_FILES), \
		echo $(f) >> linkfarm.stamp.tmp ;)
	cmp -s linkfarm.stamp.tmp linkfarm.stamp && \
		rm linkfarm.stamp.tmp || { \
		mv linkfarm.stamp.tmp linkfarm.stamp; \
		cat linkfarm.stamp | while read f; \
		  do rm -f "$(D)/$$f"; ln -s "$(XEN_ROOT)/$$f" "$(D)/$$f"; done \
		}

# Copy enough of the tree to build the shim hypervisor
$(D): linkfarm.stamp
	$(MAKE) -C $(D)/xen distclean

.PHONY: shim-%config
shim-%config: $(D) FORCE
	$(MAKE) -C $(D)/xen $*config \
		XEN_CONFIG_EXPERT=y \
		KCONFIG_CONFIG=$(CURDIR)/shim.config

xen-shim: $(D) shim-olddefconfig
	$(MAKE) -C $(D)/xen build \
		XEN_CONFIG_EXPERT=y \
		KCONFIG_CONFIG=$(CURDIR)/shim.config
	ln -sf $(D)/xen/xen $@
	ln -sf $(D)/xen/xen-syms $@-syms

.PHONY: distclean clean
distclean clean:
	rm -f xen-shim xen-shim-syms *.old
	rm -rf $(D)
	rm -f linkfarm.stamp*
