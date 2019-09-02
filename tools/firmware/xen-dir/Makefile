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

# Exclude some intermediate files and final build products
LINK_EXCLUDES := '*.[isoa]' '.*.d' '.*.d2' '.config'
LINK_EXCLUDES += '*.map' 'xen' 'xen.gz' 'xen.efi' 'xen-syms'

# This is all a giant mess and doesn't really work.
#
# The correct solution is to fix Xen to be able to do out-of-tree builds.
#
# Until that happens, we set up a linkfarm by iterating over the xen/ tree,
# linking source files.  This is repeated each time we enter this directory,
# which poses a problem for a two-step "make; make install" build process.
#
# Any time the list of files to link changes, we relink all files, then
# distclean to take out not-easy-to-classify intermediate files.  This is to
# support easy development of the shim, but has a side effect of clobbering
# the already-built shim.
#
# $(LINK_EXCLUDES) should be set such that a parallel build of shim and xen/
# doesn't cause a subsequent `make install` to decide to regenerate the
# linkfarm.  This means that all final build artefacts must be excluded.
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
		 find $(d) ! -type l -type f $(addprefix ! -name ,$(LINK_EXCLUDES))) \
		 >> linkfarm.stamp.tmp ; ) \
	$(foreach f, $(LINK_FILES), \
		echo $(f) >> linkfarm.stamp.tmp ;)
	cmp -s linkfarm.stamp.tmp linkfarm.stamp && \
		rm linkfarm.stamp.tmp || { \
		cat linkfarm.stamp.tmp | while read f; \
		  do rm -f "$(D)/$$f"; ln -s "$(XEN_ROOT)/$$f" "$(D)/$$f"; done; \
		mv linkfarm.stamp.tmp linkfarm.stamp; \
		}

# Copy enough of the tree to build the shim hypervisor
$(D): linkfarm.stamp
	$(MAKE) -C $(D)/xen distclean

$(D)/xen/arch/x86/configs/pvshim_defconfig: $(D)

$(D)/xen/.config: $(D)/xen/arch/x86/configs/pvshim_defconfig
	$(MAKE) -C $(@D) KBUILD_DEFCONFIG=pvshim_defconfig XEN_CONFIG_EXPERT=y defconfig

xen-shim: $(D)/xen/.config
	$(MAKE) -C $(<D) build XEN_CONFIG_EXPERT=y
	ln -sf $(D)/xen/xen $@
	ln -sf $(D)/xen/xen-syms $@-syms

.PHONY: distclean clean
distclean clean:
	rm -f xen-shim xen-shim-syms *.old
	rm -rf $(D)
	rm -f linkfarm.stamp*
