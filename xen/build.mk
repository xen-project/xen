quiet_cmd_banner = BANNER  $@
define cmd_banner
    if command -v figlet >/dev/null 2>&1 ; then \
	echo " Xen $(XEN_FULLVERSION)" | figlet -w 100 -f $< > $@.tmp; \
    else \
	echo "Xen $(XEN_FULLVERSION)" > $@.tmp; \
    fi; \
    mv -f $@.tmp $@
endef

.banner: tools/xen.flf FORCE
	$(call if_changed,banner)

targets += .banner

# Don't refresh this files during e.g., 'sudo make install'
quiet_cmd_compile.h = UPD     $@
define cmd_compile.h
    if [ ! -r $@ -o -O $@ ]; then \
	cat .banner; \
	sed -e 's/@@date@@/$(XEN_BUILD_DATE)/g' \
	    -e 's/@@time@@/$(XEN_BUILD_TIME)/g' \
	    -e 's/@@whoami@@/$(XEN_WHOAMI)/g' \
	    -e 's/@@domain@@/$(XEN_DOMAIN)/g' \
	    -e 's/@@hostname@@/$(XEN_BUILD_HOST)/g' \
	    -e 's!@@compiler@@!$(shell $(CC) --version 2>&1 | head -1)!g' \
	    -e 's/@@version@@/$(XEN_VERSION)/g' \
	    -e 's/@@subversion@@/$(XEN_SUBVERSION)/g' \
	    -e 's/@@extraversion@@/$(XEN_EXTRAVERSION)/g' \
	    -e 's!@@changeset@@!$(shell $(srctree)/tools/scmversion $(XEN_ROOT) || echo "unavailable")!g' \
	    < $< > $(dot-target).tmp; \
	sed -rf $(srctree)/tools/process-banner.sed < .banner >> $(dot-target).tmp; \
	mv -f $(dot-target).tmp $@; \
    fi
endef

include/xen/compile.h: include/xen/compile.h.in .banner FORCE
	$(if $(filter-out FORCE,$?),$(Q)rm -fv $@)
	$(call if_changed,compile.h)

targets += include/xen/compile.h

-include $(wildcard .asm-offsets.s.d)
asm-offsets.s: arch/$(SRCARCH)/$(ARCH)/asm-offsets.c
	$(CC) $(call cpp_flags,$(c_flags)) -S -g0 -o $@.new -MQ $@ $<
	$(call move-if-changed,$@.new,$@)

arch/$(SRCARCH)/include/asm/asm-offsets.h: asm-offsets.s
	@(set -e; \
	  echo "/*"; \
	  echo " * DO NOT MODIFY."; \
	  echo " *"; \
	  echo " * This file was auto-generated from $<"; \
	  echo " *"; \
	  echo " */"; \
	  echo ""; \
	  echo "#ifndef __ASM_OFFSETS_H__"; \
	  echo "#define __ASM_OFFSETS_H__"; \
	  echo ""; \
	  sed -rne "/^[^#].*==>/{s:.*==>(.*)<==.*:\1:; s: [\$$#]: :; p;}"; \
	  echo ""; \
	  echo "#endif") <$< >$@

build-dirs := $(patsubst %/built_in.o,%,$(filter %/built_in.o,$(ALL_OBJS) $(ALL_LIBS)))

# The actual objects are generated when descending,
# make sure no implicit rule kicks in
$(sort $(ALL_OBJS) $(ALL_LIBS)): $(build-dirs) ;

PHONY += $(build-dirs)
$(build-dirs): FORCE
	$(Q)$(MAKE) $(build)=$@ need-builtin=1

ifeq ($(CONFIG_LTO),y)
# Gather all LTO objects together
prelink_lto.o: $(ALL_OBJS) $(ALL_LIBS)
	$(LD_LTO) -r -o $@ $(filter-out %.a,$^) --start-group $(filter %.a,$^) --end-group

# Link it with all the binary objects
prelink.o: $(patsubst %/built_in.o,%/built_in_bin.o,$(ALL_OBJS)) prelink_lto.o FORCE
	$(call if_changed,ld)
else
prelink.o: $(ALL_OBJS) $(ALL_LIBS) FORCE
	$(call if_changed,ld)
endif

targets += prelink.o

$(TARGET): prelink.o FORCE
	$(Q)$(MAKE) $(build)=arch/$(SRCARCH) $@
