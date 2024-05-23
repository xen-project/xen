ifeq ($(XEN_TARGET_ARCH),x86_64)
OBJCOPY_MAGIC := -I binary -O elf64-x86-64 -B i386:x86-64
endif
ifeq ($(XEN_TARGET_ARCH),arm64)
OBJCOPY_MAGIC := -I binary -O elf64-littleaarch64 -B aarch64
endif
ifeq ($(XEN_TARGET_ARCH),arm32)
OBJCOPY_MAGIC := -I binary -O elf32-littlearm -B arm
endif

CODE_ADDR=$(shell nm --defined $(1) | grep $(2) | awk '{print "0x"$$1}')
CODE_SZ=$(shell nm --defined -S $(1) | grep $(2) | awk '{ print "0x"$$2}')

CFLAGS-y += -iquote $(obj)

extra-y += xen_hello_world.livepatch
xen_hello_world-objs := xen_hello_world_func.o xen_hello_world.o note.o xen_note.o modinfo.o
$(obj)/xen_hello_world.o: $(obj)/config.h

#
# To compute these values we need the binary files: xen-syms
# and xen_hello_world_func.o to be already compiled.
#
$(obj)/config.h: $(obj)/xen_hello_world_func.o
	(set -e; \
	 echo "#define NEW_CODE_SZ $(call CODE_SZ,$<,xen_hello_world)"; \
	 echo "#define MINOR_VERSION_SZ $(call CODE_SZ,$(objtree)/xen-syms,xen_minor_version)"; \
	 echo "#define MINOR_VERSION_ADDR $(call CODE_ADDR,$(objtree)/xen-syms,xen_minor_version)"; \
	 echo "#define OLD_CODE_SZ $(call CODE_SZ,$(objtree)/xen-syms,xen_extra_version)") > $@

$(obj)/modinfo.o:
	(set -e; \
	 printf "LIVEPATCH_RULEZ\0") > $@.bin
	$(OBJCOPY) $(OBJCOPY_MAGIC) \
		   --rename-section=.data=.modinfo,alloc,load,readonly,data,contents -S $@.bin $@
	rm -f $@.bin

#
# This target is only accessible if CONFIG_LIVEPATCH is defined, which
# depends on $(build_id_linker) being available. Hence we do not
# need any checks.
#
# N.B. The reason we don't use arch/x86/note.o is that it may
# not be built (it is for EFI builds), and that we do not have
# the note.o.bin to muck with (as it gets deleted)
#
$(obj)/note.o: $(objtree)/xen-syms
	$(OBJCOPY) -O binary --only-section=.note.gnu.build-id $< $@.bin
	$(OBJCOPY) $(OBJCOPY_MAGIC) \
		   --rename-section=.data=.livepatch.depends,alloc,load,readonly,data,contents -S $@.bin $@
	rm -f $@.bin

#
# Append .livepatch.xen_depends section
# with Xen build-id derived from xen-syms.
#
$(obj)/xen_note.o: $(objtree)/xen-syms
	$(OBJCOPY) -O binary --only-section=.note.gnu.build-id $< $@.bin
	$(OBJCOPY) $(OBJCOPY_MAGIC) \
		   --rename-section=.data=.livepatch.xen_depends,alloc,load,readonly,data,contents -S $@.bin $@
	rm -f $@.bin

#
# Extract the build-id of the xen_hello_world.livepatch
# (which xen_bye_world will depend on).
#
$(obj)/hello_world_note.o: $(obj)/xen_hello_world.livepatch
	$(OBJCOPY) -O binary --only-section=.note.gnu.build-id $< $@.bin
	$(OBJCOPY) $(OBJCOPY_MAGIC) \
		   --rename-section=.data=.livepatch.depends,alloc,load,readonly,data,contents -S $@.bin $@
	rm -f $@.bin


extra-y += xen_bye_world.livepatch
xen_bye_world-objs := xen_bye_world_func.o xen_bye_world.o hello_world_note.o xen_note.o
$(obj)/xen_bye_world.o: $(obj)/config.h


extra-y += xen_replace_world.livepatch
xen_replace_world-objs := xen_replace_world_func.o xen_replace_world.o note.o xen_note.o
$(obj)/xen_replace_world.o: $(obj)/config.h


extra-y += xen_nop.livepatch
xen_nop-objs := xen_nop.o note.o xen_note.o
$(obj)/xen_nop.o: $(obj)/config.h

# This one always fails upon upload, because it deliberately
# does not have a .livepatch.xen_depends (xen_note.o) section.
extra-y += xen_no_xen_buildid.livepatch
xen_no_xen_buildid-objs := xen_nop.o note.o

$(obj)/xen_prepost_hooks.o: $(obj)/config.h

extra-y += xen_prepost_hooks.livepatch
xen_prepost_hooks-objs := xen_prepost_hooks.o xen_hello_world_func.o note.o xen_note.o

$(obj)/xen_prepost_hooks_fail.o: $(obj)/config.h

extra-y += xen_prepost_hooks_fail.livepatch
xen_prepost_hooks_fail-objs := xen_prepost_hooks_fail.o xen_hello_world_func.o note.o xen_note.o

$(obj)/xen_action_hooks.o: $(obj)/config.h

extra-y += xen_action_hooks.livepatch
xen_action_hooks-objs := xen_action_hooks.o xen_hello_world_func.o note.o xen_note.o

$(obj)/xen_action_hooks_nofunc.o: $(obj)/config.h

extra-y += xen_action_hooks_nofunc.livepatch
xen_action_hooks_nofunc-objs := xen_action_hooks_nofunc.o note.o xen_note.o

$(obj)/xen_action_hooks_marker.o: $(obj)/config.h

extra-y += xen_action_hooks_marker.livepatch
xen_action_hooks_marker-objs := xen_action_hooks_marker.o xen_hello_world_func.o note.o xen_note.o

$(obj)/xen_action_hooks_noapply.o: $(obj)/config.h

extra-y += xen_action_hooks_noapply.livepatch
xen_action_hooks_noapply-objs := xen_action_hooks_noapply.o xen_hello_world_func.o note.o xen_note.o

$(obj)/xen_action_hooks_norevert.o: $(obj)/config.h

extra-y += xen_action_hooks_norevert.livepatch
xen_action_hooks_norevert-objs := xen_action_hooks_norevert.o xen_hello_world_func.o note.o xen_note.o

EXPECT_BYTES_COUNT := 8
CODE_GET_EXPECT=$(shell $(OBJDUMP) -d --insn-width=1 $(1) | sed -n -e '/<'$(2)'>:$$/,/^$$/ p' | tail -n +2 | head -n $(EXPECT_BYTES_COUNT) | awk '{$$0=$$2; printf "%s", substr($$0,length-1)}' | sed 's/.\{2\}/0x&,/g' | sed 's/^/{/;s/,$$/}/g')
$(obj)/expect_config.h: $(objtree)/xen-syms
	(set -e; \
	 echo "#define EXPECT_BYTES $(call CODE_GET_EXPECT,$<,xen_extra_version)"; \
         echo "#define EXPECT_BYTES_COUNT $(EXPECT_BYTES_COUNT)") > $@

$(obj)/xen_expectations.o: $(obj)/expect_config.h

extra-y += xen_expectations.livepatch
xen_expectations-objs := xen_expectations.o xen_hello_world_func.o note.o xen_note.o

extra-y += xen_expectations_fail.livepatch
xen_expectations_fail-objs := xen_expectations_fail.o xen_hello_world_func.o note.o xen_note.o


quiet_cmd_livepatch = LD      $@
define cmd_livepatch
    $(LD) $(XEN_LDFLAGS) $(build_id_linker) -r -o $@ $(real-prereqs); \
    $(OBJCOPY) --set-section-flags ".livepatch.funcs=alloc,readonly" $@
endef

$(obj)/%.livepatch: FORCE
	$(call if_changed,livepatch)

$(call multi-depend, $(filter %.livepatch,$(extra-y)), .livepatch, -objs)
targets += $(sort $(foreach m,$(basename $(notdir $(filter %.livepatch,$(extra-y)))), \
                    $($(m)-objs)))

LIVEPATCHES := $(filter %.livepatch,$(extra-y))

LIVEPATCH_DEBUG_DIR ?= $(DEBUG_DIR)/xen-livepatch

install: $(addprefix $(obj)/,$(LIVEPATCHES))
	$(INSTALL_DIR) $(DESTDIR)$(LIVEPATCH_DEBUG_DIR)
	$(INSTALL_DATA) $(addprefix $(obj)/,$(LIVEPATCHES)) $(DESTDIR)$(LIVEPATCH_DEBUG_DIR)

uninstall:
	cd $(DESTDIR)$(LIVEPATCH_DEBUG_DIR) && rm -f $(LIVEPATCHES)

clean-files := config.h expect_config.h
