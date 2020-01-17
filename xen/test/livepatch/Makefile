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

.PHONY: default

LIVEPATCH := xen_hello_world.livepatch
LIVEPATCH_BYE := xen_bye_world.livepatch
LIVEPATCH_REPLACE := xen_replace_world.livepatch
LIVEPATCH_NOP := xen_nop.livepatch
LIVEPATCH_NO_XEN_BUILDID := xen_no_xen_buildid.livepatch
LIVEPATCH_PREPOST_HOOKS := xen_prepost_hooks.livepatch
LIVEPATCH_PREPOST_HOOKS_FAIL := xen_prepost_hooks_fail.livepatch
LIVEPATCH_ACTION_HOOKS := xen_action_hooks.livepatch
LIVEPATCH_ACTION_HOOKS_NOFUNC := xen_action_hooks_nofunc.livepatch
LIVEPATCH_ACTION_HOOKS_MARKER:= xen_action_hooks_marker.livepatch
LIVEPATCH_ACTION_HOOKS_NOAPPLY:= xen_action_hooks_noapply.livepatch
LIVEPATCH_ACTION_HOOKS_NOREVERT:= xen_action_hooks_norevert.livepatch
LIVEPATCH_EXPECTATIONS:= xen_expectations.livepatch
LIVEPATCH_EXPECTATIONS_FAIL:= xen_expectations_fail.livepatch

LIVEPATCHES += $(LIVEPATCH)
LIVEPATCHES += $(LIVEPATCH_BYE)
LIVEPATCHES += $(LIVEPATCH_REPLACE)
LIVEPATCHES += $(LIVEPATCH_NOP)
LIVEPATCHES += $(LIVEPATCH_NO_XEN_BUILDID)
LIVEPATCHES += $(LIVEPATCH_PREPOST_HOOKS)
LIVEPATCHES += $(LIVEPATCH_PREPOST_HOOKS_FAIL)
LIVEPATCHES += $(LIVEPATCH_ACTION_HOOKS)
LIVEPATCHES += $(LIVEPATCH_ACTION_HOOKS_NOFUNC)
LIVEPATCHES += $(LIVEPATCH_ACTION_HOOKS_MARKER)
LIVEPATCHES += $(LIVEPATCH_ACTION_HOOKS_NOAPPLY)
LIVEPATCHES += $(LIVEPATCH_ACTION_HOOKS_NOREVERT)
LIVEPATCHES += $(LIVEPATCH_EXPECTATIONS)
LIVEPATCHES += $(LIVEPATCH_EXPECTATIONS_FAIL)

LIVEPATCH_DEBUG_DIR ?= $(DEBUG_DIR)/xen-livepatch

build default: livepatch

install: livepatch
	$(INSTALL_DIR) $(DESTDIR)$(LIVEPATCH_DEBUG_DIR)
	$(INSTALL_DATA) $(LIVEPATCHES) $(DESTDIR)$(LIVEPATCH_DEBUG_DIR)

uninstall:
	cd $(DESTDIR)$(LIVEPATCH_DEBUG_DIR) && rm -f $(LIVEPATCHES)

.PHONY: clean
clean::
	rm -f *.o .*.o.d *.livepatch config.h expect_config.h

#
# To compute these values we need the binary files: xen-syms
# and xen_hello_world_func.o to be already compiled.
#
.PHONY: config.h
config.h: OLD_CODE_SZ=$(call CODE_SZ,$(BASEDIR)/xen-syms,xen_extra_version)
config.h: NEW_CODE_SZ=$(call CODE_SZ,$<,xen_hello_world)
config.h: MINOR_VERSION_SZ=$(call CODE_SZ,$(BASEDIR)/xen-syms,xen_minor_version)
config.h: MINOR_VERSION_ADDR=$(call CODE_ADDR,$(BASEDIR)/xen-syms,xen_minor_version)
config.h: xen_hello_world_func.o
	(set -e; \
	 echo "#define NEW_CODE_SZ $(NEW_CODE_SZ)"; \
	 echo "#define MINOR_VERSION_SZ $(MINOR_VERSION_SZ)"; \
	 echo "#define MINOR_VERSION_ADDR $(MINOR_VERSION_ADDR)"; \
	 echo "#define OLD_CODE_SZ $(OLD_CODE_SZ)") > $@

xen_hello_world.o: config.h

.PHONY: $(LIVEPATCH)
$(LIVEPATCH): xen_hello_world_func.o xen_hello_world.o note.o xen_note.o modinfo.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH) $^

.PHONY: modinfo.o
modinfo.o:
	(set -e; \
	 printf "LIVEPATCH_RULEZ\0") > $@.bin
	$(OBJCOPY) $(OBJCOPY_MAGIC) \
		   --rename-section=.data=.modinfo,alloc,load,readonly,data,contents -S $@.bin $@
	#rm -f $@.bin

#
# This target is only accessible if CONFIG_LIVEPATCH is defined, which
# depends on $(build_id_linker) being available. Hence we do not
# need any checks.
#
# N.B. The reason we don't use arch/x86/note.o is that it may
# not be built (it is for EFI builds), and that we do not have
# the note.o.bin to muck with (as it gets deleted)
#
.PHONY: note.o
note.o:
	$(OBJCOPY) -O binary --only-section=.note.gnu.build-id $(BASEDIR)/xen-syms $@.bin
	$(OBJCOPY) $(OBJCOPY_MAGIC) \
		   --rename-section=.data=.livepatch.depends,alloc,load,readonly,data,contents -S $@.bin $@
	rm -f $@.bin

#
# Append .livepatch.xen_depends section
# with Xen build-id derived from xen-syms.
#
.PHONY: xen_note.o
xen_note.o:
	$(OBJCOPY) -O binary --only-section=.note.gnu.build-id $(BASEDIR)/xen-syms $@.bin
	$(OBJCOPY) $(OBJCOPY_MAGIC) \
		   --rename-section=.data=.livepatch.xen_depends,alloc,load,readonly,data,contents -S $@.bin $@
	rm -f $@.bin

#
# Extract the build-id of the xen_hello_world.livepatch
# (which xen_bye_world will depend on).
#
.PHONY: hello_world_note.o
hello_world_note.o: $(LIVEPATCH)
	$(OBJCOPY) -O binary --only-section=.note.gnu.build-id $(LIVEPATCH) $@.bin
	$(OBJCOPY) $(OBJCOPY_MAGIC) \
		   --rename-section=.data=.livepatch.depends,alloc,load,readonly,data,contents -S $@.bin $@
	rm -f $@.bin

xen_bye_world.o: config.h

.PHONY: $(LIVEPATCH_BYE)
$(LIVEPATCH_BYE): xen_bye_world_func.o xen_bye_world.o hello_world_note.o xen_note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_BYE) $^

xen_replace_world.o: config.h

.PHONY: $(LIVEPATCH_REPLACE)
$(LIVEPATCH_REPLACE): xen_replace_world_func.o xen_replace_world.o note.o xen_note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_REPLACE) $^

xen_nop.o: config.h

.PHONY: $(LIVEPATCH_NOP)
$(LIVEPATCH_NOP): xen_nop.o note.o xen_note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_NOP) $^

# This one always fails upon upload, because it deliberately
# does not have a .livepatch.xen_depends (xen_note.o) section.
xen_no_xen_buildid.o: config.h

.PHONY: $(LIVEPATCH_NO_XEN_BUILDID)
$(LIVEPATCH_NO_XEN_BUILDID): xen_nop.o note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_NO_XEN_BUILDID) $^

xen_prepost_hooks.o: config.h

.PHONY: $(LIVEPATCH_PREPOST_HOOKS)
$(LIVEPATCH_PREPOST_HOOKS): xen_prepost_hooks.o xen_hello_world_func.o note.o xen_note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_PREPOST_HOOKS) $^

xen_prepost_hooks_fail.o: config.h

.PHONY: $(LIVEPATCH_PREPOST_HOOKS_FAIL)
$(LIVEPATCH_PREPOST_HOOKS_FAIL): xen_prepost_hooks_fail.o xen_hello_world_func.o note.o xen_note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_PREPOST_HOOKS_FAIL) $^

xen_action_hooks.o: config.h

.PHONY: $(LIVEPATCH_ACTION_HOOKS)
$(LIVEPATCH_ACTION_HOOKS): xen_action_hooks.o xen_hello_world_func.o note.o xen_note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_ACTION_HOOKS) $^

xen_action_hooks_nofunc.o: config.h

.PHONY: $(LIVEPATCH_ACTION_HOOKS_NOFUNC)
$(LIVEPATCH_ACTION_HOOKS_NOFUNC): xen_action_hooks_nofunc.o note.o xen_note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_ACTION_HOOKS_NOFUNC) $^

xen_action_hooks_marker.o: config.h

.PHONY: $(LIVEPATCH_ACTION_HOOKS_MARKER)
$(LIVEPATCH_ACTION_HOOKS_MARKER): xen_action_hooks_marker.o xen_hello_world_func.o note.o xen_note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_ACTION_HOOKS_MARKER) $^

xen_action_hooks_noapply.o: config.h

.PHONY: $(LIVEPATCH_ACTION_HOOKS_NOAPPLY)
$(LIVEPATCH_ACTION_HOOKS_NOAPPLY): xen_action_hooks_marker.o xen_hello_world_func.o note.o xen_note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_ACTION_HOOKS_NOAPPLY) $^

xen_action_hooks_norevert.o: config.h

.PHONY: $(LIVEPATCH_ACTION_HOOKS_NOREVERT)
$(LIVEPATCH_ACTION_HOOKS_NOREVERT): xen_action_hooks_marker.o xen_hello_world_func.o note.o xen_note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_ACTION_HOOKS_NOREVERT) $^

EXPECT_BYTES_COUNT := 8
CODE_GET_EXPECT=$(shell $(OBJDUMP) -d --insn-width=1 $(1) | sed -n -e '/<'$(2)'>:$$/,/^$$/ p' | tail -n +2 | head -n $(EXPECT_BYTES_COUNT) | awk '{$$0=$$2; printf "%s", substr($$0,length-1)}' | sed 's/.\{2\}/0x&,/g' | sed 's/^/{/;s/,$$/}/g')
.PHONY: expect_config.h
expect_config.h: EXPECT_BYTES=$(call CODE_GET_EXPECT,$(BASEDIR)/xen-syms,xen_extra_version)
expect_config.h:
	(set -e; \
	 echo "#define EXPECT_BYTES $(EXPECT_BYTES)"; \
         echo "#define EXPECT_BYTES_COUNT $(EXPECT_BYTES_COUNT)") > $@

xen_expectations.o: expect_config.h

.PHONY: $(LIVEPATCH_EXPECTATIONS)
$(LIVEPATCH_EXPECTATIONS): xen_expectations.o xen_hello_world_func.o note.o xen_note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_EXPECTATIONS) $^

.PHONY: $(LIVEPATCH_EXPECTATIONS_FAIL)
$(LIVEPATCH_EXPECTATIONS_FAIL): xen_expectations_fail.o xen_hello_world_func.o note.o xen_note.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_EXPECTATIONS_FAIL) $^

.PHONY: livepatch
livepatch: $(LIVEPATCH) $(LIVEPATCH_BYE) $(LIVEPATCH_REPLACE) $(LIVEPATCH_NOP) $(LIVEPATCH_NO_XEN_BUILDID) \
           $(LIVEPATCH_PREPOST_HOOKS) $(LIVEPATCH_PREPOST_HOOKS_FAIL) $(LIVEPATCH_ACTION_HOOKS) \
           $(LIVEPATCH_ACTION_HOOKS_NOFUNC) $(LIVEPATCH_ACTION_HOOKS_MARKER) $(LIVEPATCH_ACTION_HOOKS_NOAPPLY) \
           $(LIVEPATCH_ACTION_HOOKS_NOREVERT) $(LIVEPATCH_EXPECTATIONS) $(LIVEPATCH_EXPECTATIONS_FAIL)
