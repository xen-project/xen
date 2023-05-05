EFIOBJ-y := boot.init.o pe.init.o ebmalloc.o runtime.o
EFIOBJ-$(CONFIG_COMPAT) += compat.o

CFLAGS-y += -fshort-wchar
CFLAGS-y += -iquote $(srctree)/common/efi
CFLAGS-y += -iquote $(srcdir)

source :=
ifneq ($(abs_objtree),$(abs_srctree))
source := source/
endif

# Part of the command line transforms $(obj)
# e.g.: It transforms "dir/foo/bar" into successively
#       "dir foo bar", ".. .. ..", "../../.."
$(obj)/%.c: $(srctree)/common/efi/%.c FORCE
	$(Q)ln -nfs $(subst $(space),/,$(patsubst %,..,$(subst /, ,$(obj))))/$(source)common/efi/$(<F) $@

clean-files += $(patsubst %.o, %.c, $(EFIOBJ-y:.init.o=.o) $(EFIOBJ-))
clean-files += common-stub.c

.PRECIOUS: $(obj)/%.c
