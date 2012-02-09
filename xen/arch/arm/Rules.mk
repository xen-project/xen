########################################
# arm-specific definitions

#
# If you change any of these configuration options then you must
# 'make clean' before rebuilding.
#

CFLAGS += -fno-builtin -fno-common -Wredundant-decls
CFLAGS += -iwithprefix include -Werror -Wno-pointer-arith -pipe
CFLAGS += -I$(BASEDIR)/include

# Prevent floating-point variables from creeping into Xen.
CFLAGS += -msoft-float

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))
$(call cc-option-add,CFLAGS,CC,-Wnested-externs)

arm := y

ifneq ($(call cc-option,$(CC),-fvisibility=hidden,n),n)
CFLAGS += -DGCC_HAS_VISIBILITY_ATTRIBUTE
endif

CFLAGS += -march=armv7-a -mcpu=cortex-a15

# Require GCC v3.4+ (to avoid issues with alignment constraints in Xen headers)
check-$(gcc) = $(call cc-ver-check,CC,0x030400,"Xen requires at least gcc-3.4")
$(eval $(check-y))
