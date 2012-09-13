########################################
# arm-specific definitions

#
# If you change any of these configuration options then you must
# 'make clean' before rebuilding.
#

HAS_DEVICE_TREE := y

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

CFLAGS += -mcpu=cortex-a15 -mfpu=vfpv3 -mfloat-abi=softfp
