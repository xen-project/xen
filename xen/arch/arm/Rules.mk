########################################
# arm-specific definitions

#
# If you change any of these configuration options then you must
# 'make clean' before rebuilding.
#

HAS_DEVICE_TREE := y
HAS_VIDEO := y
HAS_ARM_HDLCD := y

CFLAGS += -fno-builtin -fno-common -Wredundant-decls
CFLAGS += -iwithprefix include -Werror -Wno-pointer-arith -pipe
CFLAGS += -I$(BASEDIR)/include

$(call cc-options-add,CFLAGS,CC,$(EMBEDDED_EXTRA_CFLAGS))
$(call cc-option-add,CFLAGS,CC,-Wnested-externs)

arm := y

ifeq ($(TARGET_SUBARCH),arm32)
# Prevent floating-point variables from creeping into Xen.
CFLAGS += -msoft-float
CFLAGS += -mcpu=cortex-a15 -mfpu=vfpv3 -mfloat-abi=softfp
arm32 := y
arm64 := n
endif

ifneq ($(call cc-option,$(CC),-fvisibility=hidden,n),n)
CFLAGS += -DGCC_HAS_VISIBILITY_ATTRIBUTE
endif
