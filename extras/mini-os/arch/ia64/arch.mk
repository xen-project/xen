# Build for Big Endian?
BIGENDIAN := n

ARCH_CFLAGS := -mfixed-range=f2-f5,f12-f15,f32-f127 -mconstant-gp
ARCH_CFLAGS += -O2
ARCH_ASFLAGS := -x assembler-with-cpp
ARCH_ASFLAGS += -mfixed-range=f2-f5,f12-f15,f32-f127 -fomit-frame-pointer
ARCH_ASFLAGS += -fno-builtin -fno-common -fno-strict-aliasing -mconstant-gp

ARCH_LDFLAGS = -warn-common

# Next lines are for big endian code !
ifeq ($(BIGENDIAN),y)
ARCH_CFLAGS += -mbig-endian -Wa,-mbe -Wa,-mlp64
ARCH_CFLAGS += -DBIG_ENDIAN
ARCH_ASFLAGS += -Wa,-mbe
ARCH_ASFLAGS += -DBIG_ENDIAN
ARCH_LDFLAGS = -EB -d
endif

