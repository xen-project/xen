########################################
# ia64-specific definitions

VALIDATE_VT	?= n
ifneq ($(COMPILE_ARCH),$(TARGET_ARCH))
CROSS_COMPILE ?= /usr/local/sp_env/v2.2.5/i686/bin/ia64-unknown-linux-
endif
AFLAGS  += -D__ASSEMBLY__
CPPFLAGS  += -I$(BASEDIR)/include -I$(BASEDIR)/include/asm-ia64 	\
             -I$(BASEDIR)/include/asm-ia64/linux 			\
	     -I$(BASEDIR)/include/asm-ia64/linux-xen 			\
	     -I$(BASEDIR)/include/asm-ia64/linux-null 			\
             -I$(BASEDIR)/arch/ia64/linux -I$(BASEDIR)/arch/ia64/linux-xen

CFLAGS  := -nostdinc -fno-builtin -fno-common -fno-strict-aliasing
#CFLAGS  += -O3		# -O3 over-inlines making debugging tough!
CFLAGS  += -O2		# but no optimization causes compile errors!
#CFLAGS  += -iwithprefix include -Wall -DMONITOR_BASE=$(MONITOR_BASE)
CFLAGS  += -iwithprefix include -Wall
CFLAGS  += -fomit-frame-pointer -I$(BASEDIR)/include -D__KERNEL__
CFLAGS  += -I$(BASEDIR)/include/asm-ia64 -I$(BASEDIR)/include/asm-ia64/linux \
           -I$(BASEDIR)/include/asm-ia64/linux 				\
           -I$(BASEDIR)/include/asm-ia64/linux-xen 			\
	   -I$(BASEDIR)/include/asm-ia64/linux-null 			\
           -I$(BASEDIR)/arch/ia64/linux -I$(BASEDIR)/arch/ia64/linux-xen
#CFLAGS  += -Wno-pointer-arith -Wredundant-decls
CFLAGS  += -DIA64 -DXEN -DLINUX_2_6 -DV_IOSAPIC_READY
CFLAGS	+= -ffixed-r13 -mfixed-range=f12-f15,f32-f127
CFLAGS	+= -g
#CFLAGS  += -DVTI_DEBUG
ifeq ($(VALIDATE_VT),y)
CFLAGS  += -DVALIDATE_VT
endif
LDFLAGS := -g
