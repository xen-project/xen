########################################
# ia64-specific definitions

HAS_ACPI := y
HAS_VGA  := y
xenoprof := y
no_warns ?= n
xen_ia64_expose_p2m	?= y
xen_ia64_pervcpu_vhpt	?= y
xen_ia64_tlb_track	?= y
xen_ia64_tlb_track_cnt	?= n
xen_ia64_tlbflush_clock	?= y

ifneq ($(COMPILE_ARCH),$(TARGET_ARCH))
CROSS_COMPILE ?= /usr/local/sp_env/v2.2.5/i686/bin/ia64-unknown-linux-
endif

# Used only by linux/Makefile.
AFLAGS_KERNEL  += -mconstant-gp -nostdinc $(CPPFLAGS)

CFLAGS	+= -nostdinc -fno-builtin -fno-common -fno-strict-aliasing
CFLAGS	+= -mconstant-gp
#CFLAGS  += -O3		# -O3 over-inlines making debugging tough!
CFLAGS	+= -O2		# but no optimization causes compile errors!
CFLAGS	+= -fomit-frame-pointer -D__KERNEL__
CFLAGS	+= -iwithprefix include
CPPFLAGS+= -I$(BASEDIR)/include						\
	   -I$(BASEDIR)/include/asm-ia64				\
	   -I$(BASEDIR)/include/asm-ia64/linux 				\
	   -I$(BASEDIR)/include/asm-ia64/linux-xen 			\
	   -I$(BASEDIR)/include/asm-ia64/linux-null 			\
	   -I$(BASEDIR)/arch/ia64/linux -I$(BASEDIR)/arch/ia64/linux-xen
CFLAGS	+= $(CPPFLAGS)
#CFLAGS  += -Wno-pointer-arith -Wredundant-decls
CFLAGS	+= -DIA64 -DXEN -DLINUX_2_6
CFLAGS	+= -ffixed-r13 -mfixed-range=f2-f5,f12-f127,b2-b5
CFLAGS	+= -g
#CFLAGS  += -DVTI_DEBUG
ifeq ($(xen_ia64_expose_p2m),y)
CFLAGS	+= -DCONFIG_XEN_IA64_EXPOSE_P2M
endif
ifeq ($(xen_ia64_pervcpu_vhpt),y)
CFLAGS	+= -DCONFIG_XEN_IA64_PERVCPU_VHPT
endif
ifeq ($(xen_ia64_tlb_track),y)
CFLAGS	+= -DCONFIG_XEN_IA64_TLB_TRACK
endif
ifeq ($(xen_ia64_tlb_track_cnt),y)
CFLAGS	+= -DCONFIG_TLB_TRACK_CNT
endif
ifeq ($(xen_ia64_tlbflush_clock),y)
CFLAGS += -DCONFIG_XEN_IA64_TLBFLUSH_CLOCK
endif
ifeq ($(no_warns),y)
CFLAGS	+= -Wa,--fatal-warnings -Werror -Wno-uninitialized
endif

LDFLAGS := -g

# Additionnal IA64 include dirs.
HDRS += $(wildcard $(BASEDIR)/include/asm-ia64/linux-null/asm/*.h)
HDRS += $(wildcard $(BASEDIR)/include/asm-ia64/linux-null/asm/sn/*.h)
HDRS += $(wildcard $(BASEDIR)/include/asm-ia64/linux-null/linux/*.h)
HDRS += $(wildcard $(BASEDIR)/include/asm-ia64/linux-xen/asm/*.h)
HDRS += $(wildcard $(BASEDIR)/include/asm-ia64/linux-xen/asm/sn/*.h)
HDRS += $(wildcard $(BASEDIR)/include/asm-ia64/linux-xen/linux/*.h)
HDRS += $(wildcard $(BASEDIR)/include/asm-ia64/linux/*.h)
HDRS += $(wildcard $(BASEDIR)/include/asm-ia64/linux/asm-generic/*.h)
HDRS += $(wildcard $(BASEDIR)/include/asm-ia64/linux/asm/*.h)
HDRS += $(wildcard $(BASEDIR)/include/asm-ia64/linux/byteorder/*.h)
HDRS += $(wildcard $(BASEDIR)/include/asm-ia64/hvm/*.h)
