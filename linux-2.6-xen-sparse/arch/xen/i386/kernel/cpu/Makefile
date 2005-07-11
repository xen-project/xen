#
# Makefile for x86-compatible CPU details and quirks
#

CFLAGS	+= -Iarch/i386/kernel/cpu

obj-y	:=	common.o
c-obj-y	+=	proc.o

c-obj-y	+=	amd.o
c-obj-y	+=	cyrix.o
c-obj-y	+=	centaur.o
c-obj-y	+=	transmeta.o
c-obj-y	+=	intel.o intel_cacheinfo.o
c-obj-y	+=	rise.o
c-obj-y	+=	nexgen.o
c-obj-y	+=	umc.o

#obj-$(CONFIG_X86_MCE)	+=	../../../../i386/kernel/cpu/mcheck/

obj-$(CONFIG_MTRR)	+= 	mtrr/
#obj-$(CONFIG_CPU_FREQ)	+=	../../../../i386/kernel/cpu/cpufreq/

c-link	:=

$(patsubst %.o,$(obj)/%.c,$(c-obj-y) $(c-link)):
	@ln -fsn $(srctree)/arch/i386/kernel/cpu/$(notdir $@) $@

obj-y	+= $(c-obj-y)

clean-files += $(patsubst %.o,%.c,$(c-obj-y) $(c-obj-) $(c-link))
