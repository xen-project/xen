#
# Makefile for x86 timers
#

XENARCH	:= $(subst ",,$(CONFIG_XENARCH))

obj-y :=	timer_tsc.o
c-obj-y :=

c-link	:=

$(patsubst %.o,$(obj)/%.c,$(c-obj-y) $(c-link)):
	@ln -fsn $(srctree)/arch/i386/kernel/timers/$(notdir $@) $@

obj-y	+= $(c-obj-y)

clean-files += $(patsubst %.o,%.c,$(c-obj-y) $(c-obj-) $(c-link))
