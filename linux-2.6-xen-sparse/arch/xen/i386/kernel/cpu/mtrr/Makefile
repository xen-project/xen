obj-y	:= main.o
c-obj-y	:= if.o

c-link	:=

$(patsubst %.o,$(obj)/%.c,$(c-obj-y) $(c-link)): $(obj)/mtrr.h
	@ln -fsn $(srctree)/arch/i386/kernel/cpu/mtrr/$(notdir $@) $@

$(patsubst %.o,$(obj)/%.c,$(obj-y)): $(obj)/mtrr.h

$(obj)/mtrr.h:
	@ln -fsn $(srctree)/arch/i386/kernel/cpu/mtrr/mtrr.h $@

obj-y	+= $(c-obj-y)

clean-files += $(patsubst %.o,%.c,$(c-obj-y) $(c-obj-) $(c-link))
