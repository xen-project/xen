subdir-y += vtd

subdir-$(x86_32) += x86_32
subdir-$(x86_64) += x86_64

obj-y += intr.o
ifneq ($(vmxassist),y)
obj-y += realmode.o
endif
obj-y += vmcs.o
obj-y += vmx.o
