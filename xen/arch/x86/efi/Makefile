CFLAGS += -fshort-wchar

%.o: %.ihex
	$(OBJCOPY) -I ihex -O binary $< $@

boot.init.o: buildid.o

obj-y := stub.o
obj-$(XEN_BUILD_PE) := boot.init.o compat.o relocs-dummy.o runtime.o
extra-$(XEN_BUILD_PE) += buildid.o
nogcov-$(XEN_BUILD_PE) += stub.o
