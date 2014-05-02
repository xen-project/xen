
XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test_vhpet

.PHONY: all
all: $(TARGET)

.PHONY: run
run: $(TARGET)
	./$(TARGET) > $(TARGET).out
	./$(TARGET) 0 > $(TARGET).0.out
	./$(TARGET) 0 1 0 20 > $(TARGET).0.1.0.20.out
	./$(TARGET) 200 > $(TARGET).200.out
	./$(TARGET) 200 1 0 20 > $(TARGET).200.1.0.20.out
	./$(TARGET) 300 5 > $(TARGET).200.5.out
	./$(TARGET) 400 4 2000 > $(TARGET).200.4.2000.out
	./$(TARGET) 0 1 0 20 0x0103 > $(TARGET).0.1.0.20.0x0103.out
	./$(TARGET) 200 1 0 20 0x0103 > $(TARGET).200.1.0.20.0x0103.out

$(TARGET): hpet.c main.c hpet.h emul.h Makefile
	$(HOSTCC) -g -o $@ hpet.c main.c

.PHONY: clean
clean:
	rm -rf $(TARGET) $(TARGET).out *.o *~ core* hpet.h hpet.c

.PHONY: install
install:

hpet.h: $(XEN_ROOT)/xen/include/asm-x86/hpet.h
	cp $< $@

hpet.c: $(XEN_ROOT)/xen/arch/x86/hvm/hpet.c
	sed -e "/#include/d" -e "1i#include \"emul.h\"\n" <$< >$@
