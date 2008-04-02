XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/firmware/Rules.mk

CFLAGS += -I$(XEN_ROOT)/tools/libxc -I.

.PHONY: all
all: extboot.bin

%.o: %.S
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

extboot.img: extboot.o
	$(LD) $(LDFLAGS_DIRECT) --oformat binary -Ttext 0 -o $@ $<

extboot.bin: extboot.img signrom
	./signrom extboot.img extboot.bin

signrom: signrom.c
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $^

clean:
	$(RM) -f *.o *.img *.bin signrom *~
