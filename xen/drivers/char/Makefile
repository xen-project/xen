include $(BASEDIR)/Rules.mk

obj-y += console.o
obj-y += ns16550.o
obj-y += serial.o

include $(BASEDIR)/Post.mk

# Object file contains changeset and compiler information.
console.o: $(BASEDIR)/include/xen/compile.h
