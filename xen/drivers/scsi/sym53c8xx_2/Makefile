# File: drivers/sym53c8xx/Makefile
# Makefile for the NCR/SYMBIOS/LSI 53C8XX PCI SCSI controllers driver.

O_TARGET := sym53c8xx_drv.o
#list-multi := sym53c8xx.o
sym53c8xx-objs := sym_fw.o sym_glue.o sym_hipd.o sym_malloc.o sym_misc.o sym_nvram.o
obj-sym53c8xx := sym53c8xx.o
#obj-$(CONFIG_SCSI_SYM53C8XX_2) := sym53c8xx.o

EXTRA_CFLAGS += -I.

sym53c8xx.o: $(sym53c8xx-objs)
	$(LD) -r -o $@ $(sym53c8xx-objs)

include $(BASEDIR)/Rules.mk

clean:
	rm -f *.o
