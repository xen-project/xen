#
# drivers/scsi/aic7xxx/Makefile
#
# Makefile for the Linux aic7xxx SCSI driver.
#

O_TARGET := aic7xxx_drv.o

include $(BASEDIR)/Rules.mk
#CFLAGS += -I$(BASEDIR)/drivers/scsi

#list-multi	:= aic7xxx.o aic79xx.o

#obj-$(CONFIG_SCSI_AIC7XXX)	+= aic7xxx.o
#ifeq ($(CONFIG_PCI),y)
#obj-$(CONFIG_SCSI_AIC79XX)	+= aic79xx.o
#endif

#EXTRA_CFLAGS += -g

# Platform Specific Files
obj-aic7xxx = aic7xxx_osm.o aic7xxx_proc.o aic7770_osm.o
#PCI Specific Platform Files
#ifeq ($(CONFIG_PCI),y)
obj-aic7xxx += aic7xxx_osm_pci.o
#endif
# Core Files
obj-aic7xxx += aic7xxx_core.o aic7xxx_93cx6.o aic7770.o
#PCI Specific Core Files
#ifeq ($(CONFIG_PCI),y)
obj-aic7xxx += aic7xxx_pci.o
#endif

# Platform Specific U320 Files
#obj-aic79xx = aic79xx_osm.o 
#obj-aic79xx += aic79xx_proc.o
#obj-aic79xx += aic79xx_osm_pci.o
obj-aic7xxx += aic79xx_osm.o 
obj-aic7xxx += aic79xx_proc.o
obj-aic7xxx += aic79xx_osm_pci.o
# Core Files
#obj-aic79xx += aic79xx_core.o
#obj-aic79xx += aic79xx_pci.o
obj-aic7xxx += aic79xx_core.o
obj-aic7xxx += aic79xx_pci.o

default: aic7xxx.o

aic7xxx_core.o: aic7xxx_seq.h
$(obj-aic7xxx): aic7xxx_reg.h
aic7xxx.o: aic7xxx_seq.h aic7xxx_reg.h $(obj-aic7xxx)
	$(LD) $(LD_RFLAG) -r -o $@ $(obj-aic7xxx)

aic79xx_core.o: aic79xx_seq.h
$(obj-aic79xx): aic79xx_reg.h
aic79xx.o: aic79xx_seq.h aic79xx_reg.h $(obj-aic79xx)
	$(LD) $(LD_RFLAG) -r -o $@ $(obj-aic79xx)

#ifeq ($(CONFIG_AIC7XXX_BUILD_FIRMWARE),y)
#aic7xxx_seq.h aic7xxx_reg.h: aic7xxx.seq aic7xxx.reg aicasm/aicasm
#	aicasm/aicasm -I. -r aic7xxx_reg.h -o aic7xxx_seq.h aic7xxx.seq
#endif

#ifeq ($(CONFIG_AIC79XX_BUILD_FIRMWARE),y)
#aic79xx_seq.h aic79xx_reg.h: aic79xx.seq aic79xx.reg aicasm/aicasm
#	aicasm/aicasm -I. -r aic79xx_reg.h -o aic79xx_seq.h aic79xx.seq
#endif

#aicasm/aicasm: aicasm/*.[chyl]
#	$(MAKE) -C aicasm

clean:
	rm -f *.o *~ core

