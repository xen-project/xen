
include $(BASEDIR)/Rules.mk

# naive OBJS rule gets link order wrong
SCSI_OBJS := scsi.o hosts.o scsicam.o scsi_dma.o scsi_error.o
SCSI_OBJS += scsi_ioctl.o scsi_lib.o scsi_merge.o scsi_proc.o 
SCSI_OBJS += scsi_queue.o scsi_scan.o scsi_syms.o scsi_obsolete.o
SCSI_OBJS += constants.o sd.o aacraid/aacraid.o aic7xxx/aic7xxx.o
SCSI_OBJS += megaraid.o BusLogic.o sym53c8xx_2/sym53c8xx.o

default: $(OBJS)
	$(MAKE) -C aacraid
	$(MAKE) -C aic7xxx
	$(MAKE) -C sym53c8xx_2
	$(LD) -r -o driver.o $(SCSI_OBJS)

clean:
	$(MAKE) -C aacraid clean
	$(MAKE) -C aic7xxx clean
	$(MAKE) -C sym53c8xx_2 clean
	rm -f *.o *~ core
