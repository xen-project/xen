
include $(BASEDIR)/Rules.mk

# naive OBJS rule gets link order wrong
SCSIOBJS := scsi.o hosts.o scsicam.o scsi_dma.o scsi_error.o scsi_ioctl.o scsi_lib.o scsi_merge.o scsi_proc.o scsi_queue.o scsi_scan.o scsi_syms.o constants.o sd.o aacraid/aacraid.o aic7xxx/aic7xxx.o megaraid.o

default: $(OBJS)
	$(MAKE) -C aacraid
	$(MAKE) -C aic7xxx
	$(LD) -r -o driver.o $(SCSIOBJS)

clean:
	$(MAKE) -C aacraid clean
	$(MAKE) -C aic7xxx clean
	rm -f *.o *~ core
