
include $(BASEDIR)/Rules.mk


# SMH: need to ensure cciss init function called /after/ generic blkdev 
# stuff in ll_rw_blk etc. Linux barking link-order invocation of init 
# functions means we need to explicitly order things here. 
OBJS := blkpg.o elevator.o ll_rw_blk.o xen_vbd.o genhd.o xen_block.o 
OBJS += cciss.o cciss_scsi.o


default: $(OBJS)
	$(LD) -r -o driver.o $(OBJS)

clean:
	rm -f *.o *~ core
