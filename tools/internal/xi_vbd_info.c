
#define _GNU_SOURCE
#include "dom0_defs.h"

#define MAX_EXTENTS 32 
#define XEA_SIZE    (MAX_EXTENTS * sizeof(xen_extent_t))

int main(int argc, char *argv[])
{
    block_io_op_t op; 
    unsigned int domain; 
    unsigned short vdevice; 
    xen_extent_t *extents; 
    int i, nextents, ret; 

    if( argc != 3) { 
	fprintf(stderr, "Usage: xi_vbd_info domain device\n"); 
	return 1; 
    } 
    
    domain  = atoi(argv[1]); 
    vdevice = atoi(argv[2]); 

    extents = malloc(XEA_SIZE); // convenience 

    op.cmd = BLOCK_IO_OP_VBD_INFO; 
    op.u.info_params.domain     = domain; 
    op.u.info_params.vdevice    = vdevice; 
    op.u.info_params.maxextents = MAX_EXTENTS; 
    op.u.info_params.extents    = extents; 
    op.u.info_params.nextents   = 0; 
    op.u.info_params.mode       = 0; 

    if(mlock(extents, XEA_SIZE) != 0) { 
        PERROR("Could not lock memory for Xen hypercall");
	return -1; 
    }

    ret = do_block_io_op(&op);

    (void)munlock(extents, XEA_SIZE); 

    if(ret < 0) {
	fprintf(stderr, "error %d attempting to query VBD %04x for dom %d\n", 
		ret, vdevice, domain);
    } else { 

	nextents = op.u.info_params.nextents; 
	fprintf(stderr, "Domain %d VBD %04x (mode %s) total of %d extents:\n", 
		domain, vdevice, op.u.info_params.mode == 1 ? "read-only" 
		: "read/write", nextents); 

	for(i = 0; i < nextents; i++) { 
	    fprintf(stderr, "extent %02d: dev %04x start %ld length %ld\n", 
		    i, extents[i].device, extents[i].start_sector, 
		    extents[i].nr_sectors); 
	} 
		    
    }


    return 0;
}
