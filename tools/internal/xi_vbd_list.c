
#define _GNU_SOURCE
#include "dom0_defs.h"


#define MAX_DISKS 32
#define XDA_SIZE  (MAX_DISKS * sizeof(xen_disk_t))

/*
** List VBDs for oneself or a given domain, or list all VBDs in the system. 
*/
int main(int argc, char *argv[])
{
    block_io_op_t op; 
    unsigned int domain; 
    xen_disk_info_t *xdi; 
    int i, ret; 

    if ( argc > 2 ) {	
	fprintf(stderr, "Usage: xi_vbd_list [ <domain> | all ]\n"); 
	return 1;
    } 

    /* the default (domain == 0) is to probe for own VBDs */
    domain = 0; 

    if ( argc == 2) {
	if (!strcmp(argv[1], "all")) 
	    domain = VBD_PROBE_ALL; 
	else 
	    domain = atoi(argv[1]); 
    }

    /* allocate some space for the result */
    op.cmd = BLOCK_IO_OP_VBD_PROBE; 
    op.u.probe_params.domain    = domain; 
    op.u.probe_params.xdi.max   = MAX_DISKS; 
    op.u.probe_params.xdi.disks = malloc(XDA_SIZE); 
    op.u.probe_params.xdi.count = 0;

    xdi = &op.u.probe_params.xdi; // convenience 

    if(mlock(xdi->disks, XDA_SIZE) != 0 ) { 
        PERROR("Could not lock memory for Xen hypercall");
	return -1; 
    }

    ret = do_block_io_op(&op);

    if(ret < 0) 
	fprintf(stderr, "error %d attempting to probe VBDs\n", ret);

    (void)munlock(xdi->disks, XDA_SIZE); 

    for(i = 0; i < xdi->count; i++) { 
	fprintf(stderr, 
		"Domain %02d %cBD: [R/%c] device %04x capacity %ldkB\n", 
		xdi->disks[i].domain, XD_VIRTUAL(xdi->disks[i].info) ? 'V' : 
		'P', XD_READONLY(xdi->disks[i].info) ? 'O' : 'W', 
		xdi->disks[i].device,  xdi->disks[i].capacity >> 1); 
    }


    return ret;
}
