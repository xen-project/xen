
#define _GNU_SOURCE
#include "dom0_defs.h"

/* 
** Create a new VBD for a given domain; the VBD can be read-only or
** read/write, and will be referred to by the relevant domain as 'vdevice'. 
*/
int main(int argc, char *argv[])
{
    block_io_op_t op; 
    unsigned int domain; 
    unsigned short vdevice; 
    int ret; 

    if ( argc != 4 )
    {
	fprintf(stderr, "Usage: xi_vbd_create <domain> <vdevice> <r/rw>\n"); 
	return 1;
    }

    domain  = atoi(argv[1]); 
    vdevice = atoi(argv[2]); 
    
    op.cmd = BLOCK_IO_OP_VBD_CREATE; 
    op.u.create_params.domain  = domain; 
    op.u.create_params.vdevice = vdevice; 
    op.u.create_params.mode    = 0; 
    if ( strchr(argv[3], 'r') )
	op.u.create_params.mode |= VBD_MODE_R;
    if ( strchr(argv[3], 'w') )
        op.u.create_params.mode |= VBD_MODE_W;

    ret = do_block_io_op(&op);

    if(ret < 0) { 
	fprintf(stderr, "error %d attempting to create VBD %04x\n", ret, 
		atoi(argv[2])); 
	return ret; 
    }

    return 0;
}
