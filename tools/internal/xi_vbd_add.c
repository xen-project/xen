
#define _GNU_SOURCE
#include "dom0_defs.h"

/*
** Add an extent to a VBD; the VBD must have been created previously. 
*/
int main(int argc, char *argv[])
{
    block_io_op_t op; 
    unsigned int domain; 
    unsigned short vdevice, device; 
    int ret; 

    if ( argc != 6 )
    {
	fprintf(stderr, "Usage: xi_vbd_add <domain> <vdevice> <device>" 
		"<start sector> <nr_sectors>\n");
	return 1;
    }


    domain  = atoi(argv[1]); 
    device  = atoi(argv[2]); 
    vdevice = atoi(argv[3]);
    
    op.cmd = BLOCK_IO_OP_VBD_ADD; 
    op.u.add_params.domain  = domain; 
    op.u.add_params.vdevice = vdevice;

    op.u.add_params.extent.device       = device; 
    op.u.add_params.extent.start_sector = atol(argv[4]);
    op.u.add_params.extent.nr_sectors   = atol(argv[5]);

    ret = do_block_io_op(&op);

    if(ret < 0) { 
	fprintf(stderr, "error %d attempting to add extent to VBD %04x\n", 
		ret, atoi(argv[2])); 
	return ret; 
    }

    return 0;
}
