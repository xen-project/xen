
#define _GNU_SOURCE
#include "dom0_defs.h"


int main(int argc, char *argv[])
{
    block_io_op_t op; 
    unsigned int domain; 
    unsigned short vdevice, device; 
    int ret; 

    if ( argc != 7 )
    {
	fprintf(stderr, "Usage: xi_physdev_grant_new <r/rw> <domain> "
                "<device> <start sector> <n_sectors> <partition>\n");
	return 1;
    }


    /* 
    ** XXX SMH: guests can refer to 'real' devices as anything; however 
    ** for this particular use ("physdisk access") we want to use the 
    ** same device number in the guest as is used in xen => both 'vdevice' 
    ** (XL name) and "device" (Xen name) are the same. 
    */
    domain  = atoi(argv[2]); 
    device  = atoi(argv[3]); 
    /* XXX SMH: hack -- generate device name by addition ptn number */
    vdevice = device + atoi(argv[6]);
    
    op.cmd = BLOCK_IO_OP_VBD_CREATE; 
    op.u.create_info.domain  = domain; 
    op.u.create_info.vdevice = vdevice; 
    op.u.create_info.mode    = 0; 
    if ( strchr(argv[1], 'r') )
	op.u.create_info.mode |= VBD_MODE_R;
    if ( strchr(argv[1], 'w') )
        op.u.create_info.mode |= VBD_MODE_W;

    ret = do_block_io_op(&op);

    if(ret < 0) { 
	fprintf(stderr, "error %d attempting to create VBD %04x\n", ret, 
		atoi(argv[2])); 
	return ret; 
    }


    op.cmd = BLOCK_IO_OP_VBD_ADD; 
    op.u.add_info.domain  = domain; 
    op.u.add_info.vdevice = vdevice;

    op.u.add_info.extent.device       = device; 
    op.u.add_info.extent.start_sector = atol(argv[4]);
    op.u.add_info.extent.nr_sectors   = atol(argv[5]);

    ret = do_block_io_op(&op);

    if(ret < 0) { 
	fprintf(stderr, "error %d attempting to add extent to VBD %04x\n", 
		ret, atoi(argv[2])); 
	return ret; 
    }

    return 0;
}
