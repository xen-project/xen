
#define _GNU_SOURCE
#include "dom0_defs.h"

int main(int argc, char *argv[])
{
    privcmd_blkmsg_t    blkmsg;
    physdisk_probebuf_t buf;
    int                 i;

    if ( argc != 2 )
    {
	fprintf(stderr, "Usage: xi_phys_probe <domain_nr>\n");
	return 1;
    }

    memset(&buf, 0, sizeof(buf));

    do {
        buf.domain      = atol(argv[1]);
	buf.n_aces      = PHYSDISK_MAX_ACES_PER_REQUEST;

        blkmsg.op       = XEN_BLOCK_PHYSDEV_PROBE;
        blkmsg.buf      = &buf;
        blkmsg.buf_size = sizeof(buf);

        if ( do_xen_blkmsg(&blkmsg) < 0 )
            return 1;
        
	for ( i = 0; i < buf.n_aces; i++ )
        {
	    char read = (buf.entries[i].mode & 1 ? 'r' : ' ');
	    char write = (buf.entries[i].mode & 2 ? 'w' : ' ');
	    printf("%x %x %lx %lx %c%c\n", 
                   physdev_to_xldev(buf.entries[i].device),
		   buf.entries[i].partition,
		   buf.entries[i].start_sect,
		   buf.entries[i].n_sectors, read, write);
	}

	buf.start_ind += buf.n_aces;
    } 
    while ( buf.n_aces == PHYSDISK_MAX_ACES_PER_REQUEST );

    return 0;
}
