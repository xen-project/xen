/*
 * pdb_xen.c
 *
 * alex ho
 * http://www.cl.cam.ac.uk/netos/pdb
 *
 * PDB interface library for accessing Xen
 */

#include <xenctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

int
pdb_open ()
{
    int xc_handle = xc_interface_open();

    if ( xc_handle < 0 )
    {
        fprintf(stderr, "(pdb) error opening xc interface: %d (%s)\n",
                errno, strerror(errno));
    }
    return xc_handle;
}

int 
pdb_close (int xc_handle)
{
    int rc;

    
    if ( (rc = xc_interface_close(xc_handle)) < 0 )
    {
        fprintf(stderr, "(pdb) error closing xc interface: %d (%s)\n",
                errno, strerror(errno));
    }
    return rc;
}


#include <sys/ioctl.h>
#include <xen/linux/evtchn.h>

int
xen_evtchn_bind (int evtchn_fd, int idx)
{
    if ( ioctl(evtchn_fd, EVTCHN_BIND, idx) != 0 )
        return -errno;
    
    return 0;
}

int 
xen_evtchn_unbind (int evtchn_fd, int idx)
{
    if ( ioctl(evtchn_fd, EVTCHN_UNBIND, idx) != 0 )
        return -errno;

    return 0;
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
