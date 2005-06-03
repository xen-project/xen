/*
 * pdb_xen.c
 *
 * alex ho
 * http://www.cl.cam.ac.uk/netos/pdb
 *
 * PDB interface library for accessing Xen
 */

#include <xc.h>
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


int 
pdb_evtchn_bind_virq (int xc_handle, int virq, int *port)
{
    int rc;
    
    if ( (rc = xc_evtchn_bind_virq(xc_handle, virq, port) < 0 ) )
    {
        fprintf(stderr, "(pdb) error binding virq to event channel: %d (%s)\n",
                errno, strerror(errno));
    }
    return rc;
}


#include <sys/ioctl.h>

/* /dev/xen/evtchn ioctls */
#define EVTCHN_RESET  _IO('E', 1)                   /* clear & reinit buffer */
#define EVTCHN_BIND   _IO('E', 2)                   /* bind to event channel */
#define EVTCHN_UNBIND _IO('E', 3)               /* unbind from event channel */

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
