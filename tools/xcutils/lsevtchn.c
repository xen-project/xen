#include <err.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <xs.h>
#include <xenctrl.h>
#include <xenguest.h>

int
main(int argc, char **argv)
{
    int xc_fd;
    int domid = 0, port = 0, status;
    const char *msg;

    if ( argc > 1 )
        domid = strtol(argv[1], NULL, 10);

    xc_fd = xc_interface_open();
    if ( xc_fd < 0 )
        errx(1, "failed to open control interface");

    while ( (status = xc_evtchn_status(xc_fd, domid, port)) >= 0 )
    {
        switch ( status )
        {
        case EVTCHNSTAT_closed:
            msg = "Channel is not in use.";
            break;
        case EVTCHNSTAT_unbound:
            msg = "Channel is waiting interdom connection.";
            break;
        case EVTCHNSTAT_interdomain:
            msg = "Channel is connected to remote domain.";
            break;
        case EVTCHNSTAT_pirq:
            msg = "Channel is bound to a phys IRQ line.";
            break;
        case EVTCHNSTAT_virq:
            msg = "Channel is bound to a virtual IRQ line.";
            break;
        case EVTCHNSTAT_ipi:
            msg = "Channel is bound to a virtual IPI line.";
            break;
        default:
            msg = "Unknown.";
            break;

        }
        printf("%03d: %d: %s\n", port, status, msg);
        port++;
    }

    xc_interface_close(xc_fd);

    return 0;
}
