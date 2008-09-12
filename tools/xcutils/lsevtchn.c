#include <err.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <xs.h>
#include <xenctrl.h>
#include <xenguest.h>

int main(int argc, char **argv)
{
    int xc_fd, domid, port, rc;
    xc_evtchn_status_t status;

    domid = (argc > 1) ? strtol(argv[1], NULL, 10) : 0;

    xc_fd = xc_interface_open();
    if ( xc_fd < 0 )
        errx(1, "failed to open control interface");

    for ( port = 0; ; port++ )
    {
        status.dom = domid;
        status.port = port;
        rc = xc_evtchn_status(xc_fd, &status);
        if ( rc < 0 )
            break;

        if ( status.status == EVTCHNSTAT_closed )
            continue;

        printf("%4d: VCPU %u: ", port, status.vcpu);

        switch ( status.status )
        {
        case EVTCHNSTAT_unbound:
            printf("Interdomain (Waiting connection) - Remote Domain %u",
                   status.u.unbound.dom);
            break;
        case EVTCHNSTAT_interdomain:
            printf("Interdomain (Connected) - Remote Domain %u, Port %u",
                   status.u.interdomain.dom, status.u.interdomain.port);
            break;
        case EVTCHNSTAT_pirq:
            printf("Physical IRQ %u", status.u.pirq);
            break;
        case EVTCHNSTAT_virq:
            printf("Virtual IRQ %u", status.u.virq);
            break;
        case EVTCHNSTAT_ipi:
            printf("IPI");
            break;
        default:
            printf("Unknown");
            break;
        }

        printf("\n");
    }

    xc_interface_close(xc_fd);

    return 0;
}
