#include <err.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <xenctrl.h>

int main(int argc, char **argv)
{
    xc_interface *xch;
    int domid, port, rc;
    xc_evtchn_status_t status;

    domid = (argc > 1) ? strtol(argv[1], NULL, 10) : 0;

    xch = xc_interface_open(0,0,0);
    if ( !xch )
        errx(1, "failed to open control interface");

    for ( port = 0; ; port++ )
    {
        status.dom = domid;
        status.port = port;
        rc = xc_evtchn_status(xch, &status);
        if ( rc < 0 )
        {
            switch ( errno )
            {
            case EACCES: /* Xen-owned evtchn */
                continue;

            case EINVAL: /* Port enumeration has ended */
                rc = 0;
                break;

            default:
                perror("xc_evtchn_status");
                rc = 1;
                break;
            }
            goto out;
        }

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

 out:
    xc_interface_close(xch);

    return rc;
}
