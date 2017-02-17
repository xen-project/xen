/*
 * xen-lowmemd: demo VIRQ_ENOMEM
 * Andres Lagar-Cavilla (GridCentric Inc.)
 */

#include <stdio.h>
#include <xenevtchn.h>
#include <xenctrl.h>
#include <xenstore.h>
#include <stdlib.h>
#include <string.h>

static evtchn_port_t virq_port      = ~0;
static xenevtchn_handle *xce_handle = NULL;
static xc_interface *xch            = NULL;
static struct xs_handle *xs_handle  = NULL;

void cleanup(void)
{
    if (virq_port != ~0)
        xenevtchn_unbind(xce_handle, virq_port);
    if (xce_handle)
        xenevtchn_close(xce_handle);
    if (xch)
        xc_interface_close(xch);
    if (xs_handle)
        xs_daemon_close(xs_handle);
}

/* Never shrink dom0 below 1 GiB */
#define DOM0_FLOOR  (1 << 30)
#define DOM0_FLOOR_PG   ((DOM0_FLOOR) >> 12)

/* Act if free memory is less than 92 MiB */
#define THRESHOLD   (92 << 20)
#define THRESHOLD_PG    ((THRESHOLD) >> 12)

#define BUFSZ 512
void handle_low_mem(void)
{
    xc_dominfo_t  dom0_info;
    xc_physinfo_t info;
    unsigned long long free_pages, dom0_pages, diff, dom0_target;
    char data[BUFSZ], error[BUFSZ];

    if (xc_physinfo(xch, &info) < 0)
    {
        perror("Getting physinfo failed");
        return;
    }

    free_pages = (unsigned long long) info.free_pages;
    printf("Available free pages: 0x%llx:%llux\n",
            free_pages, free_pages);

    /* Don't do anything if we have more than the threshold free */
    if ( free_pages >= THRESHOLD_PG )
        return;
    diff = THRESHOLD_PG - free_pages; 

    if (xc_domain_getinfo(xch, 0, 1, &dom0_info) < 1)
    {
        perror("Failed to get dom0 info");
        return;
    }

    dom0_pages = (unsigned long long) dom0_info.nr_pages;
    printf("Dom0 pages: 0x%llx:%llu\n", dom0_pages, dom0_pages);
    dom0_target = dom0_pages - diff;
    if (dom0_target <= DOM0_FLOOR_PG)
        return;

    printf("Shooting for dom0 target 0x%llx:%llu\n", 
            dom0_target, dom0_target);

    snprintf(data, BUFSZ, "%llu", dom0_target);
    if (!xs_write(xs_handle, XBT_NULL, 
            "/local/domain/0/memory/target", data, strlen(data)))
    {
        snprintf(error, BUFSZ,"Failed to write target %s to xenstore", data);
        perror(error);
    }
}

int main(int argc, char *argv[])
{
    int rc;

    atexit(cleanup);

	xch = xc_interface_open(NULL, NULL, 0);
	if (xch == NULL)
    {
        perror("Failed to open xc interface");
        return 1;
    }

	xce_handle = xenevtchn_open(NULL, 0);
	if (xce_handle == NULL)
    {
        perror("Failed to open evtchn device");
        return 2;
    }

    xs_handle = xs_daemon_open();
    if (xs_handle == NULL)
    {
        perror("Failed to open xenstore connection");
        return 3;
    }

	if ((rc = xenevtchn_bind_virq(xce_handle, VIRQ_ENOMEM)) == -1)
    {
        perror("Failed to bind to domain exception virq port");
        return 4;
    }

    virq_port = rc;
    
    while(1)
    {
        evtchn_port_t port;

        if ((port = xenevtchn_pending(xce_handle)) == -1)
        {
            perror("Failed to listen for pending event channel");
            return 5;
        }

        if (port != virq_port)
        {
            char data[BUFSZ];
            snprintf(data, BUFSZ, "Wrong port, got %d expected %d", port, virq_port);
            perror(data);
            return 6;
        }

        if (xenevtchn_unmask(xce_handle, port) == -1)
        {
            perror("Failed to unmask port");
            return 7;
        }

        printf("Got a virq kick, time to get work\n");
        handle_low_mem();
    }

    return 0;
}
