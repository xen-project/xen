/*
 * xen-access.c
 *
 * Exercises the basic per-page access mechanisms
 *
 * Copyright (c) 2011 Virtuata, Inc.
 * Copyright (c) 2009 by Citrix Systems, Inc. (Patrick Colp), based on
 *   xenpaging.c
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <poll.h>

#include <xenctrl.h>
#include <xenevtchn.h>
#include <xen/vm_event.h>

#if defined(__arm__) || defined(__aarch64__)
#include <xen/arch-arm.h>
#define START_PFN (GUEST_RAM0_BASE >> 12)
#elif defined(__i386__) || defined(__x86_64__)
#define START_PFN 0ULL
#endif

#define DPRINTF(a, b...) fprintf(stderr, a, ## b)
#define ERROR(a, b...) fprintf(stderr, a "\n", ## b)
#define PERROR(a, b...) fprintf(stderr, a ": %s\n", ## b, strerror(errno))

/* From xen/include/asm-x86/processor.h */
#define X86_TRAP_DEBUG  1
#define X86_TRAP_INT3   3

/* From xen/include/asm-x86/x86-defns.h */
#define X86_CR4_PGE        0x00000080 /* enable global pages */

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

typedef struct vm_event {
    domid_t domain_id;
    xenevtchn_handle *xce_handle;
    int port;
    vm_event_back_ring_t back_ring;
    uint32_t evtchn_port;
    void *ring_page;
} vm_event_t;

typedef struct xenaccess {
    xc_interface *xc_handle;

    xen_pfn_t max_gpfn;

    vm_event_t vm_event;
} xenaccess_t;

static int interrupted;
bool evtchn_bind = 0, evtchn_open = 0, mem_access_enable = 0;

static void close_handler(int sig)
{
    interrupted = sig;
}

int xc_wait_for_event_or_timeout(xc_interface *xch, xenevtchn_handle *xce, unsigned long ms)
{
    struct pollfd fd = { .fd = xenevtchn_fd(xce), .events = POLLIN | POLLERR };
    int port;
    int rc;

    rc = poll(&fd, 1, ms);
    if ( rc == -1 )
    {
        if (errno == EINTR)
            return 0;

        ERROR("Poll exited with an error");
        goto err;
    }

    if ( rc == 1 )
    {
        port = xenevtchn_pending(xce);
        if ( port == -1 )
        {
            ERROR("Failed to read port from event channel");
            goto err;
        }

        rc = xenevtchn_unmask(xce, port);
        if ( rc != 0 )
        {
            ERROR("Failed to unmask event channel port");
            goto err;
        }
    }
    else
        port = -1;

    return port;

 err:
    return -errno;
}

int xenaccess_teardown(xc_interface *xch, xenaccess_t *xenaccess)
{
    int rc;

    if ( xenaccess == NULL )
        return 0;

    /* Tear down domain xenaccess in Xen */
    if ( xenaccess->vm_event.ring_page )
        munmap(xenaccess->vm_event.ring_page, XC_PAGE_SIZE);

    if ( mem_access_enable )
    {
        rc = xc_monitor_disable(xenaccess->xc_handle,
                                xenaccess->vm_event.domain_id);
        if ( rc != 0 )
        {
            ERROR("Error tearing down domain xenaccess in xen");
            return rc;
        }
    }

    /* Unbind VIRQ */
    if ( evtchn_bind )
    {
        rc = xenevtchn_unbind(xenaccess->vm_event.xce_handle,
                              xenaccess->vm_event.port);
        if ( rc != 0 )
        {
            ERROR("Error unbinding event port");
            return rc;
        }
    }

    /* Close event channel */
    if ( evtchn_open )
    {
        rc = xenevtchn_close(xenaccess->vm_event.xce_handle);
        if ( rc != 0 )
        {
            ERROR("Error closing event channel");
            return rc;
        }
    }

    /* Close connection to Xen */
    rc = xc_interface_close(xenaccess->xc_handle);
    if ( rc != 0 )
    {
        ERROR("Error closing connection to xen");
        return rc;
    }
    xenaccess->xc_handle = NULL;

    free(xenaccess);

    return 0;
}

xenaccess_t *xenaccess_init(xc_interface **xch_r, domid_t domain_id)
{
    xenaccess_t *xenaccess = 0;
    xc_interface *xch;
    int rc;

    xch = xc_interface_open(NULL, NULL, 0);
    if ( !xch )
        goto err_iface;

    DPRINTF("xenaccess init\n");
    *xch_r = xch;

    /* Allocate memory */
    xenaccess = malloc(sizeof(xenaccess_t));
    memset(xenaccess, 0, sizeof(xenaccess_t));

    /* Open connection to xen */
    xenaccess->xc_handle = xch;

    /* Set domain id */
    xenaccess->vm_event.domain_id = domain_id;

    /* Enable mem_access */
    xenaccess->vm_event.ring_page =
            xc_monitor_enable(xenaccess->xc_handle,
                              xenaccess->vm_event.domain_id,
                              &xenaccess->vm_event.evtchn_port);
    if ( xenaccess->vm_event.ring_page == NULL )
    {
        switch ( errno ) {
            case EBUSY:
                ERROR("xenaccess is (or was) active on this domain");
                break;
            case ENODEV:
                ERROR("EPT not supported for this guest");
                break;
            default:
                perror("Error enabling mem_access");
                break;
        }
        goto err;
    }
    mem_access_enable = 1;

    /* Open event channel */
    xenaccess->vm_event.xce_handle = xenevtchn_open(NULL, 0);
    if ( xenaccess->vm_event.xce_handle == NULL )
    {
        ERROR("Failed to open event channel");
        goto err;
    }
    evtchn_open = 1;

    /* Bind event notification */
    rc = xenevtchn_bind_interdomain(xenaccess->vm_event.xce_handle,
                                    xenaccess->vm_event.domain_id,
                                    xenaccess->vm_event.evtchn_port);
    if ( rc < 0 )
    {
        ERROR("Failed to bind event channel");
        goto err;
    }
    evtchn_bind = 1;
    xenaccess->vm_event.port = rc;

    /* Initialise ring */
    SHARED_RING_INIT((vm_event_sring_t *)xenaccess->vm_event.ring_page);
    BACK_RING_INIT(&xenaccess->vm_event.back_ring,
                   (vm_event_sring_t *)xenaccess->vm_event.ring_page,
                   XC_PAGE_SIZE);

    /* Get max_gpfn */
    rc = xc_domain_maximum_gpfn(xenaccess->xc_handle,
                                xenaccess->vm_event.domain_id,
                                &xenaccess->max_gpfn);

    if ( rc )
    {
        ERROR("Failed to get max gpfn");
        goto err;
    }

    DPRINTF("max_gpfn = %"PRI_xen_pfn"\n", xenaccess->max_gpfn);

    return xenaccess;

 err:
    rc = xenaccess_teardown(xch, xenaccess);
    if ( rc )
    {
        ERROR("Failed to teardown xenaccess structure!\n");
    }

 err_iface:
    return NULL;
}

static inline
int control_singlestep(
    xc_interface *xch,
    domid_t domain_id,
    unsigned long vcpu,
    bool enable)
{
    uint32_t op = enable ?
        XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON : XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_OFF;

    return xc_domain_debug_control(xch, domain_id, op, vcpu);
}

/*
 * Note that this function is not thread safe.
 */
static void get_request(vm_event_t *vm_event, vm_event_request_t *req)
{
    vm_event_back_ring_t *back_ring;
    RING_IDX req_cons;

    back_ring = &vm_event->back_ring;
    req_cons = back_ring->req_cons;

    /* Copy request */
    memcpy(req, RING_GET_REQUEST(back_ring, req_cons), sizeof(*req));
    req_cons++;

    /* Update ring */
    back_ring->req_cons = req_cons;
    back_ring->sring->req_event = req_cons + 1;
}

/*
 * X86 control register names
 */
static const char* get_x86_ctrl_reg_name(uint32_t index)
{
    static const char* names[] = {
        [VM_EVENT_X86_CR0]  = "CR0",
        [VM_EVENT_X86_CR3]  = "CR3",
        [VM_EVENT_X86_CR4]  = "CR4",
        [VM_EVENT_X86_XCR0] = "XCR0",
    };

    if ( index >= ARRAY_SIZE(names) || names[index] == NULL )
        return "";

    return names[index];
}

/*
 * Note that this function is not thread safe.
 */
static void put_response(vm_event_t *vm_event, vm_event_response_t *rsp)
{
    vm_event_back_ring_t *back_ring;
    RING_IDX rsp_prod;

    back_ring = &vm_event->back_ring;
    rsp_prod = back_ring->rsp_prod_pvt;

    /* Copy response */
    memcpy(RING_GET_RESPONSE(back_ring, rsp_prod), rsp, sizeof(*rsp));
    rsp_prod++;

    /* Update ring */
    back_ring->rsp_prod_pvt = rsp_prod;
    RING_PUSH_RESPONSES(back_ring);
}

void usage(char* progname)
{
    fprintf(stderr, "Usage: %s [-m] <domain_id> write|exec", progname);
#if defined(__i386__) || defined(__x86_64__)
            fprintf(stderr, "|breakpoint|altp2m_write|altp2m_exec|debug|cpuid|desc_access|write_ctrlreg_cr4");
#elif defined(__arm__) || defined(__aarch64__)
            fprintf(stderr, "|privcall");
#endif
            fprintf(stderr,
            "\n"
            "Logs first page writes, execs, or breakpoint traps that occur on the domain.\n"
            "\n"
            "-m requires this program to run, or else the domain may pause\n");
}

int main(int argc, char *argv[])
{
    struct sigaction act;
    domid_t domain_id;
    xenaccess_t *xenaccess;
    vm_event_request_t req;
    vm_event_response_t rsp;
    int rc = -1;
    int rc1;
    xc_interface *xch;
    xenmem_access_t default_access = XENMEM_access_rwx;
    xenmem_access_t after_first_access = XENMEM_access_rwx;
    int memaccess = 0;
    int required = 0;
    int breakpoint = 0;
    int shutting_down = 0;
    int privcall = 0;
    int altp2m = 0;
    int debug = 0;
    int cpuid = 0;
    int desc_access = 0;
    int write_ctrlreg_cr4 = 0;
    uint16_t altp2m_view_id = 0;

    char* progname = argv[0];
    argv++;
    argc--;

    if ( argc == 3 && argv[0][0] == '-' )
    {
        if ( !strcmp(argv[0], "-m") )
            required = 1;
        else
        {
            usage(progname);
            return -1;
        }
        argv++;
        argc--;
    }

    if ( argc != 2 )
    {
        usage(progname);
        return -1;
    }

    domain_id = atoi(argv[0]);
    argv++;
    argc--;

    if ( !strcmp(argv[0], "write") )
    {
        default_access = XENMEM_access_rx;
        after_first_access = XENMEM_access_rwx;
        memaccess = 1;
    }
    else if ( !strcmp(argv[0], "exec") )
    {
        default_access = XENMEM_access_rw;
        after_first_access = XENMEM_access_rwx;
        memaccess = 1;
    }
#if defined(__i386__) || defined(__x86_64__)
    else if ( !strcmp(argv[0], "breakpoint") )
    {
        breakpoint = 1;
    }
    else if ( !strcmp(argv[0], "altp2m_write") )
    {
        default_access = XENMEM_access_rx;
        altp2m = 1;
        memaccess = 1;
    }
    else if ( !strcmp(argv[0], "altp2m_exec") )
    {
        default_access = XENMEM_access_rw;
        altp2m = 1;
        memaccess = 1;
    }
    else if ( !strcmp(argv[0], "debug") )
    {
        debug = 1;
    }
    else if ( !strcmp(argv[0], "cpuid") )
    {
        cpuid = 1;
    }
    else if ( !strcmp(argv[0], "desc_access") )
    {
        desc_access = 1;
    }
    else if ( !strcmp(argv[0], "write_ctrlreg_cr4") )
    {
        write_ctrlreg_cr4 = 1;
    }
#elif defined(__arm__) || defined(__aarch64__)
    else if ( !strcmp(argv[0], "privcall") )
    {
        privcall = 1;
    }
#endif
    else
    {
        usage(argv[0]);
        return -1;
    }

    xenaccess = xenaccess_init(&xch, domain_id);
    if ( xenaccess == NULL )
    {
        ERROR("Error initialising xenaccess");
        return 1;
    }

    DPRINTF("starting %s %u\n", argv[0], domain_id);

    /* ensure that if we get a signal, we'll do cleanup, then exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    /* Set whether the access listener is required */
    rc = xc_domain_set_access_required(xch, domain_id, required);
    if ( rc < 0 )
    {
        ERROR("Error %d setting mem_access listener required\n", rc);
        goto exit;
    }

    /* With altp2m we just create a new, restricted view of the memory */
    if ( memaccess && altp2m )
    {
        xen_pfn_t gfn = 0;
        unsigned long perm_set = 0;

        rc = xc_altp2m_set_domain_state( xch, domain_id, 1 );
        if ( rc < 0 )
        {
            ERROR("Error %d enabling altp2m on domain!\n", rc);
            goto exit;
        }

        rc = xc_altp2m_create_view( xch, domain_id, default_access, &altp2m_view_id );
        if ( rc < 0 )
        {
            ERROR("Error %d creating altp2m view!\n", rc);
            goto exit;
        }

        DPRINTF("altp2m view created with id %u\n", altp2m_view_id);
        DPRINTF("Setting altp2m mem_access permissions.. ");

        for(; gfn < xenaccess->max_gpfn; ++gfn)
        {
            rc = xc_altp2m_set_mem_access( xch, domain_id, altp2m_view_id, gfn,
                                           default_access);
            if ( !rc )
                perm_set++;
        }

        DPRINTF("done! Permissions set on %lu pages.\n", perm_set);

        rc = xc_altp2m_switch_to_view( xch, domain_id, altp2m_view_id );
        if ( rc < 0 )
        {
            ERROR("Error %d switching to altp2m view!\n", rc);
            goto exit;
        }

        rc = xc_monitor_singlestep( xch, domain_id, 1 );
        if ( rc < 0 )
        {
            ERROR("Error %d failed to enable singlestep monitoring!\n", rc);
            goto exit;
        }
    }

    if ( memaccess && !altp2m )
    {
        /* Set the default access type and convert all pages to it */
        rc = xc_set_mem_access(xch, domain_id, default_access, ~0ull, 0);
        if ( rc < 0 )
        {
            ERROR("Error %d setting default mem access type\n", rc);
            goto exit;
        }

        rc = xc_set_mem_access(xch, domain_id, default_access, START_PFN,
                               (xenaccess->max_gpfn - START_PFN) );

        if ( rc < 0 )
        {
            ERROR("Error %d setting all memory to access type %d\n", rc,
                  default_access);
            goto exit;
        }
    }

    if ( breakpoint )
    {
        rc = xc_monitor_software_breakpoint(xch, domain_id, 1);
        if ( rc < 0 )
        {
            ERROR("Error %d setting breakpoint trapping with vm_event\n", rc);
            goto exit;
        }
    }

    if ( debug )
    {
        rc = xc_monitor_debug_exceptions(xch, domain_id, 1, 1);
        if ( rc < 0 )
        {
            ERROR("Error %d setting debug exception listener with vm_event\n", rc);
            goto exit;
        }
    }

    if ( cpuid )
    {
        rc = xc_monitor_cpuid(xch, domain_id, 1);
        if ( rc < 0 )
        {
            ERROR("Error %d setting cpuid listener with vm_event\n", rc);
            goto exit;
        }
    }

    if ( desc_access )
    {
        rc = xc_monitor_descriptor_access(xch, domain_id, 1);
        if ( rc < 0 )
        {
            ERROR("Error %d setting descriptor access listener with vm_event\n", rc);
            goto exit;
        }
    }

    if ( privcall )
    {
        rc = xc_monitor_privileged_call(xch, domain_id, 1);
        if ( rc < 0 )
        {
            ERROR("Error %d setting privileged call trapping with vm_event\n", rc);
            goto exit;
        }
    }

    if ( write_ctrlreg_cr4 )
    {
        /* Mask the CR4.PGE bit so no events will be generated for global TLB flushes. */
        rc = xc_monitor_write_ctrlreg(xch, domain_id, VM_EVENT_X86_CR4, 1, 1,
                                      X86_CR4_PGE, 1);
        if ( rc < 0 )
        {
            ERROR("Error %d setting write control register trapping with vm_event\n", rc);
            goto exit;
        }
    }

    /* Wait for access */
    for (;;)
    {
        if ( interrupted )
        {
            /* Unregister for every event */
            DPRINTF("xenaccess shutting down on signal %d\n", interrupted);

            if ( breakpoint )
                rc = xc_monitor_software_breakpoint(xch, domain_id, 0);
            if ( debug )
                rc = xc_monitor_debug_exceptions(xch, domain_id, 0, 0);
            if ( cpuid )
                rc = xc_monitor_cpuid(xch, domain_id, 0);
            if ( desc_access )
                rc = xc_monitor_descriptor_access(xch, domain_id, 0);

            if ( privcall )
                rc = xc_monitor_privileged_call(xch, domain_id, 0);

            if ( altp2m )
            {
                rc = xc_altp2m_switch_to_view( xch, domain_id, 0 );
                rc = xc_altp2m_destroy_view(xch, domain_id, altp2m_view_id);
                rc = xc_altp2m_set_domain_state(xch, domain_id, 0);
                rc = xc_monitor_singlestep(xch, domain_id, 0);
            } else {
                rc = xc_set_mem_access(xch, domain_id, XENMEM_access_rwx, ~0ull, 0);
                rc = xc_set_mem_access(xch, domain_id, XENMEM_access_rwx, START_PFN,
                                       (xenaccess->max_gpfn - START_PFN) );
            }

            shutting_down = 1;
        }

        rc = xc_wait_for_event_or_timeout(xch, xenaccess->vm_event.xce_handle, 100);
        if ( rc < -1 )
        {
            ERROR("Error getting event");
            interrupted = -1;
            continue;
        }
        else if ( rc != -1 )
        {
            DPRINTF("Got event from Xen\n");
        }

        while ( RING_HAS_UNCONSUMED_REQUESTS(&xenaccess->vm_event.back_ring) )
        {
            get_request(&xenaccess->vm_event, &req);

            if ( req.version != VM_EVENT_INTERFACE_VERSION )
            {
                ERROR("Error: vm_event interface version mismatch!\n");
                interrupted = -1;
                continue;
            }

            memset( &rsp, 0, sizeof (rsp) );
            rsp.version = VM_EVENT_INTERFACE_VERSION;
            rsp.vcpu_id = req.vcpu_id;
            rsp.flags = (req.flags & VM_EVENT_FLAG_VCPU_PAUSED);
            rsp.reason = req.reason;

            switch (req.reason) {
            case VM_EVENT_REASON_MEM_ACCESS:
                if ( !shutting_down )
                {
                    /*
                     * This serves no other purpose here then demonstrating the use of the API.
                     * At shutdown we have already reset all the permissions so really no use getting it again.
                     */
                    xenmem_access_t access;
                    rc = xc_get_mem_access(xch, domain_id, req.u.mem_access.gfn, &access);
                    if (rc < 0)
                    {
                        ERROR("Error %d getting mem_access event\n", rc);
                        interrupted = -1;
                        continue;
                    }
                }

                printf("PAGE ACCESS: %c%c%c for GFN %"PRIx64" (offset %06"
                       PRIx64") gla %016"PRIx64" (valid: %c; fault in gpt: %c; fault with gla: %c) (vcpu %u [%c], altp2m view %u)\n",
                       (req.u.mem_access.flags & MEM_ACCESS_R) ? 'r' : '-',
                       (req.u.mem_access.flags & MEM_ACCESS_W) ? 'w' : '-',
                       (req.u.mem_access.flags & MEM_ACCESS_X) ? 'x' : '-',
                       req.u.mem_access.gfn,
                       req.u.mem_access.offset,
                       req.u.mem_access.gla,
                       (req.u.mem_access.flags & MEM_ACCESS_GLA_VALID) ? 'y' : 'n',
                       (req.u.mem_access.flags & MEM_ACCESS_FAULT_IN_GPT) ? 'y' : 'n',
                       (req.u.mem_access.flags & MEM_ACCESS_FAULT_WITH_GLA) ? 'y': 'n',
                       req.vcpu_id,
                       (req.flags & VM_EVENT_FLAG_VCPU_PAUSED) ? 'p' : 'r',
                       req.altp2m_idx);

                if ( altp2m && req.flags & VM_EVENT_FLAG_ALTERNATE_P2M)
                {
                    DPRINTF("\tSwitching back to default view!\n");

                    rsp.flags |= (VM_EVENT_FLAG_ALTERNATE_P2M | VM_EVENT_FLAG_TOGGLE_SINGLESTEP);
                    rsp.altp2m_idx = 0;
                }
                else if ( default_access != after_first_access )
                {
                    rc = xc_set_mem_access(xch, domain_id, after_first_access,
                                           req.u.mem_access.gfn, 1);
                    if (rc < 0)
                    {
                        ERROR("Error %d setting gfn to access_type %d\n", rc,
                              after_first_access);
                        interrupted = -1;
                        continue;
                    }
                }

                rsp.u.mem_access = req.u.mem_access;
                break;
            case VM_EVENT_REASON_SOFTWARE_BREAKPOINT:
                printf("Breakpoint: rip=%016"PRIx64", gfn=%"PRIx64" (vcpu %d)\n",
                       req.data.regs.x86.rip,
                       req.u.software_breakpoint.gfn,
                       req.vcpu_id);

                /* Reinject */
                rc = xc_hvm_inject_trap(xch, domain_id, req.vcpu_id,
                                        X86_TRAP_INT3,
                                        req.u.software_breakpoint.type, -1,
                                        req.u.software_breakpoint.insn_length, 0);
                if (rc < 0)
                {
                    ERROR("Error %d injecting breakpoint\n", rc);
                    interrupted = -1;
                    continue;
                }
                break;
            case VM_EVENT_REASON_PRIVILEGED_CALL:
                printf("Privileged call: pc=%"PRIx64" (vcpu %d)\n",
                       req.data.regs.arm.pc,
                       req.vcpu_id);

                rsp.data.regs.arm = req.data.regs.arm;
                rsp.data.regs.arm.pc += 4;
                rsp.flags |= VM_EVENT_FLAG_SET_REGISTERS;
                break;
            case VM_EVENT_REASON_SINGLESTEP:
                printf("Singlestep: rip=%016"PRIx64", vcpu %d, altp2m %u\n",
                       req.data.regs.x86.rip,
                       req.vcpu_id,
                       req.altp2m_idx);

                if ( altp2m )
                {
                    printf("\tSwitching altp2m to view %u!\n", altp2m_view_id);

                    rsp.flags |= VM_EVENT_FLAG_ALTERNATE_P2M;
                    rsp.altp2m_idx = altp2m_view_id;
                }

                rsp.flags |= VM_EVENT_FLAG_TOGGLE_SINGLESTEP;

                break;
            case VM_EVENT_REASON_DEBUG_EXCEPTION:
                printf("Debug exception: rip=%016"PRIx64", vcpu %d. Type: %u. Length: %u\n",
                       req.data.regs.x86.rip,
                       req.vcpu_id,
                       req.u.debug_exception.type,
                       req.u.debug_exception.insn_length);

                /* Reinject */
                rc = xc_hvm_inject_trap(xch, domain_id, req.vcpu_id,
                                        X86_TRAP_DEBUG,
                                        req.u.debug_exception.type, -1,
                                        req.u.debug_exception.insn_length,
                                        req.data.regs.x86.cr2);
                if (rc < 0)
                {
                    ERROR("Error %d injecting breakpoint\n", rc);
                    interrupted = -1;
                    continue;
                }

                break;
            case VM_EVENT_REASON_CPUID:
                printf("CPUID executed: rip=%016"PRIx64", vcpu %d. Insn length: %"PRIu32" " \
                       "0x%"PRIx32" 0x%"PRIx32": EAX=0x%"PRIx64" EBX=0x%"PRIx64" ECX=0x%"PRIx64" EDX=0x%"PRIx64"\n",
                       req.data.regs.x86.rip,
                       req.vcpu_id,
                       req.u.cpuid.insn_length,
                       req.u.cpuid.leaf,
                       req.u.cpuid.subleaf,
                       req.data.regs.x86.rax,
                       req.data.regs.x86.rbx,
                       req.data.regs.x86.rcx,
                       req.data.regs.x86.rdx);
                rsp.flags |= VM_EVENT_FLAG_SET_REGISTERS;
                rsp.data = req.data;
                rsp.data.regs.x86.rip += req.u.cpuid.insn_length;
                break;
            case VM_EVENT_REASON_DESCRIPTOR_ACCESS:
                printf("Descriptor access: rip=%016"PRIx64", vcpu %d: "\
                       "VMExit info=0x%"PRIx32", descriptor=%d, is write=%d\n",
                       req.data.regs.x86.rip,
                       req.vcpu_id,
                       req.u.desc_access.arch.vmx.instr_info,
                       req.u.desc_access.descriptor,
                       req.u.desc_access.is_write);
                rsp.flags |= VM_EVENT_FLAG_EMULATE;
                break;
            case VM_EVENT_REASON_WRITE_CTRLREG:
                printf("Control register written: rip=%016"PRIx64", vcpu %d: "
                       "reg=%s, old_value=%016"PRIx64", new_value=%016"PRIx64"\n",
                       req.data.regs.x86.rip,
                       req.vcpu_id,
                       get_x86_ctrl_reg_name(req.u.write_ctrlreg.index),
                       req.u.write_ctrlreg.old_value,
                       req.u.write_ctrlreg.new_value);
                break;
            default:
                fprintf(stderr, "UNKNOWN REASON CODE %d\n", req.reason);
            }

            /* Put the response on the ring */
            put_response(&xenaccess->vm_event, &rsp);
        }

        /* Tell Xen page is ready */
        rc = xenevtchn_notify(xenaccess->vm_event.xce_handle,
                              xenaccess->vm_event.port);

        if ( rc != 0 )
        {
            ERROR("Error resuming page");
            interrupted = -1;
        }

        if ( shutting_down )
            break;
    }
    DPRINTF("xenaccess shut down on signal %d\n", interrupted);

exit:
    if ( altp2m )
    {
        uint32_t vcpu_id;
        for ( vcpu_id = 0; vcpu_id<XEN_LEGACY_MAX_VCPUS; vcpu_id++)
            rc = control_singlestep(xch, domain_id, vcpu_id, 0);
    }

    /* Tear down domain xenaccess */
    rc1 = xenaccess_teardown(xch, xenaccess);
    if ( rc1 != 0 )
        ERROR("Error tearing down xenaccess");

    if ( rc == 0 )
        rc = rc1;

    DPRINTF("xenaccess exit code %d\n", rc);
    return rc;
}


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
