/*
 * Copyright (C) 2009, Mukesh Rathor, Oracle Corp.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

/* This is the main module to interface with xen. This module exports APIs that
 * allow for creating any remote debugger plugin. The APIs are:
 *
 *  xg_init() : initialize
 *  xg_attach(): attach to the given guest, preparing it for debug
 *  xg_detach_deinit(): exit debugging
 *
 *  xg_step() : single step the the given vcpu 
 *  xg_resume_n_wait(): resume the target guest and wait for any debug event
 *  xg_regs_read(): read context of given vcpu
 *  xg_regs_write(): write context of given vcpu
 *  xg_read_mem(): read memory of guest at given VA
 *  xg_write_mem(): write memory of guest at given VA
 *
 *  XGERR(): generic print error utility
 *  XGTRC(): generic trace utility
 */

#include <sys/types.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "xg_public.h"
#include <xen/version.h>
#include <xen/domctl.h>
#include <xen/sys/privcmd.h>
#include <xen/foreign/x86_32.h>
#include <xen/foreign/x86_64.h>

#define XGMIN(x,y) (((x)<(y))?(x):(y))

#define X86_EFLAGS_TF   0x00000100               /* Trap Flag */


/* 
 * Contexts returned by xen:  (gdbsx : dom 0 : hypervisor)
 *
 *   32 : 32 : 32 => 64bit context never returned. can't run 64bit guests
 *   32 : 32 : 64 => 32bit ctxt for 32bit PV guest. 64bit ctxt for 64 PV guests.
 *                   HVM always 64bit ctxt.
 *   32 : 64 : 64 =>      N/A
 *   64 : 64 : 64 => Same as 32:32:64 (CONFIG_COMPAT is almost always defined)
 *   64 : 64 : 64 => !CONFIG_COMPAT : not supported.
 */
typedef union vcpu_guest_context_any {
    vcpu_guest_context_x86_64_t ctxt64;
    vcpu_guest_context_x86_32_t ctxt32;
    vcpu_guest_context_t ctxt;
} vcpu_guest_context_any_t;


int xgtrc_on = 0;
struct xen_domctl domctl;         /* just use a global domctl */

static int     _hvm_guest;        /* hvm guest? 32bit HVMs have 64bit context */
static int     _pvh_guest;        /* PV guest in HVM container */
static domid_t _dom_id;           /* guest domid */
static int     _max_vcpu_id;      /* thus max_vcpu_id+1 VCPUs */
static int     _dom0_fd;          /* fd of /dev/privcmd */
static int     _32bit_hyp;        /* hyp is 32bit */


/* print trace info with function name pre-pended */
void
xgtrc(const char *fn, const char *fmt, ...)
{
    char buf[2048];
    va_list     args;

    fprintf(stderr, "%s:", fn);
    va_start(args, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    fprintf(stderr, "%s", buf);
    fflush (stderr);
}

/* print error msg with function name pre-pended */
void
xgprt(const char *fn, const char *fmt, ...)
{
    char buf[2048];
    va_list     args;

    fprintf(stderr, "ERROR:%s:", fn);
    va_start(args, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    fprintf (stderr, "%s", buf);
    fflush (stderr);
}


/*
 * Returns: 0 success
 *         -1 failure, errno set.
 */
int 
xg_init()
{
    int flags, saved_errno;

    XGTRC("E\n");
    if ((_dom0_fd=open("/proc/xen/privcmd", O_RDWR)) == -1) {
        perror("Failed to open /proc/xen/privcmd\n");
        return -1;
    }
    /* Although we return the file handle as the 'xc handle' the API
     * does not specify / guarentee that this integer is in fact
     * a file handle. Thus we must take responsiblity to ensure
     * it doesn't propagate (ie leak) outside the process (copied comment)*/
    if ( (flags=fcntl(_dom0_fd, F_GETFD)) < 0 ) {
        perror("Could not get file handle flags (F_GETFD)");
        goto error;
    }
    flags |= FD_CLOEXEC;
    if (fcntl(_dom0_fd, F_SETFD, flags) < 0) {
        perror("Could not set file handle flags");
        goto error;
    }

    XGTRC("X:fd:%d\n", _dom0_fd);
    return _dom0_fd;

 error:
    XGTRC("X:Error: errno:%d\n", errno);
    saved_errno = errno;
    close(_dom0_fd);
    errno = saved_errno;
    return -1;
}


/*
 * Precondition: domctl global struct must be filled 
 * Returns : 0 Success, failure otherwise with errno set
 */
static int
_domctl_hcall(uint32_t cmd,            /* which domctl hypercall */
              void *domctlarg,       /* arg/buf to domctl to pin in mem */
              int sz)                /* size of *domctlarg */
{
    privcmd_hypercall_t hypercall;
    int rc;

    if (domctlarg && sz && mlock(domctlarg, sz)) {
        XGERR("Unable to pin domctl arg. p:%p sz:%d errno:%d\n", 
              domctlarg, sz, errno);
        return 1;
    }
    domctl.cmd = cmd;
    hypercall.op = __HYPERVISOR_domctl;
    hypercall.arg[0] = (unsigned long)&domctl;

    rc = ioctl(_dom0_fd, IOCTL_PRIVCMD_HYPERCALL, &hypercall);
    if (domctlarg && sz)
        munlock(domctlarg, sz);
    return rc;
}

/* 
 * Make sure we are running on hyp enabled for gdbsx. Also, note whether
 * its 32bit. Fail if user typed 64bit for guest in case of 32bit hyp.
 *
 * RETURNS: 0 : everything OK. 
 */
static int
_check_hyp(int guest_bitness)
{
    xen_capabilities_info_t xen_caps = "";
    privcmd_hypercall_t hypercall;
    int rc;

    /*
     * Try to unpause an invalid vcpu. If hypervisor supports gdbsx then
     * this should fail with an error other than ENOSYS.
     */
    domctl.u.gdbsx_pauseunp_vcpu.vcpu = ~0u;
    (void)_domctl_hcall(XEN_DOMCTL_gdbsx_unpausevcpu, NULL, 0);
    if (errno == ENOSYS) {
        XGERR("Hyp is NOT enabled for gdbsx\n");
        return -1;
    } 

    if (mlock(&xen_caps, sizeof(xen_caps))) {
        XGERR("Unable to pin xen_caps in memory. errno:%d\n", errno);
        return -1;
    }
    memset(&xen_caps, 0, sizeof(xen_caps));

    hypercall.op = __HYPERVISOR_xen_version;
    hypercall.arg[0] = (unsigned long)XENVER_capabilities;
    hypercall.arg[1] = (unsigned long)&xen_caps;

    rc = ioctl(_dom0_fd, IOCTL_PRIVCMD_HYPERCALL, &hypercall);
    munlock(&xen_caps, sizeof(xen_caps));
    XGTRC("XENCAPS:%s\n", xen_caps);

    if (rc != 0) {
        XGERR("Failed xen_version hcall. errno:%d\n", errno);
        return -1;
    }

    _32bit_hyp = (strstr(xen_caps, "x86_64") == NULL);
    if (_32bit_hyp && guest_bitness !=32) {
        XGERR("32bit hyp can only run 32bit guests\n");
        return -1;
    }
    return 0;
}

/* check if domain is alive and well 
 * returns : 0 if domain is not alive and well
 */
static int
_domain_ok(struct xen_domctl_getdomaininfo *domp)
{
    int rc = 0;
    if (domp->flags & XEN_DOMINF_dying)
        XGERR("Invalid domain (state dying)...\n");
    else
        rc = 1;
    return rc;
}

/* Returns: 0 : success */
static int
_unpause_domain(void)
{
    memset(&domctl.u, 0, sizeof(domctl.u));
    if (_domctl_hcall(XEN_DOMCTL_unpausedomain, NULL, 0)) {
        XGERR("Unable to unpause domain:%d errno:%d\n", _dom_id, errno);
        return -1;
    } 
    return 0;
}

/*
 * Attach to the given domid for debugging.
 * Returns: max vcpu id : Success
 *                   -1 : Failure
 */
int 
xg_attach(int domid, int guest_bitness)
{
    XGTRC("E:domid:%d\n", domid);

    _dom_id = domctl.domain = domid;
    domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;

    if (mlock(&domctl, sizeof(domctl))) {
        XGERR("Unable to pin domctl in memory. errno:%d\n", errno);
        return -1;
    }
    if (_check_hyp(guest_bitness))
        return -1;

    if (_domctl_hcall(XEN_DOMCTL_pausedomain, NULL, 0)) {
        XGERR("Unable to pause domain:%d\n", _dom_id);
        return -1;
    } 

    memset(&domctl.u, 0, sizeof(domctl.u));
    domctl.u.setdebugging.enable = 1;
    if (_domctl_hcall(XEN_DOMCTL_setdebugging, NULL, 0)) {
        XGERR("Unable to set domain to debug mode: errno:%d\n", errno);
        _unpause_domain();
        return -1;
    }

    memset(&domctl.u, 0, sizeof(domctl.u));
    if (_domctl_hcall(XEN_DOMCTL_getdomaininfo, NULL, 0)) {
        XGERR("Unable to get domain info: domid:%d errno:%d\n", 
              domid, errno);
        _unpause_domain();
        return -1;
    }
    if (!_domain_ok(&domctl.u.getdomaininfo)) {
        _unpause_domain();
        return -1;
    }

    _max_vcpu_id = domctl.u.getdomaininfo.max_vcpu_id;
    _hvm_guest = (domctl.u.getdomaininfo.flags & XEN_DOMINF_hvm_guest);
    _pvh_guest = (domctl.u.getdomaininfo.flags & XEN_DOMINF_pvh_guest);
    return _max_vcpu_id;
}


/* Returns: 1 : domain is paused.  0 otherwise */
static int
_domain_is_paused(void)
{
    memset(&domctl.u, 0, sizeof(domctl.u));
    if (_domctl_hcall(XEN_DOMCTL_getdomaininfo, NULL, 0)) {
        XGERR("ERROR: Unable to get domain paused info:%d\n", _dom_id);
        return 0;
    } 
    return (domctl.u.getdomaininfo.flags & XEN_DOMINF_paused);
}

/* Detach from guest for debugger exit */
void
xg_detach_deinit(void)
{
    memset(&domctl.u, 0, sizeof(domctl.u));
    domctl.u.setdebugging.enable = 0;
    if (_domctl_hcall(XEN_DOMCTL_setdebugging, NULL, 0)) {
        XGERR("Unable to reset domain debug mode: errno:%d\n", errno);
    }
    if (_domain_is_paused()) 
        _unpause_domain();
        
    close(_dom0_fd);
}

/* 
 * Returns : 0 success. 
 *           1 error, with errno set (hopefully :))
 */
static int 
_wait_domain_pause(void)
{
    int dom_paused;
    struct timespec ts={0, 10*1000*1000};

    XGTRC("E:\n");
    do {
        dom_paused = _domain_is_paused();
        nanosleep(&ts, NULL);
    } while(!dom_paused);
    return 0;
}

/*
 * Change the TF flag for single step.   TF = (setit ? 1 : 0);
 * Returns: 0 Success
 */
static int
_change_TF(vcpuid_t which_vcpu, int guest_bitness, int setit)
{
    union vcpu_guest_context_any anyc;
    int sz = sizeof(anyc);

    /* first try the MTF for hvm guest. otherwise do manually */
    if (_hvm_guest || _pvh_guest) {
        domctl.u.debug_op.vcpu = which_vcpu;
        domctl.u.debug_op.op = setit ? XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON :
                                       XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_OFF;

        if (_domctl_hcall(XEN_DOMCTL_debug_op, NULL, 0) == 0) {
            XGTRC("vcpu:%d:MTF success setit:%d\n", which_vcpu, setit);
            return 0;
        }
        XGTRC("vcpu:%d:MTF failed. setit:%d\n", which_vcpu, setit);
    }

    memset(&anyc, 0, sz);
    domctl.u.vcpucontext.vcpu = (uint16_t)which_vcpu;
    set_xen_guest_handle(domctl.u.vcpucontext.ctxt, &anyc.ctxt);

    if (_domctl_hcall(XEN_DOMCTL_getvcpucontext, &anyc, sz)) {
        XGERR("Failed hcall to get vcpu ctxt for TF. errno:%d\n",errno);
        return 1;
    }
    if (_32bit_hyp || (guest_bitness == 32 && !_hvm_guest)) {
        if (setit)
            anyc.ctxt32.user_regs.eflags |= X86_EFLAGS_TF;
        else
            anyc.ctxt32.user_regs.eflags &= ~X86_EFLAGS_TF;
    } else {
        if (setit)
            anyc.ctxt64.user_regs.rflags |= X86_EFLAGS_TF;
        else
            anyc.ctxt64.user_regs.rflags &= ~X86_EFLAGS_TF;
    }

    if (_domctl_hcall(XEN_DOMCTL_setvcpucontext, &anyc, sz)) {
        XGERR("Failed hcall to set vcpu ctxt for TF. errno:%d\n",errno);
        return 1;
    }
    return 0;
}

/* Do the given DOMCTL hcall action(pause or unpause) on all but the given vcpu
 * Returns: 0 success */
static int
_allbutone_vcpu(uint32_t hcall, vcpuid_t which_vcpu)
{
    int i;
    for (i=0; i <= _max_vcpu_id; i++) {
        if (i == which_vcpu)
            continue;

        memset(&domctl.u, 0, sizeof(domctl.u));
        domctl.u.gdbsx_pauseunp_vcpu.vcpu = i;
        if (_domctl_hcall(hcall, NULL, 0)) {
            XGERR("Unable to do:%d vcpu:%d errno:%d\n", 
                  hcall, i, errno); 
            return 1;
        } 
    }
    return 0;
}

/*
 * Single step the given vcpu. This is achieved by pausing all but given vcpus,
 * setting the TF flag, let the domain run and pause, unpause all vcpus, and 
 * clear TF flag on given vcpu.
 * Returns: 0 success
 */
int 
xg_step(vcpuid_t which_vcpu, int guest_bitness)
{
    int rc;

    XGTRC("E:vcpu:%d\n", (int)which_vcpu);

    if (_allbutone_vcpu(XEN_DOMCTL_gdbsx_pausevcpu, which_vcpu))
        return 1;

    if ((rc=_change_TF(which_vcpu, guest_bitness, 1)))
        return rc;

    XGTRC("unpausing domain\n");

    /* now unpause the domain so our vcpu can execute */
    if (_unpause_domain())
        return 1;
         
    /* wait for our vcpu to finish step */
    _wait_domain_pause();

    _allbutone_vcpu(XEN_DOMCTL_gdbsx_unpausevcpu, which_vcpu);
    rc = _change_TF(which_vcpu, guest_bitness, 0);

    return rc;
}

/*
 * check if any one of the vcpus is in a breakpoint
 * Returns:      vcpuid   :  if a vcpu found in a bp
 *                    -1  : otherwise
 */
static vcpuid_t
_vcpu_in_bp(void)
{
    memset(&domctl.u, 0, sizeof(domctl.u));
    if (_domctl_hcall(XEN_DOMCTL_gdbsx_domstatus, NULL, 0)) {
        XGERR("ERROR: Unable to check vcpu bp status:%d errno:%d\n", 
              _dom_id, errno);
        return -1;
    } 
    return domctl.u.gdbsx_domstatus.vcpu_id;
}

/*
 * Resume the domain if no pending events. If there are pending events, like
 * another vcpu in a BP, report it. Otherwise, continue, and wait till an 
 * event, like bp or user doing xm pause, occurs.
 *
 * Returns: vcpuid : if a vcpu hits a breakpoint or end of step
 *              -1 : either an error (msg printed on terminal), or non-bp 
 *                   event, like "xm pause domid", to enter debugger
 */
vcpuid_t
xg_resume_n_wait(int guest_bitness)
{
    vcpuid_t vcpu;

    XGTRC("E:\n");
    assert(_domain_is_paused());

    if ((vcpu=_vcpu_in_bp()) != -1) {
        /* another vcpu in breakpoint. return it's id */
        return vcpu;
    }
    XGTRC("unpausing domain\n");
    if (_unpause_domain())
        return -1;
         
    /* now wait for domain to pause */
    _wait_domain_pause();

    /* check again if any vcpu in BP, or user thru "xm pause" */
    vcpu = _vcpu_in_bp(); 

    XGTRC("X:vcpu:%d\n", vcpu);
    return vcpu;
}

static void
_cp_32ctxt_to_32gdb(struct cpu_user_regs_x86_32 *cp, struct xg_gdb_regs32 *rp)
{
    memset(rp, 0, sizeof(struct xg_gdb_regs32));
    rp->ebx = cp->ebx;         
    rp->ecx = cp->ecx;    
    rp->edx = cp->edx;
    rp->esi = cp->esi;         
    rp->edi = cp->edi;    
    rp->ebp = cp->ebp;
    rp->eax = cp->eax;         
    rp->eip = cp->eip;    
    rp->cs = cp->cs;
    rp->eflags = cp->eflags;   
    rp->esp = cp->esp;    
    rp->ss = cp->ss;
    rp->es = cp->es;           
    rp->ds = cp->ds;      
    rp->fs = cp->fs;
    rp->gs = cp->gs;
}

static void
_cp_64ctxt_to_32gdb(struct cpu_user_regs_x86_64 *cp, struct xg_gdb_regs32 *rp)
{
    memset(rp, 0, sizeof(struct xg_gdb_regs32));
    rp->ebx = cp->rbx;         
    rp->ecx = cp->rcx;    
    rp->edx = cp->rdx;
    rp->esi = cp->rsi;         
    rp->edi = cp->rdi;    
    rp->ebp = cp->rbp;
    rp->eax = cp->rax;         
    rp->eip = cp->rip;    
    rp->cs = cp->cs;
    rp->eflags = cp->rflags;   
    rp->esp = cp->rsp;    
    rp->ss = cp->ss;
    rp->es = cp->es;           
    rp->ds = cp->ds;      
    rp->fs = cp->fs;
    rp->gs = cp->gs;
}

static void
_cp_64ctxt_to_64gdb(struct cpu_user_regs_x86_64 *cp, struct xg_gdb_regs64 *rp)
{
    memset(rp, 0, sizeof(struct xg_gdb_regs64));
    rp->r8 = cp->r8;           
    rp->r9 = cp->r9;        
    rp->r10 = cp->r10;
    rp->r11 = cp->r11;         
    rp->r12 = cp->r12;      
    rp->r13 = cp->r13;
    rp->r14 = cp->r14;         
    rp->r15 = cp->r15;      
    rp->rbx = cp->rbx;
    rp->rcx = cp->rcx;         
    rp->rdx = cp->rdx;      
    rp->rsi = cp->rsi;
    rp->rdi = cp->rdi;         
    rp->rbp = cp->rbp;      
    rp->rax = cp->rax;
    rp->rip = cp->rip;         
    rp->rsp = cp->rsp;      
    rp->rflags = cp->rflags;

    rp->cs = (uint64_t)cp->cs;            
    rp->ss = (uint64_t)cp->ss;
    rp->es = (uint64_t)cp->es;            
    rp->ds = (uint64_t)cp->ds;
    rp->fs = (uint64_t)cp->fs;            
    rp->gs = (uint64_t)cp->gs;
#if 0
    printf("cp:%llx bp:%llx rip:%llx\n", rp->rsp, rp->rbp, rp->rip);
    printf("rax:%llx rbx:%llx\n", rp->rax, rp->rbx);
    printf("cs:%04x ss:%04x ds:%04x\n", (int)rp->cs, (int)rp->ss, 
           (int)rp->ds);
#endif
}

static void
_cp_32gdb_to_32ctxt(struct xg_gdb_regs32 *rp, struct cpu_user_regs_x86_32 *cp)
{
    cp->ebx = rp->ebx;     
    cp->ecx = rp->ecx;     
    cp->edx = rp->edx;
    cp->esi = rp->esi;     
    cp->edi = rp->edi;     
    cp->ebp = rp->ebp;
    cp->eax = rp->eax;     
    cp->eip = rp->eip;     
    cp->esp = rp->esp;
    cp->cs = rp->cs;       
    cp->ss = rp->ss;       
    cp->es = rp->es;
    cp->ds = rp->ds;       
    cp->fs = rp->fs;       
    cp->gs = rp->gs;
    cp->eflags = rp->eflags;
}

static void
_cp_32gdb_to_64ctxt(struct xg_gdb_regs32 *rp, struct cpu_user_regs_x86_64 *cp)
{
    cp->rbx = rp->ebx;     
    cp->rcx = rp->ecx;     
    cp->rdx = rp->edx;
    cp->rsi = rp->esi;     
    cp->rdi = rp->edi;     
    cp->rbp = rp->ebp;
    cp->rax = rp->eax;     
    cp->rip = rp->eip;     
    cp->rsp = rp->esp;
    cp->cs = rp->cs;       
    cp->ss = rp->ss;       
    cp->es = rp->es;
    cp->ds = rp->ds;       
    cp->fs = rp->fs;       
    cp->gs = rp->gs;
    cp->rflags = rp->eflags;
}

static void
_cp_64gdb_to_64ctxt(struct xg_gdb_regs64 *rp, struct cpu_user_regs_x86_64 *cp)
{
    cp->r8 = rp->r8;
    cp->r9 = rp->r9;
    cp->r10 = rp->r10;
    cp->r11 = rp->r11;
    cp->r12 = rp->r12;
    cp->r13 = rp->r13;
    cp->r14 = rp->r14;
    cp->r15 = rp->r15;
    cp->rbx = rp->rbx;
    cp->rcx = rp->rcx;
    cp->rdx = rp->rdx;
    cp->rsi = rp->rsi;
    cp->rdi = rp->rdi;
    cp->rbp = rp->rbp;
    cp->rax = rp->rax;
    cp->rip = rp->rip;
    cp->rsp = rp->rsp;
    cp->rflags = rp->rflags;

    cp->cs = (uint16_t)rp->cs;
    cp->ss = (uint16_t)rp->ss;
    cp->es = (uint16_t)rp->es;
    cp->ds = (uint16_t)rp->ds;
    cp->fs = (uint16_t)rp->fs;
    cp->gs = (uint16_t)rp->gs;
}


/* get vcpu context from xen and return it in *ctxtp
 * RETURNS: 0 for success
 */
static int
_get_vcpu_ctxt(vcpuid_t vcpu_id, union vcpu_guest_context_any *anycp)
{
    int sz = sizeof(union vcpu_guest_context_any);

    memset(anycp, 0, sz);
    domctl.u.vcpucontext.vcpu = (uint16_t)vcpu_id;
    set_xen_guest_handle(domctl.u.vcpucontext.ctxt, &anycp->ctxt);

    if (_domctl_hcall(XEN_DOMCTL_getvcpucontext, anycp, sz)) {
        XGERR("Failed hcall to get vcpu ctxt. errno:%d\n", errno);
        return 1;
    }
    return 0;
}

/*
 * read regs for a particular vcpu. For now only GPRs, no FPRs.
 * Returns: 0 success,  else failure with errno set
 */
int 
xg_regs_read(regstype_t which_regs, vcpuid_t which_vcpu, 
             union xg_gdb_regs *regsp, int guest_bitness)
{
    union vcpu_guest_context_any anyc;
    struct cpu_user_regs_x86_32 *cr32p = &anyc.ctxt32.user_regs;
    struct cpu_user_regs_x86_64 *cr64p = &anyc.ctxt64.user_regs;
    struct xg_gdb_regs32 *r32p = &regsp->gregs_32;
    struct xg_gdb_regs64 *r64p = &regsp->gregs_64;
    int rc;

    if (which_regs != XG_GPRS) {
        errno = EINVAL;
        XGERR("regs got: %d. Expected GPRS:%d\n", which_regs, XG_GPRS);
        return 1;
    }
    if ((rc=_get_vcpu_ctxt(which_vcpu, &anyc)))
        return rc;

    /* 64bit hyp: only 32bit PV returns 32bit context, all others 64bit.
     * 32bit hyp: all contexts returned are 32bit */
    if (guest_bitness == 32) {
        if (_32bit_hyp || !_hvm_guest)
            _cp_32ctxt_to_32gdb(cr32p, r32p);
        else 
            _cp_64ctxt_to_32gdb(cr64p, r32p);
    } else
        _cp_64ctxt_to_64gdb(cr64p, r64p);
                
    XGTRC("X:vcpu:%d bitness:%d rc:%d\n", which_vcpu, guest_bitness, rc);
    return rc;
}

/*
 * write registers for the given vcpu
 * Returns: 0 success, 1 failure with errno
 */
int 
xg_regs_write(regstype_t which_regs, vcpuid_t which_vcpu, 
              union xg_gdb_regs *regsp, int guest_bitness)
{
    union vcpu_guest_context_any anyc;
    struct cpu_user_regs_x86_32 *cr32p = &anyc.ctxt32.user_regs;
    struct cpu_user_regs_x86_64 *cr64p = &anyc.ctxt64.user_regs;
    struct xg_gdb_regs32 *r32p = &regsp->gregs_32;
    struct xg_gdb_regs64 *r64p = &regsp->gregs_64;
    int rc, sz = sizeof(anyc);

    if (which_regs != XG_GPRS) {
        errno = EINVAL;
        XGERR("regs got: %d. Expected GPRS:%d\n", which_regs, XG_GPRS);
        return 1;
    }
    if ((rc=_get_vcpu_ctxt(which_vcpu, &anyc)))
        return rc;

    if (guest_bitness == 32) {
        if (_32bit_hyp || !_hvm_guest)
            _cp_32gdb_to_32ctxt(r32p, cr32p);
        else 
            _cp_32gdb_to_64ctxt(r32p, cr64p);
    } else
        _cp_64gdb_to_64ctxt(r64p, cr64p);

    /* set vcpu context back */
    if ((rc =_domctl_hcall(XEN_DOMCTL_setvcpucontext, &anyc, sz))) {
        XGERR("Failed hcall to set vcpu ctxt. errno:%d\n", errno);
        return rc;
    }
    XGTRC("X:vcpu:%d bitness:%d rc:%d\n", which_vcpu, guest_bitness, rc);
    return rc;
}

/*
 * Returns: bytes remaining to be read. 0 => read all bytes, ie, success.
 */
int 
xg_read_mem(uint64_t guestva, char *tobuf, int tobuf_len, uint64_t pgd3val)
{
    struct xen_domctl_gdbsx_memio *iop = &domctl.u.gdbsx_guest_memio;
    union {uint64_t llbuf8; char buf8[8];} u = {0};
    int i, rc;

    XGTRC("E:gva:%llx tobuf:%lx len:%d\n", guestva, tobuf, tobuf_len);

    memset(&domctl.u, 0, sizeof(domctl.u));
    iop->pgd3val = pgd3val;
    iop->gva = guestva;
    iop->uva = (uint64_aligned_t)((unsigned long)tobuf);
    iop->len = tobuf_len;
    iop->gwr = 0;       /* not writing to guest */

    if ( (rc = _domctl_hcall(XEN_DOMCTL_gdbsx_guestmemio, tobuf, tobuf_len)) )
    {
        XGTRC("ERROR: failed to read bytes. errno:%d rc:%d\n", errno, rc);
        return tobuf_len;
    }

    for(i=0; i < XGMIN(8, tobuf_len); u.buf8[i]=tobuf[i], i++);
    XGTRC("X:remain:%d buf8:0x%llx\n", iop->remain, u.llbuf8);

    return iop->remain;
}

/*
 * Returns: bytes that could not be written. 0 => wrote all bytes, ie, success.
 */
int 
xg_write_mem(uint64_t guestva, char *frombuf, int buflen, uint64_t pgd3val)
{
    struct xen_domctl_gdbsx_memio *iop = &domctl.u.gdbsx_guest_memio;
    union {uint64_t llbuf8; char buf8[8];} u = {0};
    int i, rc;

    for(i=0; i < XGMIN(8, buflen); u.buf8[i]=frombuf[i], i++);
    XGTRC("E:gva:%llx frombuf:%lx len:%d buf8:0x%llx\n", guestva, frombuf, 
          buflen, u.llbuf8);

    memset(&domctl.u, 0, sizeof(domctl.u));
    iop->pgd3val = pgd3val;
    iop->gva = guestva;
    iop->uva = (uint64_aligned_t)((unsigned long)frombuf);
    iop->len = buflen;
    iop->gwr = 1;       /* writing to guest */

    if ((rc=_domctl_hcall(XEN_DOMCTL_gdbsx_guestmemio, frombuf, buflen)))
    {
        XGERR("ERROR: failed to write bytes to %llx. errno:%d rc:%d\n",
              guestva, errno, rc);
        return buflen;
    }
    return iop->remain;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
