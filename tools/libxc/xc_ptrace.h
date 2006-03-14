#ifndef XC_PTRACE_
#define XC_PTRACE_

#include <thread_db.h>

#ifdef XC_PTRACE_PRIVATE
#define X86_CR0_PE              0x00000001 /* Enable Protected Mode    (RW) */
#define X86_CR0_PG              0x80000000 /* Paging                   (RW) */
#define BSD_PAGE_MASK (PAGE_SIZE-1)
#define PDRSHIFT        22
#define PSL_T  0x00000100 /* trace enable bit */

struct gdb_regs {
    long ebx; /* 0 */
    long ecx; /* 4 */
    long edx; /* 8 */
    long esi; /* 12 */
    long edi; /* 16 */
    long ebp; /* 20 */
    long eax; /* 24 */ 
    int  xds; /* 28 */
    int  xes; /* 32 */
    int  xfs; /* 36 */
    int  xgs; /* 40 */
    long orig_eax; /* 44 */
    long eip;    /* 48 */
    int  xcs;    /* 52 */
    long eflags; /* 56 */
    long esp;    /* 60 */     
    int  xss;    /* 64 */
};


#define printval(x) printf("%s = %lx\n", #x, (long)x);
#define SET_PT_REGS(pt, xc)                     \
{                                               \
    pt.ebx = xc.ebx;                            \
    pt.ecx = xc.ecx;                            \
    pt.edx = xc.edx;                            \
    pt.esi = xc.esi;                            \
    pt.edi = xc.edi;                            \
    pt.ebp = xc.ebp;                            \
    pt.eax = xc.eax;                            \
    pt.eip = xc.eip;                            \
    pt.xcs = xc.cs;                             \
    pt.eflags = xc.eflags;                      \
    pt.esp = xc.esp;                            \
    pt.xss = xc.ss;                             \
    pt.xes = xc.es;                             \
    pt.xds = xc.ds;                             \
    pt.xfs = xc.fs;                             \
    pt.xgs = xc.gs;                             \
}

#define SET_XC_REGS(pt, xc)                     \
{                                               \
    xc.ebx = pt->ebx;                           \
    xc.ecx = pt->ecx;                           \
    xc.edx = pt->edx;                           \
    xc.esi = pt->esi;                           \
    xc.edi = pt->edi;                           \
    xc.ebp = pt->ebp;                           \
    xc.eax = pt->eax;                           \
    xc.eip = pt->eip;                           \
    xc.cs = pt->xcs;                            \
    xc.eflags = pt->eflags;                     \
    xc.esp = pt->esp;                           \
    xc.ss = pt->xss;                            \
    xc.es = pt->xes;                            \
    xc.ds = pt->xds;                            \
    xc.fs = pt->xfs;                            \
    xc.gs = pt->xgs;                            \
}

#define vtopdi(va) ((va) >> PDRSHIFT)
#define vtopti(va) (((va) >> PAGE_SHIFT) & 0x3ff)
#endif

typedef void (*thr_ev_handler_t)(long);

void xc_register_event_handler(
    thr_ev_handler_t h, 
    td_event_e e);

long xc_ptrace(
    int xc_handle,
    enum __ptrace_request request, 
    uint32_t  domid,
    long addr, 
    long data);

int xc_waitdomain(
    int xc_handle,
    int domain, 
    int *status, 
    int options);

#endif /* XC_PTRACE */
