/*
 * kdd-xen.c -- xen-specific functions for the kdd debugging stub
 *
 * Tim Deegan <Tim.Deegan@citrix.com>
 * 
 * Copyright (c) 2007-2010, Citrix Systems Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <xenctrl.h>
#include <xen/xen.h>
#include <xen/hvm/save.h>

#include "kdd.h"

#define MAPSIZE 4093 /* Prime */

#define PAGE_SHIFT 12
#define PAGE_SIZE (1U << PAGE_SHIFT)

struct kdd_guest {
    struct xentoollog_logger xc_log; /* Must be first for xc log callbacks */
    xc_interface *xc_handle;
    uint32_t domid;
    char id[80];
    FILE *log;
    int verbosity;
    void *hvm_buf;
    uint32_t hvm_sz;
    uint32_t pfns[MAPSIZE];
    void * maps[MAPSIZE];
};


/* Flush any mappings we have of the guest memory: it's not polite
 * top hold on to them while the guest is running */
static void flush_maps(kdd_guest *g)
{
    int i;
    for (i = 0; i < MAPSIZE; i++) {
        if (g->maps[i] != NULL)
            munmap(g->maps[i], PAGE_SIZE);
        g->maps[i] = NULL;
    }
}


/* Halt the guest so we can debug it */
void kdd_halt(kdd_guest *g)
{
    uint32_t sz;
    void *buf;

    xc_domain_pause(g->xc_handle, g->domid);

    /* How much space do we need for the HVM state? */
    sz = xc_domain_hvm_getcontext(g->xc_handle, g->domid, 0, 0);
    if (sz == (uint32_t) -1) {
        KDD_LOG(g, "Can't get HVM state size for domid %"PRIu32": %s\n",
                g->domid, strerror(errno));
        return;
    }
    buf = realloc(g->hvm_buf, sz);
    if (!buf) {
        KDD_LOG(g, "Couldn't allocate %"PRIu32" for HVM buffer\n", sz);
        return;
    }
    g->hvm_buf = buf;
    g->hvm_sz = sz;
    memset(buf, 0, sz);

    /* Get the HVM state */
    sz = xc_domain_hvm_getcontext(g->xc_handle, g->domid, buf, sz);
    if (sz == (uint32_t) -1) {
        KDD_LOG(g, "Can't get HVM state for domid %"PRIu32": %s\n",
                g->domid, strerror(errno));
    }
}

/* Check whether the guest has stopped.  Returns 'interesting' vcpu or -1 */
/* TODO: open DEBUG_VIRQ if it's free and wait for events rather than
 * always polling the guest state */
int kdd_poll_guest(kdd_guest *g)
{
    /* TODO: finish plumbing through polling for breakpoints */
    return 0;
}

/* Update the HVM state */
static void hvm_writeback(kdd_guest *g)
{
    if (g->hvm_buf && xc_domain_hvm_setcontext(g->xc_handle, g->domid, 
                                               g->hvm_buf, g->hvm_sz))
        KDD_LOG(g, "Can't set HVM state for domid %"PRIu32": %s\n",
                g->domid, strerror(errno));
}

/* Start the guest running again */
void kdd_run(kdd_guest *g)
{
    flush_maps(g);
    hvm_writeback(g);
    xc_domain_unpause(g->xc_handle, g->domid);
}

/* How many CPUs are there in this guest? */
int kdd_count_cpus(kdd_guest *g)
{
    struct hvm_save_descriptor *desc;
    int maxcpu = 0;

    if (!g->hvm_buf)
        return 0;

    /* Scan the CPU save records. */
    for (desc = g->hvm_buf;
         (void *) desc >= g->hvm_buf && (void *) desc < g->hvm_buf + g->hvm_sz;
         desc = ((void *)desc) + (sizeof *desc) + desc->length) {
        if (desc->typecode == HVM_SAVE_CODE(CPU)) {
            if (maxcpu < desc->instance) 
                maxcpu = desc->instance;
        }
    }
    return maxcpu + 1;
}

/* Helper fn: get CPU state from cached HVM state */
static struct hvm_hw_cpu *get_cpu(kdd_guest *g, int cpuid)
{
    struct hvm_save_descriptor *desc;
    struct hvm_hw_cpu *cpu;

    if (!g->hvm_buf)
        return NULL;

    /* Find the right CPU */
    for (desc = g->hvm_buf;
         (void *) desc >= g->hvm_buf && (void *) desc < g->hvm_buf + g->hvm_sz;
         desc = ((void *)desc) + (sizeof *desc) + desc->length) {
        if (desc->typecode == HVM_SAVE_CODE(CPU) && desc->instance == cpuid) {
            cpu = ((void *)desc) + (sizeof *desc);
            if ((void *) cpu + sizeof (*cpu) <= g->hvm_buf + g->hvm_sz)
                return cpu;
        }
    }
    
    KDD_LOG(g, "Dom %"PRIu32" has no CPU %i\n", g->domid, cpuid);
    return NULL;
}

/* Helper fn: get APIC state from cached HVM state */
static struct hvm_hw_lapic_regs *get_lapic(kdd_guest *g, int cpuid)
{
    struct hvm_save_descriptor *desc;
    struct hvm_hw_lapic_regs *regs;

    if (!g->hvm_buf)
        return NULL;

    /* Find the right CPU's LAPIC */
    for (desc = g->hvm_buf;
         (void *) desc >= g->hvm_buf && (void *) desc < g->hvm_buf + g->hvm_sz;
         desc = ((void *)desc) + (sizeof *desc) + desc->length) {
        if (desc->typecode == HVM_SAVE_CODE(LAPIC_REGS) && desc->instance == cpuid) {
            regs = ((void *)desc) + (sizeof *desc);
            if ((void *) regs + sizeof (*regs) <= g->hvm_buf + g->hvm_sz)
                return regs;
        }
    }
    
    KDD_LOG(g, "Dom %"PRIu32" has no LAPIC %i\n", g->domid, cpuid);
    return NULL;
}


/* Accessors for guest user registers */
static void kdd_get_regs_x86_32(struct hvm_hw_cpu *cpu, kdd_regs_x86_32 *r)
{
    r->gs     = cpu->gs_sel;
    r->fs     = cpu->fs_sel;
    r->es     = cpu->es_sel;
    r->ds     = cpu->ds_sel;
    r->edi    = cpu->rdi;
    r->esi    = cpu->rsi;
    r->ebx    = cpu->rbx;
    r->edx    = cpu->rdx;
    r->ecx    = cpu->rcx;
    r->eax    = cpu->rax;
    r->ebp    = cpu->rbp;
    r->eip    = cpu->rip;
    r->cs     = cpu->cs_sel;
    r->eflags = cpu->rflags;
    r->esp    = cpu->rsp;
    r->ss     = cpu->ss_sel;
    memcpy(r->fp, cpu->fpu_regs, 112); // 108 save area + 4 of ???
}

static void kdd_set_regs_x86_32(struct hvm_hw_cpu *cpu, kdd_regs_x86_32 *r)
{
    cpu->gs_sel = r->gs;
    cpu->fs_sel = r->fs;
    cpu->es_sel = r->es;
    cpu->ds_sel = r->ds;
    cpu->rdi    = r->edi;
    cpu->rsi    = r->esi;
    cpu->rbx    = r->ebx;
    cpu->rdx    = r->edx;
    cpu->rcx    = r->ecx;
    cpu->rax    = r->eax;
    cpu->rbp    = r->ebp;
    cpu->rip    = r->eip;
    cpu->cs_sel = r->cs;
    cpu->rflags = r->eflags;
    cpu->rsp    = r->esp;
    cpu->ss_sel = r->ss;
    memcpy(cpu->fpu_regs, r->fp, 112); // 108 save area + 4 of ???
}

static void kdd_get_regs_x86_64(struct hvm_hw_cpu *cpu, kdd_regs_x86_64 *r)
{
    // XXX debug pattern
    uint16_t i;
    for (i = 0 ; i < (sizeof *r / 2) ; i++)
        ((uint16_t *)r)[i] = i;

    r->cs     = cpu->cs_sel;
    r->ds     = cpu->ds_sel;
    r->es     = cpu->es_sel;
    r->fs     = cpu->fs_sel;
    r->gs     = cpu->gs_sel;
    r->ss     = cpu->ss_sel;
    r->rflags = cpu->rflags;
    r->dr0    = cpu->dr0;
    r->dr1    = cpu->dr1;
    r->dr2    = cpu->dr2;
    r->dr3    = cpu->dr3;
    r->dr6    = cpu->dr6;
    r->dr7    = cpu->dr7;
    r->rax    = cpu->rax;
    r->rcx    = cpu->rcx;
    r->rdx    = cpu->rdx;
    r->rbx    = cpu->rbx;
    r->rsp    = cpu->rsp;
    r->rbp    = cpu->rbp;
    r->rsi    = cpu->rsi;
    r->rdi    = cpu->rdi;
    r->r8     = cpu->r8;
    r->r9     = cpu->r9;
    r->r10    = cpu->r10;
    r->r11    = cpu->r11;
    r->r12    = cpu->r12;
    r->r13    = cpu->r13;
    r->r14    = cpu->r14;
    r->r15    = cpu->r15;
    r->rip    = cpu->rip;
    memcpy(r->fp, cpu->fpu_regs, 112); // Definitely not right
}

static void kdd_set_regs_x86_64(struct hvm_hw_cpu *cpu, kdd_regs_x86_64 *r)
{
    cpu->cs_sel = r->cs;
    cpu->ds_sel = r->ds;
    cpu->es_sel = r->es;
    cpu->fs_sel = r->fs;
    cpu->gs_sel = r->gs;
    cpu->ss_sel = r->ss;
    cpu->rflags = r->rflags;
    cpu->dr0    = r->dr0;
    cpu->dr1    = r->dr1;
    cpu->dr2    = r->dr2;
    cpu->dr3    = r->dr3;
    cpu->dr6    = r->dr6;
    cpu->dr7    = r->dr7;
    cpu->rax    = r->rax;
    cpu->rcx    = r->rcx;
    cpu->rdx    = r->rdx;
    cpu->rbx    = r->rbx;
    cpu->rsp    = r->rsp;
    cpu->rbp    = r->rbp;
    cpu->rsi    = r->rsi;
    cpu->rdi    = r->rdi;
    cpu->r8     = r->r8;
    cpu->r9     = r->r9;
    cpu->r10    = r->r10;
    cpu->r11    = r->r11;
    cpu->r12    = r->r12;
    cpu->r13    = r->r13;
    cpu->r14    = r->r14;
    cpu->r15    = r->r15;
    cpu->rip    = r->rip;
    memcpy(r->fp, cpu->fpu_regs, 112); // Definitely not right
}


int kdd_get_regs(kdd_guest *g, int cpuid, kdd_regs *r, int w64)
{
    struct hvm_hw_cpu *cpu; 
    
    cpu = get_cpu(g, cpuid);
    if (!cpu) 
        return -1;

    memset(r, 0, sizeof(*r));
    
    if (w64)
        kdd_get_regs_x86_64(cpu, &r->r64);
    else
        kdd_get_regs_x86_32(cpu, &r->r32);

    return 0;
}

int kdd_set_regs(kdd_guest *g, int cpuid, kdd_regs *r, int w64)
{
    struct hvm_hw_cpu *cpu; 
    
    cpu = get_cpu(g, cpuid);
    if (!cpu) 
        return -1;
    
    if (w64)
        kdd_set_regs_x86_64(cpu, &r->r64);
    else
        kdd_set_regs_x86_32(cpu, &r->r32);

    hvm_writeback(g);
    return 0;
}


/* Accessors for guest control registers */
static void kdd_get_ctrl_x86_32(struct hvm_hw_cpu *cpu, kdd_ctrl_x86_32 *c)
{    
    c->cr0 = cpu->cr0;
    c->cr2 = cpu->cr2;
    c->cr3 = cpu->cr3;
    c->cr4 = cpu->cr4;
    c->dr0 = cpu->dr0;
    c->dr1 = cpu->dr1;
    c->dr2 = cpu->dr2;
    c->dr3 = cpu->dr3;
    c->dr6 = cpu->dr6;
    c->dr7 = cpu->dr7;
    c->gdt_base = cpu->gdtr_base;
    c->gdt_limit = cpu->gdtr_limit;
    c->idt_base = cpu->idtr_base;
    c->idt_limit = cpu->idtr_limit;
    c->tss_sel = cpu->tr_sel;
    c->ldt_sel = cpu->ldtr_sel;
}

static void kdd_get_ctrl_x86_64(struct hvm_hw_cpu *cpu, 
                                struct hvm_hw_lapic_regs *lapic,
                                kdd_ctrl_x86_64 *c)
{    
    c->cr0 = cpu->cr0;
    c->cr2 = cpu->cr2;
    c->cr3 = cpu->cr3;
    c->cr4 = cpu->cr4;
    c->dr0 = cpu->dr0;
    c->dr1 = cpu->dr1;
    c->dr2 = cpu->dr2;
    c->dr3 = cpu->dr3;
    c->dr6 = cpu->dr6;
    c->dr7 = cpu->dr7;
    c->gdt_base = cpu->gdtr_base;
    c->gdt_limit = cpu->gdtr_limit;
    c->idt_base = cpu->idtr_base;
    c->idt_limit = cpu->idtr_limit;
    c->tss_sel = cpu->tr_sel;
    c->ldt_sel = cpu->ldtr_sel;
    c->cr8 = lapic->data[0x80] >> 4; /* Top half of the low byte of the TPR */
}


int kdd_get_ctrl(kdd_guest *g, int cpuid, kdd_ctrl *ctrl, int w64)
{
    struct hvm_hw_cpu *cpu; 
    struct hvm_hw_lapic_regs *lapic;

    cpu = get_cpu(g, cpuid);
    if (!cpu)
        return -1;

    if (w64) {
        lapic = get_lapic(g, cpuid);
        if (!lapic)
            return -1;
        kdd_get_ctrl_x86_64(cpu, lapic, &ctrl->c64);
    } else {
        kdd_get_ctrl_x86_32(cpu, &ctrl->c32);
    }

    return 0;
}

int kdd_wrmsr(kdd_guest *g, int cpuid, uint32_t msr, uint64_t value)
{
    struct hvm_hw_cpu *cpu;

    cpu = get_cpu(g, cpuid);
    if (!cpu)
        return -1;
    
    switch (msr) {
    case 0x00000174: cpu->sysenter_cs = value; break;
    case 0x00000175: cpu->sysenter_esp = value; break;
    case 0x00000176: cpu->sysenter_eip = value; break;
    case 0xc0000080: cpu->msr_efer = value; break;
    case 0xc0000081: cpu->msr_star = value; break;
    case 0xc0000082: cpu->msr_lstar = value; break;
    case 0xc0000083: cpu->msr_cstar = value; break;
    case 0xc0000084: cpu->msr_syscall_mask = value; break;
    case 0xc0000100: cpu->fs_base = value; break;
    case 0xc0000101: cpu->gs_base = value; break;
    case 0xc0000102: cpu->shadow_gs = value; break;
    default:
        return -1;
    }

    hvm_writeback(g);
    return 0;   
}

int kdd_rdmsr(kdd_guest *g, int cpuid, uint32_t msr, uint64_t *value)
{
    struct hvm_hw_cpu *cpu;

    cpu = get_cpu(g, cpuid);
    if (!cpu)
        return -1;
    
    switch (msr) {
    case 0x00000174: *value = cpu->sysenter_cs; break;
    case 0x00000175: *value = cpu->sysenter_esp; break;
    case 0x00000176: *value = cpu->sysenter_eip; break;
    case 0xc0000080: *value = cpu->msr_efer; break;
    case 0xc0000081: *value = cpu->msr_star; break;
    case 0xc0000082: *value = cpu->msr_lstar; break;
    case 0xc0000083: *value = cpu->msr_cstar; break;
    case 0xc0000084: *value = cpu->msr_syscall_mask; break;
    case 0xc0000100: *value = cpu->fs_base; break;
    case 0xc0000101: *value = cpu->gs_base; break;
    case 0xc0000102: *value = cpu->shadow_gs; break;
    default:
        return -1;
    }

    return 0;   
}


/* Accessor for guest physical memory */
static uint32_t kdd_access_physical_page(kdd_guest *g, uint64_t addr, 
                                         uint32_t len, uint8_t *buf, int write)
{
    uint32_t map_pfn, map_offset;
    uint8_t *map;

    map_pfn = (addr >> PAGE_SHIFT);
    map_offset = addr & (PAGE_SIZE - 1);

    /* Evict any mapping of the wrong frame from our slot */ 
    if (g->pfns[map_pfn % MAPSIZE] != map_pfn
        && g->maps[map_pfn % MAPSIZE] != NULL) {
        munmap(g->maps[map_pfn % MAPSIZE], PAGE_SIZE);
        g->maps[map_pfn % MAPSIZE] = NULL;
    }
    g->pfns[map_pfn % MAPSIZE] = map_pfn;

    /* Now map the frame if it's not already there */
    if (g->maps[map_pfn % MAPSIZE] != NULL)
        map = g->maps[map_pfn % MAPSIZE];
    else {
        map = xc_map_foreign_range(g->xc_handle,
                                   g->domid,
                                   PAGE_SIZE,
                                   PROT_READ|PROT_WRITE,
                                   map_pfn);

        KDD_DEBUG(g, "map: %u, 0x%16.16"PRIx32": %p +0x%"PRIx32"\n",
                  write ? PROT_READ|PROT_WRITE : PROT_READ,
                  map_pfn, map, map_offset);

        if (!map) 
            return 0;
        g->maps[map_pfn % MAPSIZE] = map;
    }

    if (write) 
        memcpy(map + map_offset, buf, len);
    else
        memcpy(buf, map + map_offset, len);

    return len;
}

uint32_t kdd_access_physical(kdd_guest *g, uint64_t addr, 
                             uint32_t len, uint8_t *buf, int write)
{
    uint32_t chunk, rv, done = 0;
    while (len > 0) {
        chunk = PAGE_SIZE - (addr & (PAGE_SIZE - 1));
        if (chunk > len) 
            chunk = len;
        rv = kdd_access_physical_page(g, addr, chunk, buf, write);
        done += rv;
        if (rv != chunk)
            return done;
        addr += chunk;
        buf += chunk;
        len -= chunk;
    }
    return done;
}


/* Plumb libxc log messages into our own logging */
static void kdd_xc_log(struct xentoollog_logger *logger,
                       xentoollog_level level,
                       int errnoval /* or -1 */,
                       const char *context /* eg "xc", "xl", may be 0 */,
                       const char *format /* without level, context, \n */,
                       va_list al)
{
    kdd_guest *g = (kdd_guest *) logger;
    /* Suppress most libxc levels unless we're logging at debug level */
    if (g->verbosity < 1 || (level < XTL_WARN && g->verbosity < 3))
        return;
    fprintf(g->log, "libxc[%s:%i:%i]: ", context ? : "?", level, errnoval);
    vfprintf(g->log, format, al);
    fprintf(g->log, "\n");
    (void) fflush(g->log);
}


/* Set up guest-specific state */
kdd_guest *kdd_guest_init(char *arg, FILE *log, int verbosity)
{
    kdd_guest *g = NULL;
    xc_interface *xch = NULL;
    uint32_t domid;
    xc_dominfo_t info;

    g = calloc(1, sizeof (kdd_guest));
    if (!g) 
        goto err;
    g->log = log;
    g->verbosity = verbosity;
    g->xc_log.vmessage = kdd_xc_log;

    xch = xc_interface_open(&g->xc_log, NULL, 0);
    if (!xch)
        goto err;
    g->xc_handle = xch;

    domid = strtoul(arg, NULL, 0);
    if (domid == 0)
        goto err;
    g->domid = domid;

    /* Check that the domain exists and is HVM */
    if (xc_domain_getinfo(xch, domid, 1, &info) != 1 || !info.hvm)
        goto err;

    snprintf(g->id, (sizeof g->id) - 1, 
             "a xen guest with domain id %i", g->domid);

    return g;

 err:
    free(g);
    if (xch)
        xc_interface_close(xch);
    return NULL;
}

/* Say what kind of guest this is */
char *kdd_guest_identify(kdd_guest *g)
{
    return g->id;
}

/* Tear down guest-specific state */
void kdd_guest_teardown(kdd_guest *g)
{
    flush_maps(g);
    xc_interface_close(g->xc_handle);
    free(g->hvm_buf);
    free(g);
}
