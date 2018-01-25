/* 
 * xen-hvmctx.c
 *
 * Print out the contents of a HVM save record in a human-readable way.
 * 
 * Tim Deegan <Tim.Deegan@citrix.com>
 * Copyright (c) 2008 Citrix Systems, Inc.
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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#define BITS_PER_LONG __WORDSIZE
#define BITS_TO_LONGS(bits) \
        (((bits)+BITS_PER_LONG-1)/BITS_PER_LONG)
#define DECLARE_BITMAP(name,bits) \
        unsigned long name[BITS_TO_LONGS(bits)]

#include <xenctrl.h>
#include <xen/xen.h>
#include <xen/domctl.h>
#include <xen/hvm/save.h>

static uint8_t *buf = NULL;
static uint32_t len;
static uint32_t off;

#define READ(_x) do {                                                      \
    if ( len - off < sizeof (_x) )                                         \
    {                                                                      \
        fprintf(stderr, "Error: need another %u bytes, only %u available", \
                (unsigned int)sizeof(_x), len - off);                      \
        exit(1);                                                           \
    }                                                                      \
    memcpy(&(_x), buf + off, sizeof (_x));                                 \
    off += sizeof (_x);                                                    \
} while (0)

static void dump_header(void)
{ 
    HVM_SAVE_TYPE(HEADER) h;
    READ(h);
    printf("     Header: magic %#lx, version %lu\n",
           (unsigned long) h.magic, (unsigned long) h.version);
    printf("             Xen changeset %llx\n", 
           (unsigned long long) h.changeset);
    printf("             CPUID[0][%%eax] 0x%.8lx\n", (unsigned long) h.cpuid);
    printf("             gtsc_khz %lu\n", (unsigned long) h.gtsc_khz);
}

struct fpu_mm {
    uint64_t lo;
    uint16_t hi;
    uint16_t pad[3];
} __attribute__((packed));

struct fpu_xmm {
    uint64_t lo;
    uint64_t hi;
};

struct fpu_regs {
    uint16_t fcw;
    uint16_t fsw;
    uint8_t ftw;
    uint8_t res0;
    uint16_t fop;
    uint64_t fpuip;
    uint64_t fpudp;
    uint32_t mxcsr;
    uint32_t mxcsr_mask;
    struct fpu_mm mm[8];
    struct fpu_xmm xmm[16];
    uint64_t res1[12];
} __attribute__((packed));

static void dump_fpu(void *p)
{
    struct fpu_regs *r = p;
    int i;

    printf("    FPU:    fcw 0x%4.4x fsw 0x%4.4x\n"  
           "            ftw 0x%2.2x (0x%2.2x) fop 0x%4.4x\n"
           "          fpuip 0x%16.16"PRIx64" fpudp 0x%16.16"PRIx64"\n"
           "          mxcsr 0x%8.8lx mask 0x%8.8lx\n",
           (unsigned)r->fcw, (unsigned)r->fsw, 
           (unsigned)r->ftw, (unsigned)r->res0, (unsigned)r->fop, 
           r->fpuip, r->fpudp, 
           (unsigned long)r->mxcsr, (unsigned long)r->mxcsr_mask);

    for ( i = 0 ; i < 8 ; i++ ) 
        printf("            mm%i 0x%4.4x%16.16"PRIx64" (0x%4.4x%4.4x%4.4x)\n",
               i, r->mm[i].hi, r->mm[i].lo,
               r->mm[i].pad[2], r->mm[i].pad[1], r->mm[i].pad[0]);

    for ( i = 0 ; i < 16 ; i++ ) 
        printf("          xmm%2.2i 0x%16.16"PRIx64"%16.16"PRIx64"\n",
               i, r->xmm[i].hi, r->xmm[i].lo);
    
    for ( i = 0 ; i < 6 ; i++ ) 
        printf("               (0x%16.16"PRIx64"%16.16"PRIx64")\n",
               r->res1[2*i+1], r->res1[2*i]);
}

static void dump_cpu(void) 
{
    HVM_SAVE_TYPE(CPU) c;
    READ(c);
    printf("    CPU:    rax 0x%16.16llx     rbx 0x%16.16llx\n"
           "            rcx 0x%16.16llx     rdx 0x%16.16llx\n"
           "            rbp 0x%16.16llx     rsi 0x%16.16llx\n"
           "            rdi 0x%16.16llx     rsp 0x%16.16llx\n"
           "             r8 0x%16.16llx      r9 0x%16.16llx\n"
           "            r10 0x%16.16llx     r11 0x%16.16llx\n"
           "            r12 0x%16.16llx     r13 0x%16.16llx\n"
           "            r14 0x%16.16llx     r15 0x%16.16llx\n"
           "            rip 0x%16.16llx  rflags 0x%16.16llx\n"
           "            cr0 0x%16.16llx     cr2 0x%16.16llx\n"
           "            cr3 0x%16.16llx     cr4 0x%16.16llx\n"
           "            dr0 0x%16.16llx     dr1 0x%16.16llx\n"
           "            dr2 0x%16.16llx     dr3 0x%16.16llx\n"
           "            dr6 0x%16.16llx     dr7 0x%16.16llx\n"
           "             cs 0x%8.8x (0x%16.16llx + 0x%8.8x / 0x%5.5x)\n"
           "             ds 0x%8.8x (0x%16.16llx + 0x%8.8x / 0x%5.5x)\n"
           "             es 0x%8.8x (0x%16.16llx + 0x%8.8x / 0x%5.5x)\n"
           "             fs 0x%8.8x (0x%16.16llx + 0x%8.8x / 0x%5.5x)\n"
           "             gs 0x%8.8x (0x%16.16llx + 0x%8.8x / 0x%5.5x)\n"
           "             ss 0x%8.8x (0x%16.16llx + 0x%8.8x / 0x%5.5x)\n"
           "             tr 0x%8.8x (0x%16.16llx + 0x%8.8x / 0x%5.5x)\n"
           "           ldtr 0x%8.8x (0x%16.16llx + 0x%8.8x / 0x%5.5x)\n"
           "           idtr            (0x%16.16llx + 0x%8.8x)\n"
           "           gdtr            (0x%16.16llx + 0x%8.8x)\n"
           "    sysenter cs 0x%8.8llx  eip 0x%16.16llx  esp 0x%16.16llx\n"
           "      shadow gs 0x%16.16llx\n"
           "      MSR flags 0x%16.16llx  lstar 0x%16.16llx\n"
           "           star 0x%16.16llx  cstar 0x%16.16llx\n"
           "         sfmask 0x%16.16llx   efer 0x%16.16llx\n"
           "            tsc 0x%16.16llx\n"
           "          event 0x%8.8lx error 0x%8.8lx\n",
           (unsigned long long) c.rax, (unsigned long long) c.rbx,
           (unsigned long long) c.rcx, (unsigned long long) c.rdx,
           (unsigned long long) c.rbp, (unsigned long long) c.rsi,
           (unsigned long long) c.rdi, (unsigned long long) c.rsp,
           (unsigned long long) c.r8, (unsigned long long) c.r9,
           (unsigned long long) c.r10, (unsigned long long) c.r11,
           (unsigned long long) c.r12, (unsigned long long) c.r13,
           (unsigned long long) c.r14, (unsigned long long) c.r15,
           (unsigned long long) c.rip, (unsigned long long) c.rflags,
           (unsigned long long) c.cr0, (unsigned long long) c.cr2,
           (unsigned long long) c.cr3, (unsigned long long) c.cr4,
           (unsigned long long) c.dr0, (unsigned long long) c.dr1,
           (unsigned long long) c.dr2, (unsigned long long) c.dr3,
           (unsigned long long) c.dr6, (unsigned long long) c.dr7,
           c.cs_sel, (unsigned long long) c.cs_base, c.cs_limit, c.cs_arbytes,
           c.ds_sel, (unsigned long long) c.ds_base, c.ds_limit, c.ds_arbytes,
           c.es_sel, (unsigned long long) c.es_base, c.es_limit, c.es_arbytes,
           c.fs_sel, (unsigned long long) c.fs_base, c.fs_limit, c.fs_arbytes,
           c.gs_sel, (unsigned long long) c.gs_base, c.gs_limit, c.gs_arbytes,
           c.ss_sel, (unsigned long long) c.ss_base, c.ss_limit, c.ss_arbytes,
           c.tr_sel, (unsigned long long) c.tr_base, c.tr_limit, c.tr_arbytes,
           c.ldtr_sel, (unsigned long long) c.ldtr_base,
           c.ldtr_limit, c.ldtr_arbytes,
           (unsigned long long) c.idtr_base, c.idtr_limit, 
           (unsigned long long) c.gdtr_base, c.gdtr_limit, 
           (unsigned long long) c.sysenter_cs, 
           (unsigned long long) c.sysenter_eip, 
           (unsigned long long) c.sysenter_esp,
           (unsigned long long) c.shadow_gs,
           (unsigned long long) c.msr_flags,
           (unsigned long long) c.msr_lstar,
           (unsigned long long) c.msr_star,
           (unsigned long long) c.msr_cstar,
           (unsigned long long) c.msr_syscall_mask,
           (unsigned long long) c.msr_efer,
           (unsigned long long) c.tsc,
           (unsigned long) c.pending_event, (unsigned long) c.error_code);
    dump_fpu(&c.fpu_regs);
}


static void dump_pic(void) 
{
    HVM_SAVE_TYPE(PIC) p;
    READ(p);
    printf("    PIC: IRQ base %#x, irr %#x, imr %#x, isr %#x\n",
           p.irq_base, p.irr, p.imr, p.isr);

    printf("         init_state %u, priority_add %u, readsel_isr %u, poll %u\n",
           p.init_state, p.priority_add, p.readsel_isr, p.poll);
    printf("         auto_eoi %u, rotate_on_auto_eoi %u\n",
           p.auto_eoi, p.rotate_on_auto_eoi);
    printf("         special_fully_nested_mode %u, special_mask_mode %u\n",
           p.special_fully_nested_mode, p.special_mask_mode);
    printf("         is_master %u, elcr %#x, int_output %#x\n",
           p.is_master, p.elcr, p.int_output);
}


static void dump_ioapic(void) 
{
    int i;
    HVM_SAVE_TYPE(IOAPIC) p;
    READ(p);
    printf("    IOAPIC: base_address %#llx, ioregsel %#x id %#x\n",
           (unsigned long long) p.base_address, p.ioregsel, p.id);
    for ( i = 0; i < VIOAPIC_NUM_PINS; i++ )
    {
        printf("            pin %.2i: 0x%.16llx\n", i, 
               (unsigned long long) p.redirtbl[i].bits);
    }
}

static void dump_lapic(void)
{
    HVM_SAVE_TYPE(LAPIC) p;
    READ(p);
    printf("    LAPIC: base_msr %#llx, disabled %#x, timer_divisor %#x\n",
           (unsigned long long) p.apic_base_msr, p.disabled, p.timer_divisor);
}

static void dump_lapic_regs(void)
{
    unsigned int i;
    HVM_SAVE_TYPE(LAPIC_REGS) r;
    READ(r);
    printf("    LAPIC registers:\n");
    for ( i = 0 ; i < 0x400 ; i += 32 )
    {
        printf("          0x%4.4x: 0x%16.16llx   0x%4.4x: 0x%16.16llx\n",
               i, *(unsigned long long *)&r.data[i], 
               i + 16, *(unsigned long long *)&r.data[i + 16]);        
    }
}

static void dump_pci_irq(void)
{
    HVM_SAVE_TYPE(PCI_IRQ) i;
    READ(i);
    printf("    PCI IRQs: 0x%16.16llx%16.16llx\n", 
           (unsigned long long) i.pad[0], (unsigned long long) i.pad[1]);
}

static void dump_isa_irq(void)
{
    HVM_SAVE_TYPE(ISA_IRQ) i;
    READ(i);
    printf("    ISA IRQs: 0x%4.4llx\n", 
           (unsigned long long) i.pad[0]);
}

static void dump_pci_link(void)
{
    HVM_SAVE_TYPE(PCI_LINK) l;
    READ(l);
    printf("    PCI LINK: %u %u %u %u\n", 
           l.route[0], l.route[1], l.route[2], l.route[3]);
}

static void dump_pit(void) 
{
    int i;
    HVM_SAVE_TYPE(PIT) p;
    READ(p);
    printf("    PIT: speaker %s\n", p.speaker_data_on ? "on" : "off");
    for ( i = 0 ; i < 2 ; i++ )
    {
        printf("         ch %1i: count %#x, latched_count %#x, count_latched %u\n", 
               i, p.channels[i].count, p.channels[i].latched_count, 
               p.channels[i].count_latched);
        printf("               status %#x, status_latched %#x\n", 
               p.channels[i].status, p.channels[i].status_latched);
        printf("               rd_state %#x, wr_state %#x, wr_latch %#x, rw_mode %#x\n", 
               p.channels[i].read_state, p.channels[i].write_state, 
               p.channels[i].write_latch, p.channels[i].rw_mode);
        printf("               mode %#x, bcd %#x, gate %#x\n",
               p.channels[i].mode, p.channels[i].bcd, p.channels[i].gate);
    }    
}

static void dump_rtc(void)
{
    HVM_SAVE_TYPE(RTC) r;
    READ(r);
    printf("    RTC: regs 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x\n",
           r.cmos_data[0], r.cmos_data[1], r.cmos_data[2], r.cmos_data[3], 
           r.cmos_data[4], r.cmos_data[5], r.cmos_data[6], r.cmos_data[7]);
    printf("              0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x, index 0x%2.2x\n",
           r.cmos_data[8], r.cmos_data[9], r.cmos_data[10], r.cmos_data[11], 
           r.cmos_data[12], r.cmos_data[13], r.cmos_index);

}

static void dump_hpet(void)
{
    int i;
    HVM_SAVE_TYPE(HPET) h;
    READ(h);
    printf("    HPET: capability %#llx config %#llx\n",
           (unsigned long long) h.capability,
           (unsigned long long) h.config);
    printf("          isr %#llx counter %#llx\n",
           (unsigned long long) h.isr,
           (unsigned long long) h.mc64);
    for ( i = 0; i < HPET_TIMER_NUM; i++ )
    {
        printf("          timer%i config %#llx cmp %#llx\n", i,
               (unsigned long long) h.timers[i].config,
               (unsigned long long) h.timers[i].cmp);
        printf("          timer%i period %#llx fsb %#llx\n", i, 
               (unsigned long long) h.period[i],
               (unsigned long long) h.timers[i].fsb);
    }
}

static void dump_pmtimer(void)
{
    HVM_SAVE_TYPE(PMTIMER) p;
    READ(p);
    printf("    ACPI PM: TMR_VAL 0x%x, PM1a_STS 0x%x, PM1a_EN 0x%x\n", 
           p.tmr_val, (unsigned) p.pm1a_sts, (unsigned) p.pm1a_en);
}

static void dump_mtrr(void)
{
    HVM_SAVE_TYPE(MTRR) p;
    int i;
    READ(p);
    printf("    MTRR: PAT 0x%llx, cap 0x%llx, default 0x%llx\n", 
           (unsigned long long) p.msr_pat_cr,
           (unsigned long long) p.msr_mtrr_cap,
           (unsigned long long) p.msr_mtrr_def_type);
    for ( i = 0 ; i < MTRR_VCNT ; i++ )
        printf("          var %i 0x%16.16llx 0x%16.16llx\n", i,
               (unsigned long long) p.msr_mtrr_var[2 * i], 
               (unsigned long long) p.msr_mtrr_var[2 * i + 1]);
    for ( i = 0 ; i < NUM_FIXED_MSR ; i++ )
        printf("          fixed %.2i 0x%16.16llx\n", i,
               (unsigned long long) p.msr_mtrr_fixed[i]);
}

static void dump_viridian_domain(void)
{
    HVM_SAVE_TYPE(VIRIDIAN_DOMAIN) p;
    READ(p);
    printf("    VIRIDIAN_DOMAIN: hypercall gpa 0x%llx, guest_os_id 0x%llx\n",
           (unsigned long long) p.hypercall_gpa,
           (unsigned long long) p.guest_os_id);           
}

static void dump_viridian_vcpu(void)
{
    HVM_SAVE_TYPE(VIRIDIAN_VCPU) p;
    READ(p);
    printf("    VIRIDIAN_VCPU: vp_assist_msr 0x%llx, vp_assist_pending %s\n",
	   (unsigned long long) p.vp_assist_msr,
	   p.vp_assist_pending ? "true" : "false");
}

static void dump_vmce_vcpu(void)
{
    HVM_SAVE_TYPE(VMCE_VCPU) p;
    READ(p);
    printf("    VMCE_VCPU: caps %" PRIx64 "\n", p.caps);
    printf("    VMCE_VCPU: bank0 mci_ctl2 %" PRIx64 "\n", p.mci_ctl2_bank0);
    printf("    VMCE_VCPU: bank1 mci_ctl2 %" PRIx64 "\n", p.mci_ctl2_bank1);
}

static void dump_tsc_adjust(void)
{
    HVM_SAVE_TYPE(TSC_ADJUST) p;
    READ(p);
    printf("    TSC_ADJUST: tsc_adjust %" PRIx64 "\n", p.tsc_adjust);
}

int main(int argc, char **argv)
{
    int entry, domid;
    xc_interface *xch;

    struct hvm_save_descriptor desc;

    if ( argc != 2 || !argv[1] || (domid = atoi(argv[1])) < 0 ) 
    {
        fprintf(stderr, "usage: %s <domid>\n", argv[0]);
        exit(1);
    }

    xch = xc_interface_open(0,0,0);
    if ( !xch )
    {
        fprintf(stderr, "Error: can't open libxc handle\n");
        exit(1);
    }
    len = xc_domain_hvm_getcontext(xch, domid, 0, 0);
    if ( len == (uint32_t) -1 )
    {
        fprintf(stderr, "Error: can't get record length for dom %i\n", domid);
        exit(1);
    }
    buf = malloc(len);
    if ( buf == NULL )
    {
        fprintf(stderr, "Error: can't allocate %u bytes\n", len);
        exit(1);
    }
    len = xc_domain_hvm_getcontext(xch, domid, buf, len);
    if ( len == (uint32_t) -1 )
    {
        fprintf(stderr, "Error: can't get HVM record for dom %i\n", domid);
        exit(1);
    }
    off = 0;

    /* Say hello */
    printf("HVM save record for domain %i\n", domid);

    entry = 0;
    do {
        READ(desc);
        printf("Entry %i: type %u instance %u, length %u\n",
               entry++, (unsigned) desc.typecode,
               (unsigned) desc.instance, (unsigned) desc.length);
        switch (desc.typecode) 
        {
        case HVM_SAVE_CODE(HEADER): dump_header(); break;
        case HVM_SAVE_CODE(CPU): dump_cpu(); break;
        case HVM_SAVE_CODE(PIC): dump_pic(); break;
        case HVM_SAVE_CODE(IOAPIC): dump_ioapic(); break;
        case HVM_SAVE_CODE(LAPIC): dump_lapic(); break;
        case HVM_SAVE_CODE(LAPIC_REGS): dump_lapic_regs(); break;
        case HVM_SAVE_CODE(PCI_IRQ): dump_pci_irq(); break;
        case HVM_SAVE_CODE(ISA_IRQ): dump_isa_irq(); break;
        case HVM_SAVE_CODE(PCI_LINK): dump_pci_link(); break;
        case HVM_SAVE_CODE(PIT): dump_pit(); break;
        case HVM_SAVE_CODE(RTC): dump_rtc(); break;
        case HVM_SAVE_CODE(HPET): dump_hpet(); break;
        case HVM_SAVE_CODE(PMTIMER): dump_pmtimer(); break;
        case HVM_SAVE_CODE(MTRR): dump_mtrr(); break;
        case HVM_SAVE_CODE(VIRIDIAN_DOMAIN): dump_viridian_domain(); break;
        case HVM_SAVE_CODE(VIRIDIAN_VCPU): dump_viridian_vcpu(); break;
        case HVM_SAVE_CODE(VMCE_VCPU): dump_vmce_vcpu(); break;
        case HVM_SAVE_CODE(TSC_ADJUST): dump_tsc_adjust(); break;
        case HVM_SAVE_CODE(END): break;
        default:
            printf(" ** Don't understand type %u: skipping\n",
                   (unsigned) desc.typecode);
            off += (desc.length);
        }
    } while ( desc.typecode != HVM_SAVE_CODE(END) && off < len );

    return 0;
} 
