/* tools/debugger/xenitp.c  - A low-level debugger.
 
   Based on xenctxt.c, but heavily modified.
   Copyright 2007 Tristan Gingold <tgingold@free.fr>
 
   Xenitp is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   Xenitp is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <time.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <argp.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>

#include "xenctrl.h"
#include <xen/sys/privcmd.h>
#include "dis-asm.h"

#ifdef __HYPERVISOR_ia64_debug_op
#define HAVE_DEBUG_OP
#include <xen/arch-ia64/debug_op.h>
#endif

static xc_interface *xc_handle = 0;
static int domid = 0;
static vcpu_guest_context_t *cur_ctx;
static int cur_vcpu;

#define PSR_BN              (1UL << 44)
#define PSR_SS              (1UL << 40)
#define PSR_DB              (1UL << 24)
#define PSR_TB              (1UL << 26)
#define PSR_DD              (1UL << 39)
#define PSR_ID              (1UL << 37)
#define PSR_IT              (1UL << 36)
#define PSR_DT              (1UL << 17)
#define PSR_RI_SHIFT             41
#define CFM_SOF_MASK            0x3f

int virt_to_phys (int is_inst, unsigned long vaddr, unsigned long *paddr);

/* wrapper for vcpu_gest_context_any_t */
static int xc_ia64_vcpu_getcontext(xc_interface *xc_handle,
                                   uint32_t domid,
                                   uint32_t vcpu,
                                   vcpu_guest_context_t *ctxt)
{
    return xc_vcpu_getcontext(xc_handle, domid, vcpu,
                              (vcpu_guest_context_any_t *)ctxt);
}

static inline unsigned int ctx_slot (vcpu_guest_context_t *ctx)
{
    return (ctx->regs.psr >> PSR_RI_SHIFT) & 3;
}

unsigned char *
target_map_memory (unsigned long paddr)
{
    static unsigned long cur_page = (unsigned long)-1;
    static unsigned char *cur_map = NULL;

    if ((paddr >> XC_PAGE_SHIFT) != cur_page) {
        if (cur_map) {
            munmap (cur_map, XC_PAGE_SIZE);
            cur_map = NULL;
        }
        cur_page = paddr >> XC_PAGE_SHIFT;
        cur_map = xc_map_foreign_range (xc_handle, domid, XC_PAGE_SIZE,
                                        PROT_READ, cur_page);
        if (cur_map == NULL) {
            perror ("cannot map page");
            cur_page = -1;
            return NULL;
        }
    }
    return cur_map + (paddr & (XC_PAGE_SIZE - 1));
}

/* Get LENGTH bytes from info's buffer, at target address memaddr.
   Transfer them to myaddr.  */
int
target_read_memory (bfd_vma memaddr, bfd_byte *myaddr,
                    unsigned int length, struct disassemble_info *info)
{
    int i;
    unsigned long paddr;

    if (cur_ctx->regs.psr & PSR_IT) {
        if (virt_to_phys (1, memaddr, &paddr) != 0)
            return EIO;
    }
    else {
        /* Clear UC.  */
        paddr = memaddr & ~(1UL << 63);
    }

    for (i = 0; i < length; i++) {
        unsigned char *p = target_map_memory (paddr + i);

        if (p == NULL)
            return EIO;
        myaddr[i] = *p;
    }
    return 0;
}

/* Print an error message.  We can assume that this is in response to
   an error return from buffer_read_memory.  */
void
perror_memory (int status, bfd_vma memaddr, struct disassemble_info *info)
{
    if (status != EIO)
        /* Can't happen.  */
        (*info->fprintf_func) (info->stream, "Unknown error %d\n", status);
    else
        /* Actually, address between memaddr and memaddr + len was
           out of bounds.  */
        (*info->fprintf_func) (info->stream,
                               "Address 0x%" PRIx64 " is out of bounds.\n",
                               memaddr);
}

/* This could be in a separate file, to save miniscule amounts of space
   in statically linked executables.  */

/* Just print the address is hex.  This is included for completeness even
   though both GDB and objdump provide their own (to print symbolic
   addresses).  */

void
generic_print_address (bfd_vma addr, struct disassemble_info *info)
{
    (*info->fprintf_func) (info->stream, "0x%" PRIx64, addr);
}

/* Just return the given address.  */

int
generic_symbol_at_address (bfd_vma addr, struct disassemble_info * info)
{
    return 1;
}

bfd_boolean
generic_symbol_is_valid (asymbol * sym ATTRIBUTE_UNUSED,
                         struct disassemble_info *info ATTRIBUTE_UNUSED)
{
    return 1;
}

bfd_vma bfd_getl32 (const bfd_byte *addr)
{
    unsigned long v;

    v = (unsigned long) addr[0];
    v |= (unsigned long) addr[1] << 8;
    v |= (unsigned long) addr[2] << 16;
    v |= (unsigned long) addr[3] << 24;

    return (bfd_vma) v;
}

bfd_vma bfd_getl64 (const bfd_byte *addr)
{
    unsigned long v;

    v = (unsigned long) addr[0];
    v |= (unsigned long) addr[1] << 8;
    v |= (unsigned long) addr[2] << 16;
    v |= (unsigned long) addr[3] << 24;
    v |= (unsigned long) addr[4] << 32;
    v |= (unsigned long) addr[5] << 40;
    v |= (unsigned long) addr[6] << 48;
    v |= (unsigned long) addr[7] << 56;

    return (bfd_vma) v;
}

bfd_vma bfd_getb32 (const bfd_byte *addr)
{
    unsigned long v;

    v = (unsigned long) addr[0] << 24;
    v |= (unsigned long) addr[1] << 16;
    v |= (unsigned long) addr[2] << 8;
    v |= (unsigned long) addr[3];

    return (bfd_vma) v;
}

bfd_vma bfd_getl16 (const bfd_byte *addr)
{
    unsigned long v;

    v = (unsigned long) addr[0];
    v |= (unsigned long) addr[1] << 8;

    return (bfd_vma) v;
}

bfd_vma bfd_getb16 (const bfd_byte *addr)
{
    unsigned long v;

    v = (unsigned long) addr[0] << 24;
    v |= (unsigned long) addr[1] << 16;

    return (bfd_vma) v;
}

void
init_disassemble_info (struct disassemble_info *info, void *stream,
		       fprintf_ftype fprintf_func)
{
    memset (info, 0, sizeof (*info));

    info->flavour = bfd_target_unknown_flavour;
    info->arch = bfd_arch_unknown;
    info->endian = BFD_ENDIAN_UNKNOWN;
    info->octets_per_byte = 1;
    info->fprintf_func = fprintf_func;
    info->stream = stream;
    info->read_memory_func = target_read_memory;
    info->memory_error_func = perror_memory;
    info->print_address_func = generic_print_address;
    info->symbol_at_address_func = generic_symbol_at_address;
    info->symbol_is_valid = generic_symbol_is_valid;
    info->display_endian = BFD_ENDIAN_UNKNOWN;
}


void target_disas (FILE *out, unsigned long code, unsigned long size)
{
    unsigned long pc;
    int count;
    struct disassemble_info disasm_info;

    INIT_DISASSEMBLE_INFO(disasm_info, out, fprintf);

    disasm_info.read_memory_func = target_read_memory;
#if 0
    disasm_info.buffer = NULL;
    disasm_info.buffer_vma = (unsigned long)code;
    disasm_info.buffer_length = size;
#endif

    disasm_info.endian = BFD_ENDIAN_LITTLE;
    disasm_info.mach = 0; //bfd_mach_ia64;

    for (pc = code; pc < code + size; pc += count) {
        int slot = (pc & 0x0f) / 6;
        fprintf (out, "0x%016lx+%d:%c ", pc & ~0x0fUL, slot,
                 ((pc & ~0x0fUL) == cur_ctx->regs.ip
                  && slot == ctx_slot (cur_ctx)) ? '*' : ' ');

        count = print_insn_ia64 (pc, &disasm_info);

#if 0
        {
            int i;
            uint8_t b;

            fprintf (out, " {");
            for (i = 0; i < count; i++) {
                target_read_memory (pc + i, &b, 1, &disasm_info);
                fprintf (out, " %02x", b);
            }
            fprintf (out, " }");
        }
#endif
        fprintf (out, "\n");
        if (count < 0)
            break;
    }
}


#define PTE_ED_SHIFT              52
#define PTE_ED_MASK                1
#define PTE_PPN_SHIFT             12
#define PTE_PPN_MASK    0x3fffffffff
#define PTE_AR_SHIFT               9
#define PTE_AR_MASK                7
#define PTE_PL_SHIFT               7
#define PTE_PL_MASK                3
#define PTE_D_SHIFT                6
#define PTE_D_MASK                 1
#define PTE_A_SHIFT                5
#define PTE_A_MASK                 1
#define PTE_MA_SHIFT               2
#define PTE_MA_MASK                7
#define PTE_P_SHIFT                0
#define PTE_P_MASK                 1
#define ITIR_KEY_SHIFT             8
#define ITIR_KEY_MASK       0xffffff
#define ITIR_PS_SHIFT              2
#define ITIR_PS_MASK            0x3f
#define ITIR_PS_MIN               12
#define ITIR_PS_MAX               28
#define RR_RID_SHIFT               8
#define RR_RID_MASK         0xffffff
#define RR_PS_SHIFT                2
#define RR_PS_MASK              0x3f
#define RR_VE_MASK                 1

static const char *get_ps (int ps_val)
{
    static const char ps[][5] = {"  4K", "  8K", " 16K", "    ",
                                 " 64K", "    ", "256K", "    ",
                                 "  1M", "    ", "  4M", "    ",
                                 " 16M", "    ", " 64M", "    ",
                                 "256M"};
    return ((ps_val >= ITIR_PS_MIN && ps_val <= ITIR_PS_MAX) ?
            ps[ps_val - ITIR_PS_MIN] : "    ");

}

static void print_a_tr (int i, const struct ia64_tr_entry *tr)
{
    int ps_val, ma_val;
    unsigned long pa;

    static const char ma[][4] = {"WB ", "   ", "   ", "   ",
                                 "UC ", "UCE", "WC ", "Nat"};

    ps_val =  tr->itir >> ITIR_PS_SHIFT & ITIR_PS_MASK;
    ma_val =  tr->pte  >> PTE_MA_SHIFT  & PTE_MA_MASK;
    pa     = (tr->pte  >> PTE_PPN_SHIFT & PTE_PPN_MASK) << PTE_PPN_SHIFT;
    pa     = (pa >> ps_val) << ps_val;
    printf (" [%2d] %ld %06lx %016lx %013lx %02d %s %ld  %ld  %ld  %ld "
           "%ld %d %s %06lx\n", i,
           tr->pte >> PTE_P_SHIFT    & PTE_P_MASK,
           tr->rid >> RR_RID_SHIFT   & RR_RID_MASK,
           tr->vadr, pa, ps_val, get_ps (ps_val),
           tr->pte >> PTE_ED_SHIFT   & PTE_ED_MASK,
           tr->pte >> PTE_PL_SHIFT   & PTE_PL_MASK,
           tr->pte >> PTE_AR_SHIFT   & PTE_AR_MASK,
           tr->pte >> PTE_A_SHIFT    & PTE_A_MASK,
           tr->pte >> PTE_D_SHIFT    & PTE_D_MASK,
           ma_val, ma[ma_val],
           tr->itir >> ITIR_KEY_SHIFT & ITIR_KEY_MASK);
}

void print_ctx (vcpu_guest_context_t *ctx)
{
    struct vcpu_guest_context_regs *regs = &ctx->regs;
    int i;
    unsigned int rbs_size, cfm_sof;

    rbs_size = (regs->ar.bsp - regs->ar.bspstore) / 8;
    cfm_sof = (regs->cfm & CFM_SOF_MASK);
    printf ("bspstore: %016lx  bsp: %016lx rbs_size=%d, sof=%d\n",
            regs->ar.bspstore, regs->ar.bsp, rbs_size, cfm_sof);

    for (i = 0; i < cfm_sof; i++) {
        int off = cfm_sof - i;
        unsigned int rbs_off =
            (((62 - ((rbs_size + regs->rbs_voff) % 64) + off)) / 63) + off;
        if (rbs_off > rbs_size)
            break;
        printf (" r%02d: %016lx%s", 32 + i,
                regs->rbs[rbs_size - rbs_off],
                (i % 3) != 2 ? "  " : "\n");
    }
    if ((i % 3) != 0)
        printf ("\n");

    printf ("\n");
    printf (" r1:  %016lx  ", regs->r[1]);
    printf (" r2:  %016lx  ", regs->r[2]);
    printf (" r3:  %016lx\n", regs->r[3]);
    printf (" r4:  %016lx  ", regs->r[4]);
    printf (" r5:  %016lx  ", regs->r[5]);
    printf (" r6:  %016lx\n", regs->r[6]);
    printf (" r7:  %016lx  ", regs->r[7]);
    printf (" r8:  %016lx  ", regs->r[8]);
    printf (" r9:  %016lx\n", regs->r[9]);
    printf (" r10: %016lx  ", regs->r[10]);
    printf (" r11: %016lx  ", regs->r[11]);
    printf (" sp:  %016lx\n", regs->r[12]);
    printf (" tp:  %016lx  ", regs->r[13]);
    printf (" r14: %016lx  ", regs->r[14]);
    printf (" r15: %016lx\n", regs->r[15]);
    printf (" r16: %016lx  ", regs->r[16]);
    printf (" r17: %016lx  ", regs->r[17]);
    printf (" r18: %016lx\n", regs->r[18]);
    printf (" r19: %016lx  ", regs->r[19]);
    printf (" r20: %016lx  ", regs->r[20]);
    printf (" r21: %016lx\n", regs->r[21]);
    printf (" r22: %016lx  ", regs->r[22]);
    printf (" r23: %016lx  ", regs->r[23]);
    printf (" r24: %016lx\n", regs->r[24]);
    printf (" r25: %016lx  ", regs->r[25]);
    printf (" r26: %016lx  ", regs->r[26]);
    printf (" r27: %016lx\n", regs->r[27]);
    printf (" r28: %016lx  ", regs->r[28]);
    printf (" r29: %016lx  ", regs->r[29]);
    printf (" r30: %016lx\n", regs->r[30]);
    printf (" r31: %016lx  ", regs->r[31]);
    printf ("                        ");
    printf (" b0:  %016lx\n", regs->b[0]);

    printf ("\n");
    printf (" psr: %016lx  ", regs->psr);
    printf (" cfm: %016lx  ", regs->cfm);
    printf (" pr:  %016lx\n", regs->pr);

    printf ("\n");
    printf (" ip:  %016lx+%d", regs->ip, (int)(regs->psr >> PSR_RI_SHIFT) & 3);
    printf ("\n");
    target_disas (stdout, regs->ip, 16);
}

void print_br (vcpu_guest_context_t *ctx)
{
    struct vcpu_guest_context_regs *regs = &ctx->regs;

    printf (" b0:  %016lx  ", regs->b[0]);
    printf (" b1:  %016lx  ", regs->b[1]);
    printf (" b2:  %016lx\n", regs->b[2]);
    printf (" b3:  %016lx  ", regs->b[3]);
    printf (" b4:  %016lx  ", regs->b[4]);
    printf (" b5:  %016lx\n", regs->b[5]);
    printf (" b6:  %016lx  ", regs->b[6]);
    printf (" b7:  %016lx\n", regs->b[7]);
}

void print_regs (vcpu_guest_context_t *ctx)
{
    struct vcpu_guest_context_regs *regs = &ctx->regs;

    printf (" r1:  %016lx  ", regs->r[1]);
    printf (" r2:  %016lx  ", regs->r[2]);
    printf (" r3:  %016lx\n", regs->r[3]);
    printf (" r4:  %016lx  ", regs->r[4]);
    printf (" r5:  %016lx  ", regs->r[5]);
    printf (" r6:  %016lx\n", regs->r[6]);
    printf (" r7:  %016lx  ", regs->r[7]);
    printf (" r8:  %016lx  ", regs->r[8]);
    printf (" r9:  %016lx\n", regs->r[9]);
    printf (" r10: %016lx  ", regs->r[10]);
    printf (" r11: %016lx  ", regs->r[11]);
    printf (" sp:  %016lx\n", regs->r[12]);
    printf (" tp:  %016lx  ", regs->r[13]);
    printf (" r14: %016lx  ", regs->r[14]);
    printf (" r15: %016lx\n", regs->r[15]);

    printf ("      Bank %d (current)                         Bank %d\n",
            (regs->psr & PSR_BN) ? 1 : 0, (regs->psr & PSR_BN) ? 0 : 1);
    printf ("16:%016lx ", regs->r[16]);
    printf ("17:%016lx ", regs->r[17]);
    printf ("16:%016lx ", regs->bank[0]);
    printf ("17:%016lx\n", regs->bank[1]);
    printf ("18:%016lx ", regs->r[18]);
    printf ("19:%016lx ", regs->r[19]);
    printf ("18:%016lx ", regs->bank[2]);
    printf ("19:%016lx\n", regs->bank[3]);
    printf ("20:%016lx ", regs->r[20]);
    printf ("21:%016lx ", regs->r[21]);
    printf ("20:%016lx ", regs->bank[4]);
    printf ("21:%016lx\n", regs->bank[5]);
    printf ("22:%016lx ", regs->r[22]);
    printf ("23:%016lx ", regs->r[23]);
    printf ("22:%016lx ", regs->bank[6]);
    printf ("23:%016lx\n", regs->bank[7]);
    printf ("24:%016lx ", regs->r[24]);
    printf ("25:%016lx ", regs->r[25]);
    printf ("24:%016lx ", regs->bank[8]);
    printf ("25:%016lx\n", regs->bank[9]);
    printf ("26:%016lx ", regs->r[26]);
    printf ("27:%016lx ", regs->r[27]);
    printf ("26:%016lx ", regs->bank[10]);
    printf ("27:%016lx\n", regs->bank[11]);
    printf ("28:%016lx ", regs->r[28]);
    printf ("29:%016lx ", regs->r[29]);
    printf ("28:%016lx ", regs->bank[12]);
    printf ("29:%016lx\n", regs->bank[13]);
    printf ("30:%016lx ", regs->r[30]);
    printf ("31:%016lx ", regs->r[31]);
    printf ("30:%016lx ", regs->bank[14]);
    printf ("31:%016lx\n", regs->bank[15]);
    printf ("\n");
}

void print_cr (vcpu_guest_context_t *ctx)
{
    struct vcpu_guest_context_regs *regs = &ctx->regs;

    printf (" dcr:  %016lx  ", regs->cr.dcr);
    printf (" itm:  %016lx  ", regs->cr.itm);
    printf (" iva:  %016lx\n", regs->cr.iva);
    printf (" pta:  %016lx  ", regs->cr.pta);
    printf (" ipsr: %016lx  ", regs->cr.ipsr);
    printf (" isr:  %016lx\n", regs->cr.isr);
    printf (" iip:  %016lx  ", regs->cr.iip);
    printf (" ifa:  %016lx  ", regs->cr.ifa);
    printf (" itir: %016lx\n", regs->cr.itir);
    printf (" iipa: %016lx  ", regs->cr.iipa);
    printf (" ifs:  %016lx  ", regs->cr.ifs);
    printf (" iim:  %016lx\n", regs->cr.iim);
    printf (" iha:  %016lx  ", regs->cr.iha);
    printf (" lid:  %016lx  ", regs->cr.lid);
    printf (" ivr:  %016lx\n", regs->cr.ivr);
    printf (" tpr:  %016lx  ", regs->cr.tpr);
    printf (" eoi:  %016lx  ", regs->cr.eoi);
    printf (" irr0: %016lx\n", regs->cr.irr[0]);
    printf (" irr1: %016lx  ", regs->cr.irr[1]);
    printf (" irr2: %016lx  ", regs->cr.irr[2]);
    printf (" irr3: %016lx\n", regs->cr.irr[3]);
    printf (" itv:  %016lx  ", regs->cr.itv);
    printf (" pmv:  %016lx  ", regs->cr.pmv);
    printf (" cmcv: %016lx\n", regs->cr.cmcv);
    printf (" lrr0: %016lx  ", regs->cr.lrr0);
    printf (" lrr1: %016lx  ", regs->cr.lrr1);
    printf (" ev_cb:%016lx\n", ctx->event_callback_ip);
}

void print_ar (vcpu_guest_context_t *ctx)
{
    struct vcpu_guest_context_regs *regs = &ctx->regs;

    printf (" kr0:  %016lx  ", regs->ar.kr[0]);
    printf (" kr1:  %016lx  ", regs->ar.kr[1]);
    printf (" kr2:  %016lx\n", regs->ar.kr[2]);
    printf (" kr3:  %016lx  ", regs->ar.kr[3]);
    printf (" kr4:  %016lx  ", regs->ar.kr[4]);
    printf (" kr5:  %016lx\n", regs->ar.kr[5]);
    printf (" kr6:  %016lx  ", regs->ar.kr[6]);
    printf (" kr7:  %016lx  ", regs->ar.kr[7]);
    printf (" rsc:  %016lx\n", regs->ar.rsc);
    printf (" bsp:  %016lx  ", regs->ar.bsp);
    printf (" bsps: %016lx  ", regs->ar.bspstore);
    printf (" rnat: %016lx\n", regs->ar.rnat);
    printf (" csd:  %016lx  ", regs->ar.csd);
    printf (" ccv:  %016lx  ", regs->ar.ccv);
    printf (" unat: %016lx\n", regs->ar.unat);
    printf (" fpsr: %016lx  ", regs->ar.fpsr);
    printf (" itc:  %016lx\n", regs->ar.itc);
    printf (" pfs:  %016lx  ", regs->ar.pfs);
    printf (" lc:   %016lx  ", regs->ar.lc);
    printf (" ec:   %016lx\n", regs->ar.ec);
}

void print_a_rr (int num, unsigned long rr)
{
    int ps_val = (rr >> RR_PS_SHIFT) & RR_PS_MASK;

    printf (" [%d]  %06lx %02x %s %ld\n",
            num, (rr >> RR_RID_SHIFT) & RR_RID_MASK,
            ps_val, get_ps (ps_val), rr & RR_VE_MASK);
}

void print_rr (vcpu_guest_context_t *ctx)
{
    struct vcpu_guest_context_regs *regs = &ctx->regs;
    int i;

    printf (" rr:  rid    ps      ve\n");
    for (i = 0; i < 8; i++)
        print_a_rr (i, regs->rr[i]);
}

void print_db (vcpu_guest_context_t *ctx)
{
    struct vcpu_guest_context_regs *regs = &ctx->regs;
    int i;

    for (i = 0; i < 7; i += 2)
        printf ("  ibr[%d]:  %016lx   ibr[%d]:  %016lx\n",
                i, regs->ibr[i], i + 1, regs->ibr[i + 1]);
    printf ("\n");
    for (i = 0; i < 7; i += 2)
        printf ("  dbr[%d]:  %016lx   dbr[%d]:  %016lx\n",
                i, regs->dbr[i], i + 1, regs->dbr[i + 1]);
}

struct bit_descr {
    const char *name;
    unsigned char sz;
};

const struct bit_descr psr_bits[] = 
    {
        {"", 1 },    {"be", 1 },  {"up", 1 },  {"ac", 1 },
        {"mfl", 1 }, {"mfh", 1 }, {"", 7 },
        {"ic", 1 },  {"i", 1 },   {"pk", 1 },
        {"", 1 },    {"dt", 1 },  {"dfl", 1 }, {"dfh", 1 },
        {"sp", 1 },  {"pp", 1 },  {"di", 1 },  {"si", 1 },
        {"db", 1 },  {"lp", 1 },  {"tb", 1 },  {"rt", 1 },
        {"", 4 },
        {"cpl", 2 }, {"is", 1 },  {"mc", 1 },
        {"it", 1 },  {"id", 1 },  {"da", 1 },  {"dd", 1 },
        {"ss", 1 },  {"ri", 2 },  {"ed", 1 },
        {"bn", 1 },  {"ia", 1 },  {"vm", 1 },
        {NULL, 0 }
    };

void print_bits (const struct bit_descr *desc, unsigned long val)
{
    const struct bit_descr *d;
    unsigned int off;

    /* Reverse order.  */
    for (d = desc, off = 0; d->name; d++)
        off += d->sz;

    d--;

    while (1) {
        off -= d->sz;
        if (*d->name) {
            if (d->sz != 1 || ((val >> off) & 1))
                printf (" %s", d->name);
            if (d->sz != 1)
                printf ("=%lx", (val >> off) & ((1 << d->sz) - 1));
        }
        if (d == desc)
            break;
        d--;
    }
}
        
void print_tr (vcpu_guest_context_t *ctx)
{
    struct vcpu_tr_regs *tr = &ctx->regs.tr;
    int i;

    printf ("\n itr: P rid    va               pa            ps      ed pl "
            "ar a d ma    key\n");

    for (i = 0; i < sizeof (tr->itrs) / sizeof (tr->itrs[0]); i++)
        print_a_tr (i, &tr->itrs[i]);

    printf ("\n dtr: P rid    va               pa            ps      ed pl "
            "ar a d ma    key\n");

    for (i = 0; i < sizeof (tr->dtrs) / sizeof (tr->dtrs[0]); i++)
        print_a_tr (i, &tr->dtrs[i]);
}

int lock_pages (void *addr, size_t len);
void unlock_pages (void *addr, size_t len);
int do_xen_hypercall (xc_interface *xc_handle, privcmd_hypercall_t *hypercall);

#ifdef HAVE_DEBUG_OP
static int do_ia64_debug_op (xc_interface *xc_handle,
                            unsigned long cmd, unsigned long domain,
                            xen_ia64_debug_op_t *op)
{
    int ret = -1;
    privcmd_hypercall_t hypercall;

    hypercall.op     = __HYPERVISOR_ia64_debug_op;
    hypercall.arg[0] = cmd;
    hypercall.arg[1] = domain;
    hypercall.arg[2] = (unsigned long)op;

    if (lock_pages (op, sizeof (*op)) != 0) {
        perror ("Could not lock memory for Xen hypercall");
        goto out1;
    }

    ret = do_xen_hypercall (xc_handle, &hypercall);
    if (ret  < 0) {
        if (errno == EACCES)
            fprintf (stderr,"domctl operation failed -- need to "
                     "rebuild the user-space tool set?\n");
    }

    unlock_pages (op, sizeof (*op));

out1:
    return ret;
}
#endif

static volatile int ctrl_c_hit;

void ctrl_c_handler (int sig)
{
    ctrl_c_hit = 1;
}

int wait_domain (int vcpu, vcpu_guest_context_t *ctx)
{
    struct timespec ts;
    xc_dominfo_t dominfo;
    int ret;
    int cnt = 0;

    ts.tv_sec = 0;
    ts.tv_nsec = 10*1000*1000;

    ret = xc_domain_unpause (xc_handle, domid);
    if (ret < 0)
        perror ("xc_domain_unpause");

    ctrl_c_hit = 0;

    while (1) {
        ret = xc_domain_getinfo (xc_handle, domid, 1, &dominfo);
        if (ret < 0)
            perror ("xc_domain_getinfo");

        if (dominfo.paused)
            break;

        if (ctrl_c_hit) {
            fflush (stdout);
            /* Force pause.  */
            ret = xc_domain_pause (xc_handle, domid);
            if (ret < 0)
                perror ("xc_domain_pause");

            break;
        }
                
        printf ("%c\b", "/-\\|"[(cnt++) % 4]);
        fflush (stdout);
        nanosleep (&ts, NULL);
    }
    return xc_ia64_vcpu_getcontext (xc_handle, domid, vcpu, ctx);
}

int virt_to_phys (int is_inst, unsigned long vaddr, unsigned long *paddr)
{
    struct vcpu_tr_regs *trs = &cur_ctx->regs.tr;
    struct ia64_tr_entry *tr;
    int i;
    int num;

    /* Search in tr.  */
    if (is_inst) {
        tr = trs->itrs;
        num = sizeof (trs->itrs) / sizeof (trs->itrs[0]);
    }
    else {
        tr = trs->dtrs;
        num = sizeof (trs->dtrs) / sizeof (trs->dtrs[0]);
    }
    for (i = 0; i < num; i++, tr++) {
        int ps_val = (tr->itir >> ITIR_PS_SHIFT) & ITIR_PS_MASK;
        unsigned long ps_mask = (-1L) << ps_val;

        if ((tr->vadr & ps_mask) == (vaddr & ps_mask)) {
            *paddr = ((tr->pte & (PTE_PPN_MASK << PTE_PPN_SHIFT)) & ps_mask) |
                     (vaddr & ~ps_mask);
            return 0;
        }
    }
    return -1;
}

unsigned long *
get_reg_addr (const char *name)
{
    if (strcmp (name, "ip") == 0)
        return &cur_ctx->regs.ip;
    else if (strcmp (name, "psr") == 0)
        return &cur_ctx->regs.psr;
    else if (strcmp (name, "iip") == 0)
        return &cur_ctx->regs.cr.iip;
    else if (strcmp (name, "b0") == 0)
        return &cur_ctx->regs.b[0];
    else
        return 0;
}

enum prio_expr {EXPR_BASE, EXPR_SUM, EXPR_LOGIC, EXPR_PROD};

int parse_expr (char **buf, unsigned long *res, enum prio_expr prio);

int next_char (char **buf)
{
    char *b;

    b = *buf;
    while (isspace ((unsigned char)*b))
        b++;
    *buf = b;
    return *b;
}

int parse_unary (char **buf, unsigned long *res)
{
    char c;

    c = next_char (buf);
    switch (c) {
    case '0' ... '9':
        {
            char *e;
            *res = strtoul (*buf, &e, 0);
            if (e == *buf) {
                printf ("bad literal\n");
                return -1;
            }
            *buf = e;
        }
        break;
    case '+':
        (*buf)++;
        return parse_unary (buf, res);
    case '$':
        {
            char *b;
            char *e;
            char c;
            unsigned long *reg;
            int len;

            b = *buf;
            e = b + 1;

            while ((*e >= 'a' && *e <= 'z') ||
                   (*e >= 'A' && *e <= 'Z') ||
                   (*e >= '0' && *e <= '9') ||
                   (*e == '_' || *e == '.'))
                e++;

            if (b == e) {
                printf ("identifier missing after '$'\n");
                return -1;
            }

            b++;
            len = e - b;

            c = b[len];
            b[len] = 0;
            reg = get_reg_addr (b);
            b[len] = c;

            if (reg != NULL)
                *res = *reg;
            else if (strncmp (b, "d2p", len) == 0 ||
                     strncmp (b, "i2p", len) == 0) {
                unsigned long vaddr;

                *buf = e;
                if (parse_unary (buf, &vaddr) != 0)
                    return -1;
                if (virt_to_phys (*b == 'i', vaddr, res) != 0) {
                    printf ("cannot find vaddr %016lx in tr\n", vaddr);
                    return -1;
                }
                return 0;
            }
            else {
                printf ("unknown symbol\n");
                return -1;
            }
            *buf = e;
        }
        break;
    case '(':
        (*buf)++;
        if (parse_expr (buf, res, EXPR_BASE) != 0)
            return -1;

        if (next_char (buf) != ')') {
            printf ("missing ')'\n");
            return -1;
        }
        else
            (*buf)++;
        break;
    default:
        printf ("unknown operand '%c' in expression\n", c);
        return -1;
    }

    return 0;
}

int parse_expr (char **buf, unsigned long *res, enum prio_expr prio)
{
    unsigned long val = 0;
    unsigned long val1;
    char c;

    if (parse_unary (buf, &val) != 0)
        return -1;

    while (1) {
        c = next_char (buf);
        switch (c) {
        case '+':
        case '-':
            if (prio > EXPR_SUM)
                return 0;
            (*buf)++;
            if (parse_expr (buf, &val1, EXPR_SUM) < 0)
                return -1;
            if (c == '+')
                val += val1;
            else
                val -= val1;
            break;
        case '*':
            if (prio > EXPR_PROD)
                return 0;

            (*buf)++;
            if (parse_expr (buf, &val1, EXPR_SUM) < 0)
                return -1;

            val *= val1;
            break;
        default:
            *res = val;
            return 0;
        }
    }
}

char *parse_arg (char **buf)
{
    char *res;
    char *b = *buf;

    /* Eat leading spaces.  */
    while (isspace ((unsigned char)*b))
        b++;

    res = b;
    while (*b && !isspace ((unsigned char)*b))
        b++;

    /* Set the NUL terminator.  */
    if (*b)
        *b++ = 0;

    *buf = b;
    return res;
}

vcpu_guest_context_any_t *vcpu_ctx_any;

int vcpu_setcontext (int vcpu)
{
    int ret;

    ret = xc_vcpu_setcontext (xc_handle, domid, vcpu, &vcpu_ctx_any[vcpu]);
    if (ret < 0)
        perror ("xc_vcpu_setcontext");

    return ret;
}

enum cmd_status { CMD_ERROR, CMD_OK, CMD_REPEAT, CMD_QUIT };

struct command_desc
{
    const char *name;
    const char *help;
    enum cmd_status (*cmd)(char *line);
};

static enum cmd_status
cmd_registers (char *line)
{
    print_ctx (cur_ctx);
    return CMD_OK;
}

static enum cmd_status
cmd_sstep (char *line)
{
    /* Set psr.dd and psr.id to skip over current breakpoint.  */
    cur_ctx->regs.psr |= PSR_SS | PSR_DD | PSR_ID;
    cur_ctx->regs.psr &= ~PSR_TB;
    if (vcpu_setcontext (cur_vcpu) < 0)
        return CMD_ERROR;

    if (wait_domain (cur_vcpu, cur_ctx) < 0) {
        perror ("wait_domain");
        return CMD_ERROR;
    }

    print_ctx (cur_ctx);

    return CMD_REPEAT;
}

static enum cmd_status
cmd_go (char *line)
{
    unsigned long n = 1;

    if (*line != 0) {
        if (parse_expr (&line, &n, 0) < 0)
            return CMD_ERROR;
    }
    while (n > 0) {
        /* Set psr.dd and psr.id to skip over current breakpoint.  */
        if ((cur_ctx->regs.psr & (PSR_SS | PSR_TB | PSR_DB)) != 0) {
            cur_ctx->regs.psr &= ~(PSR_SS | PSR_TB);
            cur_ctx->regs.psr |= PSR_DD | PSR_ID;
            if (vcpu_setcontext (cur_vcpu) < 0)
                return CMD_ERROR;
        }

        if (wait_domain (cur_vcpu, cur_ctx) < 0) {
            perror ("wait_domain");
            return CMD_ERROR;
        }
        print_ctx (cur_ctx);
        n--;
    }

    return CMD_REPEAT;
}

static enum cmd_status
cmd_cb (char *line)
{
    if ((cur_ctx->regs.psr & (PSR_SS | PSR_TB)) != PSR_TB) {
        cur_ctx->regs.psr &= ~PSR_SS;
        cur_ctx->regs.psr |= PSR_TB;
        if (vcpu_setcontext (cur_vcpu) < 0)
            return CMD_ERROR;
    }

    if (wait_domain (cur_vcpu, cur_ctx) < 0) {
        perror ("wait_domain");
        return CMD_ERROR;
    }

    print_ctx (cur_ctx);

    return CMD_REPEAT;
}

static int quit_paused;

static enum cmd_status
cmd_quit (char *line)
{
    if (!strcmp (line, "paused"))
        quit_paused = 1;
    return CMD_QUIT;
}

static enum cmd_status
cmd_echo (char *line)
{
    printf ("%s", line);
    return CMD_OK;
}

static enum cmd_status
cmd_disassemble (char *args)
{
    static unsigned long addr;
    unsigned long end_addr = addr + 16;

    if (*args != 0) {
        if (parse_expr (&args, &addr, 0) < 0)
            return CMD_ERROR;
        if (*args != 0) {
            if (parse_expr (&args, &end_addr, 0) < 0)
                return CMD_ERROR;
        }
        else 
            end_addr = addr + 16;
    }
    target_disas (stdout, addr, end_addr - addr);
    addr = end_addr;
    return CMD_REPEAT;
}

static enum cmd_status
cmd_dump (char *args)
{
    static unsigned long addr;
    unsigned long end_addr = addr + 256;
    unsigned long p;

    if (*args != 0) {
        if (parse_expr (&args, &addr, 0) < 0)
            return CMD_ERROR;
        if (*args != 0) {
            if (parse_expr (&args, &end_addr, 0) < 0)
                return CMD_ERROR;
        }
        else 
            end_addr = addr + 256;
    }
    for (p = addr; p < end_addr; p += 16) {
        int i;
        printf ("%016lx:", p);
        for (i = 0; i < 16; i++) {
            unsigned char *m = target_map_memory (p + i);
            printf ("%c%02x", i == 8 ? '-' : ' ', *m);
        }
        printf ("\n");
    }
    addr = end_addr;
    return CMD_REPEAT;
}

static enum cmd_status
cmd_break (char *args)
{
    unsigned long addr;
    int i;

    for (i = 0; i < 4; i++)
        if (cur_ctx->regs.ibr[2 * i] == 0 && cur_ctx->regs.ibr[2 * i + 1] == 0)
            break;

    if (i == 4) {
        printf ("no availabe break points\n");
        return CMD_ERROR;
    }

    if (parse_expr (&args, &addr, 0) < 0)
        return CMD_ERROR;

    cur_ctx->regs.ibr[2 * i] = addr;
    cur_ctx->regs.ibr[2 * i + 1] = 0x87fffffffffffff0UL;
    cur_ctx->regs.psr |= PSR_DB;

    if (vcpu_setcontext (cur_vcpu) < 0)
        return CMD_ERROR;
    else
        return CMD_OK;
}

static enum cmd_status
cmd_watch (char *args)
{
    unsigned long addr;
    unsigned long mask;
    int i;

    for (i = 0; i < 4; i++)
        if (cur_ctx->regs.dbr[2 * i] == 0 && cur_ctx->regs.dbr[2 * i + 1] == 0)
            break;

    if (i == 4) {
        printf ("no availabe watch points\n");
        return CMD_ERROR;
    }

    if (parse_expr (&args, &addr, 0) < 0)
        return CMD_ERROR;

    if (*args == 0)
        mask = 3;
    else if (parse_expr (&args, &mask, 0) < 0)
        return CMD_ERROR;

    cur_ctx->regs.dbr[2 * i] = addr;
    cur_ctx->regs.dbr[2 * i + 1] = ~((1UL << mask) - 1) | (0xc7UL << 56);
    cur_ctx->regs.psr |= PSR_DB;

    if (vcpu_setcontext (cur_vcpu) < 0)
        return CMD_ERROR;
    else {
        printf ("Watchpoint %d set\n", i);
        return CMD_OK;
    }
}

static enum cmd_status
cmd_delete (char *args)
{
    unsigned long num;

    if (parse_expr (&args, &num, 0) < 0)
        return CMD_ERROR;

    if (num < 4) {
        cur_ctx->regs.ibr[2 * num] = 0;
        cur_ctx->regs.ibr[2 * num + 1] = 0;
    }
    else if (num < 8) {
        num -= 4;
        cur_ctx->regs.dbr[2 * num] = 0;
        cur_ctx->regs.dbr[2 * num + 1] = 0;
    }
    else {
        printf ("breakpoint out of range\n");
        return CMD_ERROR;
    }

    cur_ctx->regs.psr |= PSR_DB;

    if (vcpu_setcontext (cur_vcpu) < 0)
        return CMD_ERROR;
    else
        return CMD_OK;
}

static enum cmd_status
cmd_disable (char *args)
{
    unsigned long num;

    if (parse_expr (&args, &num, 0) < 0)
        return CMD_ERROR;

    if (num >= 4) {
        printf ("breakpoint out of range\n");
        return CMD_ERROR;
    }

    cur_ctx->regs.ibr[2 * num + 1] &= ~(1UL << 63);

    if (vcpu_setcontext (cur_vcpu) < 0)
        return CMD_ERROR;
    else
        return CMD_OK;
}

static enum cmd_status
cmd_enable (char *args)
{
    unsigned long num;

    if (parse_expr (&args, &num, 0) < 0)
        return CMD_ERROR;

    if (num >= 4) {
        printf ("breakpoint out of range\n");
        return CMD_ERROR;
    }

    cur_ctx->regs.ibr[2 * num + 1] |= 1UL << 63;

    if (vcpu_setcontext (cur_vcpu) < 0)
        return CMD_ERROR;
    else
        return CMD_OK;
}

static enum cmd_status
cmd_print (char *args)
{
    unsigned long addr;

    if (parse_expr (&args, &addr, 0) < 0)
        return CMD_ERROR;

    printf ("res: 0x%016lx = %ld\n", addr, addr);

    return CMD_OK;
}

struct bit_xlat {
    unsigned int bit;
    const char *name;
};

static const struct bit_xlat debug_flags[] = {
    { XEN_IA64_DEBUG_ON_KERN_SSTEP, "sstep" },
    { XEN_IA64_DEBUG_ON_KERN_DEBUG, "debug" },
    { XEN_IA64_DEBUG_ON_KERN_TBRANCH, "tbranch" },
    { XEN_IA64_DEBUG_ON_EXTINT, "extint" },
    { XEN_IA64_DEBUG_ON_EXCEPT, "except" },
    { XEN_IA64_DEBUG_ON_EVENT, "event" },
    { XEN_IA64_DEBUG_ON_PRIVOP, "privop" },
    { XEN_IA64_DEBUG_ON_PAL, "pal" },
    { XEN_IA64_DEBUG_ON_SAL, "sal" },
    { XEN_IA64_DEBUG_ON_EFI, "efi" },
    { XEN_IA64_DEBUG_ON_RFI, "rfi" },
    { XEN_IA64_DEBUG_ON_MMU, "mmu" },
    { XEN_IA64_DEBUG_ON_BAD_MPA, "mpa" },
    { XEN_IA64_DEBUG_FORCE_SS, "ss" },
    { XEN_IA64_DEBUG_FORCE_DB, "db" },
    { XEN_IA64_DEBUG_ON_TR, "tr" },
    { XEN_IA64_DEBUG_ON_TC, "tc" },
#if 0
    { XEN_IA64_DEBUG_ON_KEYS, "keys" },
    { XEN_IA64_DEBUG_ON_MOV_TO_CR, "mov_to_cr" },
    { XEN_IA64_DEBUG_ON_VHPT, "vhpt" },
    { XEN_IA64_DEBUG_ON_IOSAPIC, "iosapic" },
#endif
    { 0, NULL }
};

static enum cmd_status
cmd_disp (char *arg)
{
    if (strcmp (arg, "br") == 0)
        print_br (cur_ctx);
    else if (strcmp (arg, "regs") == 0)
        print_regs (cur_ctx);
    else if (strcmp (arg, "cr") == 0)
        print_cr (cur_ctx);
    else if (strcmp (arg, "ar") == 0)
        print_ar (cur_ctx);
    else if (strcmp (arg, "tr") == 0)
        print_tr (cur_ctx);
    else if (strcmp (arg, "rr") == 0)
        print_rr (cur_ctx);
    else if (strcmp (arg, "db") == 0)
        print_db (cur_ctx);
    else if (strcmp (arg, "psr") == 0) {
        printf ("psr:");
        print_bits (psr_bits, cur_ctx->regs.psr);
        printf ("\n");
    }
    else if (strcmp (arg, "ipsr") == 0) {
        printf ("ipsr:");
        print_bits (psr_bits, cur_ctx->regs.cr.ipsr);
        printf ("\n");
    }
    else if (strcmp (arg, "break") == 0) {
        int i;

        for (i = 0; i < 4; i++)
            if (cur_ctx->regs.ibr[2 * i + 1])
                printf ("%d: 0x%016lx %s\n", i, cur_ctx->regs.ibr[2 * i],
                        (cur_ctx->regs.ibr[2 * i + 1] & (1UL << 63)) ?
                        "enabled" : "disabled");
        for (i = 0; i < 4; i++)
            if (cur_ctx->regs.dbr[2 * i + 1])
                printf ("%d: 0x%016lx %s\n", i, cur_ctx->regs.dbr[2 * i],
                        (cur_ctx->regs.dbr[2 * i + 1] & (1UL << 63)) ?
                        "enabled" : "disabled");
    }
    else if (strcmp (arg, "domain") == 0) {
        xc_dominfo_t dominfo;
#ifdef HAVE_DEBUG_OP
        xen_ia64_debug_op_t debug_op;
        int i;
#endif
        if (xc_domain_getinfo (xc_handle, domid, 1, &dominfo) < 0) {
            perror ("xc_domain_getinfo");
            return 0;
        }

        printf ("id=%d nr_pages=%lu shared_info_frame=%lu max_mem=%luKB\n",
                dominfo.domid, dominfo.nr_pages, dominfo.shared_info_frame,
                dominfo.max_memkb);
        printf ("  nr_online_vcpu=%u max_vcpu_id=%u\n",
                dominfo.nr_online_vcpus, dominfo.max_vcpu_id);
        printf ("  status:");
        if (dominfo.dying)
            printf (" dying");
        if (dominfo.crashed)
            printf (" crashed");
        if (dominfo.shutdown)
            printf (" shutdown(%u)", dominfo.shutdown_reason);
        if (dominfo.paused)
            printf (" paused");
        if (dominfo.blocked)
            printf (" blocked");
        if (dominfo.running)
            printf (" running");
        if (dominfo.hvm)
            printf (" hvm");
        if (dominfo.debugged)
            printf (" debug");
        printf ("\n");

#ifdef HAVE_DEBUG_OP
        if (do_ia64_debug_op (xc_handle, XEN_IA64_DEBUG_OP_GET_FLAGS,
                              domid, &debug_op) < 0) {
            perror ("xc_domain_getinfo");
            return 0;
        }
        printf ("debug flags: %08lx: ", debug_op.flags);
        for (i = 0; debug_flags[i].name; i++)
            if (debug_flags[i].bit & debug_op.flags)
                printf (" %s", debug_flags[i].name);
        printf ("\n");
#endif
    }
    else if (*arg == 0)
        printf ("choose among br, regs, cr, ar, tr, rr, db\n");
    else {
        printf ("cannot disp '%s'\n", arg);
        return CMD_ERROR;
    }
    return CMD_OK;
}

static enum cmd_status
cmd_bev (char *arg)
{
    xen_ia64_debug_op_t debug_op;
    int i;

    if (do_ia64_debug_op (xc_handle, XEN_IA64_DEBUG_OP_GET_FLAGS,
                          domid, &debug_op) < 0) {
        perror ("get debug flags");
        return CMD_ERROR;
    }
    if (arg == NULL || arg[0] == 0) {
        printf ("debug flags: %08lx:\n", debug_op.flags);
        for (i = 0; debug_flags[i].name; i++)
            printf (" %c%s\n",
                    (debug_flags[i].bit & debug_op.flags) ? '+' : '-',
                    debug_flags[i].name);
        return CMD_OK;
    }
    else {
        char *p = strtok ((char *)arg, " ");

        while (p != NULL) {
            unsigned int flag = 0;

            for (i = 0; debug_flags[i].name; i++)
                if (strcmp (p, debug_flags[i].name) == 0
                    || ((p[0] == '-' || p[0] == '+')
                        && strcmp (p + 1, debug_flags[i].name) == 0)) {
                    flag = debug_flags[i].bit;
                    break;
                }
            if (flag == 0) {
                printf ("unknown event %s\n", p);
                return CMD_ERROR;
            }
            if (p[0] == '-')
                debug_op.flags &= ~flag;
            else
                debug_op.flags |= flag;

            p = strtok (NULL, " ");
        }
        if (do_ia64_debug_op (xc_handle, XEN_IA64_DEBUG_OP_SET_FLAGS,
                              domid, &debug_op) < 0) {
            perror ("set debug flags");
            return CMD_ERROR;
        }
        /* Disabling force_SS and force_DB requires setting psr.  */
        if (vcpu_setcontext (cur_vcpu) < 0)
            return CMD_ERROR;
        else
            return CMD_OK;
    }
}

static enum cmd_status
cmd_set (char *line)
{
    char *reg;
    unsigned long *addr;
    unsigned long val;

    reg = parse_arg (&line);

    addr = get_reg_addr (reg);
    if (addr == NULL) {
        printf ("unknown register %s\n", reg);
        return CMD_ERROR;
    }

    if (parse_expr (&line, &val, 0) < 0)
        return CMD_ERROR;

    *addr = val;

    if (vcpu_setcontext (cur_vcpu) < 0)
        return CMD_ERROR;
    else
        return CMD_OK;
}

const struct command_desc commands[];

static enum cmd_status
cmd_help (char *line)
{
    int i;

    for (i = 0; commands[i].name; i++)
        printf ("%s -- %s\n", commands[i].name, commands[i].help);

    return CMD_OK;
}

const struct command_desc commands[] = {
    { "registers", "display current registers", cmd_registers },
    { "sstep", "single step", cmd_sstep },
    { "go", "resume execution", cmd_go },
    { "quit", "quit debugger", cmd_quit },
    { "echo", "display parameters", cmd_echo },
    { "disassemble", "disassemble memory", cmd_disassemble },
    { "dump", "dump memory", cmd_dump },
    { "break", "set a break point", cmd_break },
    { "watch", "set a watch point", cmd_watch },
    { "cb", "resume until branch", cmd_cb },
    { "delete", "delete a break point", cmd_delete },
    { "disable", "disable a break point", cmd_disable },
    { "enable", "enable a break point", cmd_enable },
    { "print", "print an expression", cmd_print },
    { "disp", "disp br/regs/cr/ar/tr/rr/db/psr/break/domain", cmd_disp},
    { "bev", "break on event", cmd_bev},
    { "set", "set reg val", cmd_set},
    { "help", "disp help", cmd_help },
    { NULL, NULL, NULL }
};


enum cmd_status do_command (int vcpu, char *line)
{
    char *cmd;
    char *args;
    int i;
    const struct command_desc *desc;
    static const struct command_desc *last_desc;
    enum cmd_status status;
    int flag_ambiguous;

    cur_vcpu = vcpu;
    cur_ctx = &vcpu_ctx_any[vcpu].c;

    /* Handle repeat last-command.  */
    if (*line == 0) {
        if (last_desc != NULL)
            return (*last_desc->cmd)("");
        else
            return CMD_OK;
    }
    last_desc = NULL;

    cmd = parse_arg (&line);
    args = line;

    desc = NULL;
    flag_ambiguous = 0;

    for (i = 0; commands[i].name; i++) {
        const char *n = commands[i].name;
        char *c = cmd;

        while (*n == *c && *n)
            n++, c++;

        if (*c == 0) {
            /* Match.  */
            if (desc != NULL) {
                if (!flag_ambiguous)
                    printf ("ambiguous command: %s", desc->name);
                printf (", %s", commands[i].name);
                flag_ambiguous = 1;
            }
            else
                desc = &commands[i];
        }
    }

    if (flag_ambiguous) {
        printf ("\n");
        return CMD_ERROR;
    }
    else if (!desc) {
        printf ("command not found, try help\n");
        return CMD_ERROR;
    }

    status = (*desc->cmd)(args);
    if (status == CMD_REPEAT)
        last_desc = desc;
    return status;
}

void xenitp (int vcpu)
{
    int ret;
    struct sigaction sa;
    xc_dominfo_t dominfo;

    xc_handle = xc_interface_open (); /* for accessing control interface */

    ret = xc_domain_getinfo (xc_handle, domid, 1, &dominfo);
    if (ret < 0) {
        perror ("xc_domain_getinfo");
        exit (-1);
    }

    vcpu_ctx_any = calloc (sizeof(vcpu_ctx_any), dominfo.max_vcpu_id + 1);
    if (!vcpu_ctx_any) {
        perror ("vcpu context array alloc");
        exit (-1);
    }
    cur_ctx = &vcpu_ctx_any[vcpu].c;

    if (xc_domain_setdebugging (xc_handle, domid, 1) != 0)
        perror ("setdebugging");

    ret = xc_domain_pause (xc_handle, domid);
    if (ret < 0) {
        perror ("xc_domain_pause");
        exit (-1);
    }

    ret = xc_ia64_vcpu_getcontext (xc_handle, domid, vcpu, cur_ctx);
    if (ret < 0) {
        perror ("xc_ia64_vcpu_getcontext");
        exit (-1);
    }

    print_ctx (cur_ctx);

    /* Catch ctrl-c.  */
    sa.sa_handler = &ctrl_c_handler;
    sa.sa_flags = 0;
    sigemptyset (&sa.sa_mask);
    if (sigaction (SIGINT, &sa, NULL) != 0)
        perror ("sigaction");

    while (1) {
        char buf[128];
        int len;

        printf ("XenITP> ");
        fflush (stdout);

        if (fgets (buf, sizeof (buf), stdin) == NULL)
            break;

        len = strlen ((char *)buf);
        if (len >= 1 && buf[len - 1] == '\n')
            buf[len - 1] = 0;

        ret = do_command (vcpu, buf);
        if (ret == CMD_QUIT)
            break;
    }

    /* Clear debug bits.  */
    if ((cur_ctx->regs.psr & (PSR_SS | PSR_TB | PSR_DB)) != 0) {
        cur_ctx->regs.psr &= ~(PSR_SS | PSR_TB | PSR_DB);
        cur_ctx->regs.psr |= PSR_DD | PSR_ID;
        vcpu_setcontext (cur_vcpu);
    }

    /* Disable debugging.  */
    if (xc_domain_setdebugging (xc_handle, domid, 0) != 0)
            perror ("setdebugging");

    if (!quit_paused) {
        ret = xc_domain_unpause (xc_handle, domid);
        if (ret < 0) {
            perror ("xc_domain_unpause");
            exit (-1);
        }
    }

    ret = xc_interface_close (xc_handle);
    if (ret < 0) {
        perror ("xc_interface_close");
        exit (-1);
    }
}

static void usage (void)
{
    printf ("usage:\n");
    printf ("  xenitp <DOMAIN> [VCPU]\n");

}

int main (int argc, char **argv)
{
    int ch;
    static const char *sopts = "h"
        ;
    static const struct option lopts[] = {
        {"help", 0, NULL, 'h'},
        {0, 0, 0, 0}
    };
    int vcpu = 0;

    while ((ch = getopt_long (argc, argv, sopts, lopts, NULL)) != -1) {
        switch (ch) {
        case 'h':
            usage ();
            exit (-1);
        case '?':
            fprintf (stderr, "%s --help for more options\n", argv[0]);
            exit (-1);
        }
    }

    argv += optind;
    argc -= optind;

    if (argc < 1 || argc > 2) {
        usage ();
        exit (-1);
    }

    domid = atoi (argv[0]);
    if (domid == 0) {
        fprintf (stderr, "cannot trace dom0\n");
        exit (-1);
    }

    if (argc == 2)
        vcpu = atoi (argv[1]);

    xenitp (vcpu);

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
