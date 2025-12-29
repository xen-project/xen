/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/sched.h>

#include <asm/processor.h>
#include <asm/sbi.h>
#include <asm/vsbi.h>

extern const struct vsbi_ext _svsbi_exts[], _evsbi_exts[];

void __init check_vsbi_ext_ranges(void)
{
    for ( const struct vsbi_ext *a = _svsbi_exts; a != _evsbi_exts; a++ )
        for ( const struct vsbi_ext *b = a + 1; b != _evsbi_exts; b++ )
            if ( !(a->eid_end < b->eid_start || b->eid_end < a->eid_start) )
                panic("EID range overlap detected: "
                      "%s:[#%#lx..#%#lx] vs %s:[#%#lx..#%#lx]\n",
                      a->name, a->eid_start, a->eid_end,
                      b->name, b->eid_start, b->eid_end);
}

const struct vsbi_ext *vsbi_find_extension(unsigned long eid)
{
    for ( const struct vsbi_ext *ext = _svsbi_exts;
          ext != _evsbi_exts;
          ext++ )
        if ( (eid >= ext->eid_start) && (eid <= ext->eid_end) )
            return ext;

    return NULL;
}

void vsbi_handle_ecall(struct cpu_user_regs *regs)
{
    const unsigned long eid = regs->a7;
    const unsigned long fid = regs->a6;
    const struct vsbi_ext *ext = vsbi_find_extension(eid);
    int ret;

    if ( ext )
        ret = ext->handler(eid, fid, regs);
    else
    {
        gprintk(XENLOG_ERR, "Unsupported Guest SBI EID #%#lx, FID #%lu\n",
                eid, regs->a1);
        ret = SBI_ERR_NOT_SUPPORTED;
    }

    /*
     * The ecall instruction is not part of the RISC-V C extension (compressed
     * instructions), so it is always 4 bytes long. Therefore, it is safe to
     * use a fixed length of 4 bytes instead of reading guest memory to
     * determine the instruction length.
     */
    regs->sepc += 4;
    regs->a0 = ret;
}
