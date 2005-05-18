
/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * mmio.c: MMIO emulation components.
 * Copyright (c) 2004, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 *  Yaozu Dong (Eddie Dong) (Eddie.dong@intel.com)
 *  Kun Tian (Kevin Tian) (Kevin.tian@intel.com)
 */

#include <linux/sched.h>
#include <asm/tlb.h>
#include <asm/vmx_mm_def.h>
#include <asm/gcc_intrin.h>
#include <xen/interrupt.h>
#include <asm/vmx_vcpu.h>

struct mmio_list *lookup_mmio(u64 gpa, struct mmio_list *mio_base)
{
    int     i;
    for (i=0; mio_base[i].iot != NOT_IO; i++ ) {
        if ( gpa >= mio_base[i].start && gpa <= mio_base[i].end )
            return &mio_base[i];
    }
    return NULL;
}


extern void pib_write(VCPU *vcpu, void *src, uint64_t pib_off, size_t s, int ma);
static inline void mmio_write(VCPU *vcpu, void *src, u64 dest_pa, size_t s, int ma)
{
    struct virutal_platform_def *v_plat;
    struct mmio_list    *mio;
    
    v_plat = vmx_vcpu_get_plat(vcpu);
    mio = lookup_mmio(dest_pa, v_plat->mmio);
    if ( mio == NULL ) 
        panic ("Wrong address for MMIO\n");
    
    switch (mio->iot) {
    case PIB_MMIO:
        pib_write(vcpu, src, dest_pa - v_plat->pib_base, s, ma);
        break;
    case VGA_BUFF:
    case CHIPSET_IO:
    case LOW_MMIO:
    case LEGACY_IO:
    case IO_SAPIC:
    default:
        break;
    }
    return;
}

static inline void mmio_read(VCPU *vcpu, u64 src_pa, void *dest, size_t s, int ma)
{
    struct virutal_platform_def *v_plat;
    struct mmio_list    *mio;
    
    v_plat = vmx_vcpu_get_plat(vcpu);
    mio = lookup_mmio(src_pa, v_plat->mmio);
    if ( mio == NULL ) 
        panic ("Wrong address for MMIO\n");
    
    switch (mio->iot) {
    case PIB_MMIO:
        pib_read(vcpu, src_pa - v_plat->pib_base, dest, s, ma);
        break;
    case VGA_BUFF:
    case CHIPSET_IO:
    case LOW_MMIO:
    case LEGACY_IO:
    case IO_SAPIC:
    default:
        break;
    }
    return;
}

/*
 * Read or write data in guest virtual address mode.
 */
 
void
memwrite_v(VCPU *vcpu, thash_data_t *vtlb, void *src, void *dest, size_t s)
{
    uint64_t pa;

    if (!vtlb->nomap)
        panic("Normal memory write shouldn't go to this point!");
    pa = PPN_2_PA(vtlb->ppn);
    pa += POFFSET((u64)dest, vtlb->ps);
    mmio_write (vcpu, src, pa, s, vtlb->ma);
}


void
memwrite_p(VCPU *vcpu, void *src, void *dest, size_t s)
{
    uint64_t pa = (uint64_t)dest;
    int    ma;

    if ( pa & (1UL <<63) ) {
        // UC
        ma = 4;
        pa <<=1; 
        pa >>=1;
    } 
    else {
        // WBL
        ma = 0;     // using WB for WBL
    }
    mmio_write (vcpu, src, pa, s, ma);
}

void
memread_v(VCPU *vcpu, thash_data_t *vtlb, void *src, void *dest, size_t s)
{
    uint64_t pa;

    if (!vtlb->nomap)
        panic("Normal memory write shouldn't go to this point!");
    pa = PPN_2_PA(vtlb->ppn);
    pa += POFFSET((u64)src, vtlb->ps);
    
    mmio_read(vcpu, pa, dest, s, vtlb->ma);
}

void
memread_p(VCPU *vcpu, void *src, void *dest, size_t s)
{
    uint64_t pa = (uint64_t)src;
    int    ma;

    if ( pa & (1UL <<63) ) {
        // UC
        ma = 4;
        pa <<=1; 
        pa >>=1;
    } 
    else {
        // WBL
        ma = 0;     // using WB for WBL
    }
    mmio_read(vcpu, pa, dest, s, ma);
}

#define	PIB_LOW_HALF(ofst)	!(ofst&(1<<20))
#define PIB_OFST_INTA           0x1E0000
#define PIB_OFST_XTP            0x1E0008


/*
 * Deliver IPI message. (Only U-VP is supported now)
 *  offset: address offset to IPI space.
 *  value:  deliver value.
 */
static void deliver_ipi (VCPU *vcpu, uint64_t dm, uint64_t vector)
{
#ifdef  IPI_DEBUG
  printf ("deliver_ipi %lx %lx\n",dm,vector);
#endif
    switch ( dm ) {
    case 0:     // INT
        vmx_vcpu_pend_interrupt (vcpu, vector);
        break;
    case 2:     // PMI
        // TODO -- inject guest PMI
        panic ("Inject guest PMI!\n");
        break;
    case 4:     // NMI
        vmx_vcpu_pend_interrupt (vcpu, 2);     
        break;
    case 5:     // INIT
        // TODO -- inject guest INIT
        panic ("Inject guest INIT!\n");
        break;
    case 7:     // ExtINT
        vmx_vcpu_pend_interrupt (vcpu, 0);     
        break;
        
    case 1:
    case 3:
    case 6:
    default:
        panic ("Deliver reserved IPI!\n");
        break;
    }   
}

/*
 * TODO: Use hash table for the lookup.
 */
static inline VCPU *lid_2_vcpu (struct domain *d, u64 id, u64 eid)
{
	int   i;
	VCPU  *vcpu;
	LID	  lid;
	
	for (i=0; i<MAX_VIRT_CPUS; i++) {
		vcpu = d->exec_domain[i];
		lid.val = VPD_CR(vcpu, lid);
		if ( lid.id == id && lid.eid == eid ) {
		    return vcpu;
		}
	}
	return NULL;
}

/*
 * execute write IPI op.
 */
static int write_ipi (VCPU *vcpu, uint64_t addr, uint64_t value)
{
    VCPU   *target_cpu;
    
    target_cpu = lid_2_vcpu(vcpu->domain, 
    				((ipi_a_t)addr).id, ((ipi_a_t)addr).eid);
    if ( target_cpu == NULL ) panic("Unknown IPI cpu\n");
    if ( target_cpu == vcpu ) {
    	// IPI to self
        deliver_ipi (vcpu, ((ipi_d_t)value).dm, 
                ((ipi_d_t)value).vector);
        return 1;
    }
    else {
    	// TODO: send Host IPI to inject guest SMP IPI interruption
        panic ("No SM-VP supported!\n");
        return 0;
    }
}

void pib_write(VCPU *vcpu, void *src, uint64_t pib_off, size_t s, int ma)
{
    
    switch (pib_off) {
    case PIB_OFST_INTA:
        panic("Undefined write on PIB INTA\n");
        break;
    case PIB_OFST_XTP:
        if ( s == 1 && ma == 4 /* UC */) {
            vmx_vcpu_get_plat(vcpu)->xtp = *(uint8_t *)src;
        }
        else {
            panic("Undefined write on PIB XTP\n");
        }
        break;
    default:
        if ( PIB_LOW_HALF(pib_off) ) {   // lower half
            if ( s != 8 || ma != 0x4 /* UC */ ) {
                panic("Undefined IPI-LHF write!\n");
            }
            else {
                write_ipi(vcpu, pib_off, *(uint64_t *)src);
                // TODO for SM-VP
            }
        }
        else {      // upper half
            printf("IPI-UHF write %lx\n",pib_off);
            panic("Not support yet for SM-VP\n");
        }
        break;
    }
}

void pib_read(VCPU *vcpu, uint64_t pib_off, void *dest, size_t s, int ma)
{
    switch (pib_off) {
    case PIB_OFST_INTA:
        // todo --- emit on processor system bus.
        if ( s == 1 && ma == 4) { // 1 byte load
            // TODO: INTA read from IOSAPIC
        }
        else {
            panic("Undefined read on PIB INTA\n");
        }
        break;
    case PIB_OFST_XTP:
        if ( s == 1 && ma == 4) {
            *((uint8_t*)dest) = vmx_vcpu_get_plat(vcpu)->xtp;
        }
        else {
            panic("Undefined read on PIB XTP\n");
        }
        break;
    default:
        if ( PIB_LOW_HALF(pib_off) ) {   // lower half
            if ( s != 8 || ma != 4 ) {
                panic("Undefined IPI-LHF read!\n");
            }
            else {
#ifdef  IPI_DEBUG
                printf("IPI-LHF read %lx\n",pib_off);
#endif
                *(uint64_t *)dest = 0;  // TODO for SM-VP
            }
        }
        else {      // upper half
            if ( s != 1 || ma != 4 ) {
                panic("Undefined PIB-UHF read!\n");
            }
            else {
#ifdef  IPI_DEBUG
                printf("IPI-UHF read %lx\n",pib_off);
#endif
                *(uint8_t *)dest = 0;   // TODO for SM-VP
            }
        }
        break;
    }
}

