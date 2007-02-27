
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
#include <xen/mm.h>
#include <asm/vmx_mm_def.h>
#include <asm/gcc_intrin.h>
#include <linux/interrupt.h>
#include <asm/vmx_vcpu.h>
#include <asm/bundle.h>
#include <asm/types.h>
#include <public/hvm/ioreq.h>
#include <asm/vmx.h>
#include <public/event_channel.h>
#include <public/xen.h>
#include <linux/event.h>
#include <xen/domain.h>
#include <asm/viosapic.h>
#include <asm/vlsapic.h>

#define HVM_BUFFERED_IO_RANGE_NR 1

struct hvm_buffered_io_range {
    unsigned long start_addr;
    unsigned long length;
};

static struct hvm_buffered_io_range buffered_stdvga_range = {0xA0000, 0x20000};
static struct hvm_buffered_io_range
*hvm_buffered_io_ranges[HVM_BUFFERED_IO_RANGE_NR] =
{
    &buffered_stdvga_range
};

int hvm_buffered_io_intercept(ioreq_t *p)
{
    struct vcpu *v = current;
    spinlock_t  *buffered_io_lock;
    buffered_iopage_t *buffered_iopage =
        (buffered_iopage_t *)(v->domain->arch.hvm_domain.buffered_io_va);
    unsigned long tmp_write_pointer = 0;
    int i;

    /* ignore READ ioreq_t! */
    if ( p->dir == IOREQ_READ )
        return 0;

    for ( i = 0; i < HVM_BUFFERED_IO_RANGE_NR; i++ ) {
        if ( p->addr >= hvm_buffered_io_ranges[i]->start_addr &&
             p->addr + p->size - 1 < hvm_buffered_io_ranges[i]->start_addr +
                                     hvm_buffered_io_ranges[i]->length )
            break;
    }

    if ( i == HVM_BUFFERED_IO_RANGE_NR )
        return 0;

    buffered_io_lock = &v->domain->arch.hvm_domain.buffered_io_lock;
    spin_lock(buffered_io_lock);

    if ( buffered_iopage->write_pointer - buffered_iopage->read_pointer ==
         (unsigned long)IOREQ_BUFFER_SLOT_NUM ) {
        /* the queue is full.
         * send the iopacket through the normal path.
         * NOTE: The arithimetic operation could handle the situation for
         * write_pointer overflow.
         */
        spin_unlock(buffered_io_lock);
        return 0;
    }

    tmp_write_pointer = buffered_iopage->write_pointer % IOREQ_BUFFER_SLOT_NUM;

    memcpy(&buffered_iopage->ioreq[tmp_write_pointer], p, sizeof(ioreq_t));

    /*make the ioreq_t visible before write_pointer*/
    wmb();
    buffered_iopage->write_pointer++;

    spin_unlock(buffered_io_lock);

    return 1;
}


static void low_mmio_access(VCPU *vcpu, u64 pa, u64 *val, size_t s, int dir)
{
    struct vcpu *v = current;
    vcpu_iodata_t *vio;
    ioreq_t *p;

    vio = get_vio(v->domain, v->vcpu_id);
    if (vio == 0) {
        panic_domain(NULL,"bad shared page: %lx", (unsigned long)vio);
    }
    p = &vio->vp_ioreq;
    p->addr = pa;
    p->size = s;
    p->count = 1;
    p->dir = dir;
    if(dir==IOREQ_WRITE)     //write;
        p->data = *val;
    p->data_is_ptr = 0;
    p->type = 1;
    p->df = 0;

    p->io_count++;
    if(hvm_buffered_io_intercept(p)){
        p->state = STATE_IORESP_READY;
        vmx_io_assist(v);
        return ;
    }else 
    vmx_send_assist_req(v);
    if(dir==IOREQ_READ){ //read
        *val=p->data;
    }
    return;
}

int vmx_ide_pio_intercept(ioreq_t *p, u64 *val)
{
    struct buffered_piopage *pio_page =
        (void *)(current->domain->arch.hvm_domain.buffered_pio_va);
    struct pio_buffer *piobuf;
    uint32_t pointer, page_offset;

    if (p->addr == 0x1F0)
	piobuf = &pio_page->pio[PIO_BUFFER_IDE_PRIMARY];
    else if (p->addr == 0x170)
	piobuf = &pio_page->pio[PIO_BUFFER_IDE_SECONDARY];
    else
	return 0;

    if (p->size != 2 && p->size != 4)
        return 0;

    pointer = piobuf->pointer;
    page_offset = piobuf->page_offset;

    /* sanity check */
    if (page_offset + pointer < offsetof(struct buffered_piopage, buffer))
	return 0;
    if (page_offset + piobuf->data_end > PAGE_SIZE)
	return 0;

    if (pointer + p->size < piobuf->data_end) {
        uint8_t *bufp = (uint8_t *)pio_page + page_offset + pointer;
        if (p->dir == IOREQ_WRITE) {
            if (likely(p->size == 4 && (((long)bufp & 3) == 0)))
                *(uint32_t *)bufp = *val;
            else
                memcpy(bufp, val, p->size);
        } else {
            if (likely(p->size == 4 && (((long)bufp & 3) == 0))) {
                *val = *(uint32_t *)bufp;
            } else {
                *val = 0;
                memcpy(val, bufp, p->size);
            }
        }
        piobuf->pointer += p->size;
        p->state = STATE_IORESP_READY;
        vmx_io_assist(current);
        return 1;
    }
    return 0;
}

#define TO_LEGACY_IO(pa)  (((pa)>>12<<2)|((pa)&0x3))

static void legacy_io_access(VCPU *vcpu, u64 pa, u64 *val, size_t s, int dir)
{
    struct vcpu *v = current;
    vcpu_iodata_t *vio;
    ioreq_t *p;

    vio = get_vio(v->domain, v->vcpu_id);
    if (vio == 0) {
        panic_domain(NULL,"bad shared page\n");
    }
    p = &vio->vp_ioreq;
    p->addr = TO_LEGACY_IO(pa&0x3ffffffUL);
    p->size = s;
    p->count = 1;
    p->dir = dir;
    if(dir==IOREQ_WRITE)     //write;
        p->data = *val;
    p->data_is_ptr = 0;
    p->type = 0;
    p->df = 0;

    p->io_count++;

    if (vmx_ide_pio_intercept(p, val))
        return;

    vmx_send_assist_req(v);
    if(dir==IOREQ_READ){ //read
        *val=p->data;
    }
#ifdef DEBUG_PCI
    if(dir==IOREQ_WRITE)
        if(p->addr == 0xcf8UL)
            printk("Write 0xcf8, with val [0x%lx]\n", p->data);
    else
        if(p->addr == 0xcfcUL)
            printk("Read 0xcfc, with val [0x%lx]\n", p->data);
#endif //DEBUG_PCI
    return;
}

static void mmio_access(VCPU *vcpu, u64 src_pa, u64 *dest, size_t s, int ma, int dir)
{
    struct virtual_platform_def *v_plat;
    //mmio_type_t iot;
    unsigned long iot;
    iot=__gpfn_is_io(vcpu->domain, src_pa>>PAGE_SHIFT);
    v_plat = vmx_vcpu_get_plat(vcpu);

    perfc_incra(vmx_mmio_access, iot >> 56);
    switch (iot) {
    case GPFN_PIB:       
        if (ma != 4)
            panic_domain(NULL, "Access PIB not with UC attribute\n");

        if (!dir)
            vlsapic_write(vcpu, src_pa, s, *dest);
        else
            *dest = vlsapic_read(vcpu, src_pa, s);
        break;
    case GPFN_GFW:
        break;
    case GPFN_IOSAPIC:
	if (!dir)
	    viosapic_write(vcpu, src_pa, s, *dest);
	else
	    *dest = viosapic_read(vcpu, src_pa, s);
	break;
    case GPFN_FRAME_BUFFER:
    case GPFN_LOW_MMIO:
        low_mmio_access(vcpu, src_pa, dest, s, dir);
        break;
    case GPFN_LEGACY_IO:
        legacy_io_access(vcpu, src_pa, dest, s, dir);
        break;
    default:
        panic_domain(NULL,"Bad I/O access\n");
        break;
    }
    return;
}

/*
   dir 1: read 0:write
    inst_type 0:integer 1:floating point
 */
#define SL_INTEGER  0        // store/load interger
#define SL_FLOATING    1       // store/load floating

void emulate_io_inst(VCPU *vcpu, u64 padr, u64 ma)
{
    REGS *regs;
    IA64_BUNDLE bundle;
    int slot, dir=0, inst_type;
    size_t size;
    u64 data, post_update, slot1a, slot1b, temp;
    INST64 inst;
    regs=vcpu_regs(vcpu);
    if (IA64_RETRY == __vmx_get_domain_bundle(regs->cr_iip, &bundle)) {
        /* if fetch code fail, return and try again */
        return;
    }
    slot = ((struct ia64_psr *)&(regs->cr_ipsr))->ri;
    if (!slot) inst.inst = bundle.slot0;
    else if (slot == 1){
        slot1a=bundle.slot1a;
        slot1b=bundle.slot1b;
        inst.inst =slot1a + (slot1b<<18);
    }
    else if (slot == 2) inst.inst = bundle.slot2;


    // Integer Load/Store
    if(inst.M1.major==4&&inst.M1.m==0&&inst.M1.x==0){
        inst_type = SL_INTEGER;  //
        size=(inst.M1.x6&0x3);
        if((inst.M1.x6>>2)>0xb){      // write
            dir=IOREQ_WRITE;     //write
            vcpu_get_gr_nat(vcpu,inst.M4.r2,&data);
        }else if((inst.M1.x6>>2)<0xb){   //  read
            dir=IOREQ_READ;
        }
    }
    // Integer Load + Reg update
    else if(inst.M2.major==4&&inst.M2.m==1&&inst.M2.x==0){
        inst_type = SL_INTEGER;
        dir = IOREQ_READ;     //write
        size = (inst.M2.x6&0x3);
        vcpu_get_gr_nat(vcpu,inst.M2.r3,&temp);
        vcpu_get_gr_nat(vcpu,inst.M2.r2,&post_update);
        temp += post_update;
        vcpu_set_gr(vcpu,inst.M2.r3,temp,0);
    }
    // Integer Load/Store + Imm update
    else if(inst.M3.major==5){
        inst_type = SL_INTEGER;  //
        size=(inst.M3.x6&0x3);
        if((inst.M5.x6>>2)>0xb){      // write
            dir=IOREQ_WRITE;     //write
            vcpu_get_gr_nat(vcpu,inst.M5.r2,&data);
            vcpu_get_gr_nat(vcpu,inst.M5.r3,&temp);
            post_update = (inst.M5.i<<7)+inst.M5.imm7;
            if(inst.M5.s)
                temp -= post_update;
            else
                temp += post_update;
            vcpu_set_gr(vcpu,inst.M5.r3,temp,0);

        }else if((inst.M3.x6>>2)<0xb){   //  read
            dir=IOREQ_READ;
            vcpu_get_gr_nat(vcpu,inst.M3.r3,&temp);
            post_update = (inst.M3.i<<7)+inst.M3.imm7;
            if(inst.M3.s)
                temp -= post_update;
            else
                temp += post_update;
            vcpu_set_gr(vcpu,inst.M3.r3,temp,0);

        }
    }
    // Floating-point spill
    else if (inst.M9.major == 6 && inst.M9.x6 == 0x3B &&
             inst.M9.m == 0 && inst.M9.x == 0) {
        struct ia64_fpreg v;

        inst_type = SL_FLOATING;
        dir = IOREQ_WRITE;
        vcpu_get_fpreg(vcpu, inst.M9.f2, &v);
        /* Write high word.
           FIXME: this is a kludge!  */
        v.u.bits[1] &= 0x3ffff;
        mmio_access(vcpu, padr + 8, &v.u.bits[1], 8, ma, IOREQ_WRITE);
        data = v.u.bits[0];
        size = 3;
    }
    // Floating-point spill + Imm update
    else if(inst.M10.major==7&&inst.M10.x6==0x3B){
        struct ia64_fpreg v;
	inst_type=SL_FLOATING;
	dir=IOREQ_WRITE;
	vcpu_get_fpreg(vcpu,inst.M10.f2,&v);
	vcpu_get_gr_nat(vcpu,inst.M10.r3,&temp);
	post_update = (inst.M10.i<<7)+inst.M10.imm7;
	if(inst.M10.s)
            temp -= post_update;
	else
            temp += post_update;
	vcpu_set_gr(vcpu,inst.M10.r3,temp,0);

	/* Write high word.
	   FIXME: this is a kludge!  */
	v.u.bits[1] &= 0x3ffff;
	mmio_access(vcpu, padr + 8, &v.u.bits[1], 8, ma, IOREQ_WRITE);
	data = v.u.bits[0];
	size = 3;
    }
    // Floating-point stf8 + Imm update
    else if(inst.M10.major==7&&inst.M10.x6==0x31){
        struct ia64_fpreg v;
	inst_type=SL_FLOATING;
	dir=IOREQ_WRITE;
	size=3;
	vcpu_get_fpreg(vcpu,inst.M10.f2,&v);
	data = v.u.bits[0]; /* Significand.  */
	vcpu_get_gr_nat(vcpu,inst.M10.r3,&temp);
	post_update = (inst.M10.i<<7)+inst.M10.imm7;
	if(inst.M10.s)
            temp -= post_update;
	else
            temp += post_update;
	vcpu_set_gr(vcpu,inst.M10.r3,temp,0);
    }
//    else if(inst.M6.major==6&&inst.M6.m==0&&inst.M6.x==0&&inst.M6.x6==3){
//        inst_type=SL_FLOATING;  //fp
//        dir=IOREQ_READ;
//        size=3;     //ldfd
//    }
    //  lfetch - do not perform accesses.
    else if(inst.M15.major==7&&inst.M15.x6>=0x2c&&inst.M15.x6<=0x2f){
	vcpu_get_gr_nat(vcpu,inst.M15.r3,&temp);
	post_update = (inst.M15.i<<7)+inst.M15.imm7;
	if(inst.M15.s)
            temp -= post_update;
	else
            temp += post_update;
	vcpu_set_gr(vcpu,inst.M15.r3,temp,0);

	vcpu_increment_iip(vcpu);
	return;
    }
    // Floating-point Load Pair + Imm ldfp8 M12
    else if(inst.M12.major==6&&inst.M12.m==1&&inst.M12.x==1&&inst.M12.x6==1){
        struct ia64_fpreg v;
        inst_type=SL_FLOATING;
        dir = IOREQ_READ;
        size = 8;     //ldfd
        mmio_access(vcpu, padr, &data, size, ma, dir);
        v.u.bits[0]=data;
        v.u.bits[1]=0x1003E;
        vcpu_set_fpreg(vcpu,inst.M12.f1,&v);
        padr += 8;
        mmio_access(vcpu, padr, &data, size, ma, dir);
        v.u.bits[0]=data;
        v.u.bits[1]=0x1003E;
        vcpu_set_fpreg(vcpu,inst.M12.f2,&v);
        padr += 8;
        vcpu_set_gr(vcpu,inst.M12.r3,padr,0);
        vcpu_increment_iip(vcpu);
        return;
    }
    else{
        panic_domain
	  (NULL,"This memory access instr can't be emulated: %lx pc=%lx\n ",
	   inst.inst, regs->cr_iip);
    }

    size = 1 << size;
    if(dir==IOREQ_WRITE){
        mmio_access(vcpu, padr, &data, size, ma, dir);
    }else{
        mmio_access(vcpu, padr, &data, size, ma, dir);
        if(inst_type==SL_INTEGER){       //gp
            vcpu_set_gr(vcpu,inst.M1.r1,data,0);
        }else{
            panic_domain(NULL, "Don't support ldfd now !");
/*            switch(inst.M6.f1){

            case 6:
                regs->f6=(struct ia64_fpreg)data;
            case 7:
                regs->f7=(struct ia64_fpreg)data;
            case 8:
                regs->f8=(struct ia64_fpreg)data;
            case 9:
                regs->f9=(struct ia64_fpreg)data;
            case 10:
                regs->f10=(struct ia64_fpreg)data;
            case 11:
                regs->f11=(struct ia64_fpreg)data;
            default :
                ia64_ldfs(inst.M6.f1,&data);
            }
*/
        }
    }
    vcpu_increment_iip(vcpu);
}
