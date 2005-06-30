/////////////////////////////////////////////////////////////////////////
//
//  Copyright (C) 2001  MandrakeSoft S.A.
//
//    MandrakeSoft S.A.
//    43, rue d'Aboukir
//    75002 Paris - France
//    http://www.linux-mandrake.com/
//    http://www.mandrakesoft.com/
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
//

#include "vl.h"
#include "ioapic.h"

#ifdef __OS
#undef __OS
#endif
#ifdef __i386__
#define __OS	"l"
#else
#define __OS "q"
#endif
#define ADDR (*(volatile long *) addr)

#ifdef IOAPIC_DEBUG
#define IOAPIC_LOG(a...) fprintf(logfile, ##a)
#else
#define IOAPIC_LOG(a...)
#endif

static IOAPICState *ioapic;

#define IOAPIC_ERR(a...) fprintf(logfile, ##a)
static __inline__ int test_and_set_bit(long nr, volatile void * addr)
{
	long oldbit;

	__asm__ __volatile__( 
		"bts"__OS" %2,%1\n\tsbb"__OS" %0,%0"
		:"=r" (oldbit),"=m" (ADDR)
		:"Ir" (nr) : "memory");
	return oldbit;
}

static __inline__ int test_and_clear_bit(long nr, volatile void * addr)
{
	long oldbit;

	__asm__ __volatile__( LOCK_PREFIX
		"btr"__OS" %2,%1\n\tsbb"__OS" %0,%0"
		:"=r" (oldbit),"=m" (ADDR)
		:"dIr" (nr) : "memory");
	return oldbit;
}

static __inline__ void clear_bit(long nr, volatile void * addr)
{
	__asm__ __volatile__( 
		"btr"__OS" %1,%0"
		:"=m" (ADDR)
		:"Ir" (nr));
}

static inline
void get_shareinfo_apic_msg(vlapic_info *share_info){
    while(test_and_set_bit(VL_STATE_MSG_LOCK, &share_info->vl_state)){};
}

static inline
void put_shareinfo_apic_msg(vlapic_info *share_info){
    clear_bit(VL_STATE_MSG_LOCK, &share_info->vl_state);
}
static inline
void get_shareinfo_eoi(vlapic_info *share_info){
    while(test_and_set_bit(VL_STATE_EOI_LOCK, &share_info->vl_state)){};
}

static inline
void put_shareinfo_eoi(vlapic_info *share_info){
    clear_bit(VL_STATE_EOI_LOCK, &share_info->vl_state);
}


static inline
void get_shareinfo_ext(vlapic_info *share_info){
    while(test_and_set_bit(VL_STATE_EXT_LOCK, &share_info->vl_state));
}

static inline
void put_shareinfo_ext(vlapic_info *share_info){
    clear_bit(VL_STATE_EXT_LOCK, &share_info->vl_state);
}


static __inline__ int test_bit(int nr, uint32_t value){
    return value & (1 << nr);
}

static void ioapic_enable(IOAPICState *s, uint8_t enable)
{
    if (!enable ^ IOAPICEnabled(s)) return;
    if(enable)
        s->flags |= IOAPIC_ENABLE_FLAG;
    else
        s->flags &= ~IOAPIC_ENABLE_FLAG;
}

#ifdef IOAPIC_DEBUG
static void
ioapic_dump_redir(IOAPICState *s, uint8_t entry)
{
    if (!s)
        return;

    RedirStatus redir = s->redirtbl[entry];

    fprintf(logfile, "entry %x: "
      "vector %x deliver_mod %x destmode %x delivestatus %x "
      "polarity %x remote_irr %x trigmod %x mask %x dest_id %x\n",
      entry,
      redir.RedirForm.vector, redir.RedirForm.deliver_mode,
      redir.RedirForm.destmode, redir.RedirForm.delivestatus,
      redir.RedirForm.polarity, redir.RedirForm.remoteirr,
      redir.RedirForm.trigmod, redir.RedirForm.mask,
      redir.RedirForm.dest_id);
}

static void
ioapic_dump_shareinfo(IOAPICState *s , int number)
{
    if (!s || !s->lapic_info[number])
        return;
    vlapic_info *m = s->lapic_info[number];
    IOAPIC_LOG("lapic_info %x : "
      "vl_lapic_id %x vl_logical_dest %x vl_dest_format %x vl_arb_id %x\n",
      number, m->vl_lapic_id, m->vl_logical_dest, m->vl_dest_format, m->vl_arb_id );
}
#endif

static void
ioapic_save(QEMUFile* f,void* opaque)
{
    IOAPIC_ERR("no implementation for ioapic_save\n");
}

static
int ioapic_load(QEMUFile* f,void* opaque,int version_id)
{
    IOAPIC_ERR("no implementation for ioapic_load\n");
    return 0;
}

uint32_t
ioapic_mem_readb(void *opaque, target_phys_addr_t addr)
{
    IOAPIC_ERR("ioapic_mem_readb\n");
    return 0;
}

uint32_t
ioapic_mem_readw(void *opaque, target_phys_addr_t addr)
{
    IOAPIC_ERR("ioapic_mem_readw\n");
    return 0;
}

static
void ioapic_mem_writeb(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    IOAPIC_ERR("ioapic_mem_writeb\n");
}

static
void ioapic_mem_writew(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    IOAPIC_ERR("ioapic_mem_writew\n");
}

static
uint32_t ioapic_mem_readl(void *opaque, target_phys_addr_t addr)
{
    unsigned short ioregsel;
    IOAPICState *s = opaque;
    uint32_t    result = 0;
    uint32_t    redir_index = 0;
    uint64_t    redir_content = 0;

    IOAPIC_LOG("apic_mem_readl addr %x\n", addr);
    if (!s){
        IOAPIC_ERR("null pointer for apic_mem_readl\n");
        return result;
    }

    addr &= 0xff;
    if(addr == 0x00){
        result = s->ioregsel;
        return result;
    }else if (addr != 0x10){
        IOAPIC_ERR("apic_mem_readl address error\n");
        return result;
    }

    ioregsel = s->ioregsel;

    switch (ioregsel){
        case IOAPIC_REG_APIC_ID:
            result = ((s->id & 0xf) << 24);
            break;
        case IOAPIC_REG_VERSION:
            result = ((((IOAPIC_NUM_PINS-1) & 0xff) << 16)  
                     | (IOAPIC_VERSION_ID & 0x0f));
            break;
        case IOAPIC_REG_ARB_ID:
            //FIXME
            result = ((s->id & 0xf) << 24);
            break;
        default:
            redir_index = (ioregsel - 0x10) >> 1;
            if (redir_index >= 0 && redir_index < IOAPIC_NUM_PINS){
               redir_content = s->redirtbl[redir_index].value;
               result = (ioregsel & 0x1)?
                        (redir_content >> 32) & 0xffffffff :
                        redir_content & 0xffffffff;
            }else{
                IOAPIC_ERR(
                  "upic_mem_readl:undefined ioregsel %x\n",
                  ioregsel);
            }
    }
    return result;
}

static
void ioapic_mem_writel(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    IOAPICState *s = opaque;
    uint32_t redir_index = 0;
    uint64_t redir_content;

    IOAPIC_LOG("apic_mem_writel addr %x val %x\n", addr, val);

    if (!s){
        IOAPIC_ERR("apic_mem_writel: null opaque\n");
        return;
    }

    addr &= 0xff;
    if (addr == 0x00){
        s->ioregsel = val;
        return;
    }else if (addr != 0x10){
        IOAPIC_ERR("apic_mem_writel: unsupported address\n");
    }

    switch (s->ioregsel){
        case IOAPIC_REG_APIC_ID:
            s->id = (val >> 24) & 0xf;
            break;
        case IOAPIC_REG_VERSION:
            IOAPIC_ERR("apic_mem_writel: version register read only\n");
            break;
        case IOAPIC_REG_ARB_ID:
            s->arb_id = val;
            break;
        default:
            redir_index = (s->ioregsel - 0x10) >> 1;
//            IOAPIC_LOG("apic_mem_write: change redir :index %x before %lx, val %x\n", redir_index, s->redirtbl[redir_index].value, val);
            if (redir_index >= 0 && redir_index < IOAPIC_NUM_PINS){
                redir_content = s->redirtbl[redir_index].value;
                if (s->ioregsel & 0x1)
                   redir_content = (((uint64_t)val & 0xffffffff) << 32) | (redir_content & 0xffffffff);
                else
                    redir_content = ((redir_content >> 32) << 32) | (val & 0xffffffff);
                s->redirtbl[redir_index].value = redir_content;
            }else {
                IOAPIC_ERR("apic_mem_writel: error register\n");
            }
            //IOAPIC_LOG("after value is %lx\n",  s->redirtbl[redir_index].value);
    }
}

static CPUReadMemoryFunc *ioapic_mem_read[3] = {
    ioapic_mem_readb,
    ioapic_mem_readw,
    ioapic_mem_readl,
};

static CPUWriteMemoryFunc *ioapic_mem_write[3] = {
    ioapic_mem_writeb,
    ioapic_mem_writew,
    ioapic_mem_writel,
};

void
IOAPICReset(IOAPICState *s)
{
    int i;
    if (!s)
        return ;

    memset(s, 0, sizeof(IOAPICState));

    for (i = 0; i < IOAPIC_NUM_PINS; i++)
        s->redirtbl[i].RedirForm.mask = 0x1;
//    IOAPIC_LOG("after Reset %lx\n",  s->redirtbl[0].value);
}

void
ioapic_update_config(IOAPICState *s, unsigned long address, uint8_t enable)
{
    int ioapic_mem;
    if (!s)
       return;

    ioapic_enable(s, enable);

    if (address != s->base_address){
        ioapic_mem = cpu_register_io_memory(0, ioapic_mem_read, ioapic_mem_write, s);
        cpu_register_physical_memory(address, IOAPIC_MEM_LENGTH, ioapic_mem);
        s->base_address = ioapic_mem;
    }
}

#define direct_intr(mode)   \
  (mode == VLAPIC_DELIV_MODE_SMI || \
   mode == VLAPIC_DELIV_MODE_NMI || \
   mode == VLAPIC_DELIV_MODE_INIT ||\
   mode == VLAPIC_DELIV_MODE_STARTUP)

int
ioapic_inj_irq(IOAPICState *s, uint8_t dest, uint8_t vector, uint8_t trig_mode, uint8_t delivery_mode)
{
    int msg_count;
    if (!s || !s->lapic_info[dest]){
        IOAPIC_ERR("ioapic_inj_irq NULL parameter\n");
        return 0;
    }
    IOAPIC_LOG("ioapic_inj_irq %d , trig %d delive mode %d\n",
      vector, trig_mode, delivery_mode);
    switch(delivery_mode){
        case VLAPIC_DELIV_MODE_FIXED:
        case VLAPIC_DELIV_MODE_LPRI:
            get_shareinfo_apic_msg(s->lapic_info[dest]);
            msg_count = s->lapic_info[dest]->apic_msg_count;
            s->lapic_info[dest]->vl_apic_msg[msg_count].deliv_mode = delivery_mode;
            s->lapic_info[dest]->vl_apic_msg[msg_count].level = trig_mode;
            s->lapic_info[dest]->vl_apic_msg[msg_count].vector = vector;
            s->lapic_info[dest]->vl_apic_msg[msg_count].vector = vector;
            s->lapic_info[dest]->apic_msg_count ++;
            put_shareinfo_apic_msg(s->lapic_info[dest]);
            break;
        case VLAPIC_DELIV_MODE_EXT:
/*            get_shareinfo_ext(s->lapic_info[dest]);
            test_and_set_bit(vector, &s->lapic_info[dest]->vl_ext_intr[0]);
            put_shareinfo_ext(s->lapic_info[dest]);*/
            IOAPIC_ERR("<ioapic_inj_irq> Ext interrupt\n");
            return 0;
        default:
            IOAPIC_ERR("<ioapic_inj_irq> error delivery mode\n");
            break;
    }
    return 1;
}

int
ioapic_match_logical_addr(IOAPICState *s, int number, uint8_t address)
{
    if(!s || !s->lapic_info[number]){
        IOAPIC_ERR("ioapic_match_logical_addr NULL parameter: "
          "number: %i s %p address %x\n",
          number, s, address);
        return 0;
    }
    IOAPIC_LOG("ioapic_match_logical_addr number %i address %x\n",
      number, address);

    if (((s->lapic_info[number]->vl_dest_format >> 28 ) & 0xf) != 0xf) {
        IOAPIC_ERR("ioapic_match_logical_addr: cluster model not implemented still%x"
          ,s->lapic_info[number]->vl_dest_format);
#ifdef IOAPIC_DEBUG
        ioapic_dump_shareinfo(s, number);
#endif
        return 0;
    }
    return ((address & ((s->lapic_info[number]->vl_logical_dest >> 24) & 0xff)) != 0);
}

int
ioapic_get_apr_lowpri(IOAPICState *s, int number)
{
    if(!s || !s->lapic_info[number]){
        IOAPIC_ERR("ioapic_get_apr_lowpri NULL parameter\n");
        return 0;
    }
    return s->lapic_info[number]->vl_arb_id;
}

uint32_t
ioapic_get_delivery_bitmask(IOAPICState *s,
uint8_t dest, uint8_t dest_mode, uint8_t vector, uint8_t delivery_mode)
{
    uint32_t mask = 0;
    int low_priority = 256, selected = -1, i;
    fprintf(logfile, "<ioapic_get_delivery_bitmask>: dest %d dest_mode %d"
      "vector %d del_mode %d, lapic_count %d\n",
      dest, dest_mode, vector, delivery_mode, s->lapic_count);
    if (!s) return mask;
    if (dest_mode == 0) { //Physical mode
        if ((dest < s->lapic_count) && s->lapic_info[dest])
            mask = 1 << dest;
    }
    else {
        /* logical destination. call match_logical_addr for each APIC. */
        if (dest == 0) return 0;
        for (i=0; i< s->lapic_count; i++) {
            //FIXME focus one, since no such issue on IPF, shoudl we add it?
            if ( s->lapic_info[i] && ioapic_match_logical_addr(s, i, dest)){
                if (delivery_mode != APIC_DM_LOWPRI)
                    mask |= (1<<i);
                else {
                    if (low_priority > ioapic_get_apr_lowpri(s, i)){
                        low_priority = ioapic_get_apr_lowpri(s, i);
                        selected = i;
                    }
                    fprintf(logfile, "%d low_priority %d apr %d select %d\n",
                      i, low_priority, ioapic_get_apr_lowpri(s, i), selected);
                }
            }
        }
        if (delivery_mode == APIC_DM_LOWPRI && (selected != -1)) 
            mask |= (1<< selected);
    }
  return mask;
}

void
ioapic_deliver(IOAPICState *s, int irqno){
    uint8_t dest = s->redirtbl[irqno].RedirForm.dest_id;
    uint8_t dest_mode = s->redirtbl[irqno].RedirForm.destmode;
    uint8_t delivery_mode = s->redirtbl[irqno].RedirForm.deliver_mode;
    uint8_t vector = s->redirtbl[irqno].RedirForm.vector;
    uint8_t trig_mode = s->redirtbl[irqno].RedirForm.trigmod;
    uint8_t bit;
    uint32_t deliver_bitmask; 

    IOAPIC_LOG("IOAPIC deliver: "
      "dest %x dest_mode %x delivery_mode %x vector %x trig_mode %x\n",
      dest, dest_mode, delivery_mode, vector, trig_mode);

    deliver_bitmask =
      ioapic_get_delivery_bitmask(s, dest, dest_mode, vector, delivery_mode);

      IOAPIC_LOG("ioapic_get_delivery_bitmask return %x\n", deliver_bitmask);
    if (!deliver_bitmask){
        IOAPIC_ERR("Ioapic deliver, no target on destination\n");
        return ;
    }

    switch (delivery_mode){
        case VLAPIC_DELIV_MODE_FIXED:
        case VLAPIC_DELIV_MODE_LPRI:
        case VLAPIC_DELIV_MODE_EXT:
            break;
        case VLAPIC_DELIV_MODE_SMI:
        case VLAPIC_DELIV_MODE_NMI:
        case VLAPIC_DELIV_MODE_INIT:
        case VLAPIC_DELIV_MODE_STARTUP:
        default:
            IOAPIC_ERR("Not support delivey mode %d\n", delivery_mode);
            return ;
    }

    for (bit = 0; bit < s->lapic_count; bit++){
        if (deliver_bitmask & (1 << bit)){
            if (s->lapic_info[bit]){
                ioapic_inj_irq(s, bit, vector, trig_mode, delivery_mode);
            }
        }
    }
}

static inline int __fls(u32 word)
{
    int bit;
    __asm__("bsrl %1,%0"
      :"=r" (bit)
      :"rm" (word));
    return word ? bit : -1;
}

#if 0
static __inline__ int find_highest_bit(unsigned long *data, int length){
    while(length && !data[--length]);
    return __fls(data[length]) +  32 * length;
}
#endif
int
ioapic_get_highest_irq(IOAPICState *s){
    uint32_t irqs;
    if (!s)
        return -1;
    irqs = s->irr & ~s->isr;
    return __fls(irqs);
}


void
service_ioapic(IOAPICState *s){
    int irqno;

    while((irqno = ioapic_get_highest_irq(s)) != -1){
        IOAPIC_LOG("service_ioapic: highest irqno %x\n", irqno);

        if (!s->redirtbl[irqno].RedirForm.mask)
            ioapic_deliver(s, irqno);

        if (s->redirtbl[irqno].RedirForm.trigmod == IOAPIC_LEVEL_TRIGGER){
            s->isr |= (1 << irqno);
        }
 //       clear_bit(irqno, &s->irr);
        s->irr &= ~(1 << irqno);
    }
}

void
ioapic_update_irq(IOAPICState *s)
{
    s->INTR = 1;
}

void
ioapic_set_irq(IOAPICState *s, int irq, int level)
{
    IOAPIC_LOG("ioapic_set_irq %x %x\n", irq, level);

    /* Timer interrupt implemented on HV side */
    if(irq == 0x0) return;
    if (!s){
        fprintf(logfile, "ioapic_set_irq null parameter\n");
        return;
    }
    if (!IOAPICEnabled(s) || s->redirtbl[irq].RedirForm.mask)
        return;
#ifdef IOAPIC_DEBUG
    ioapic_dump_redir(s, irq);
#endif
    if (irq >= 0 && irq < IOAPIC_NUM_PINS){
        uint32_t bit = 1 << irq;
        if (s->redirtbl[irq].RedirForm.trigmod == IOAPIC_LEVEL_TRIGGER){
            if(level)
                s->irr |= bit;
            else
                s->irr &= ~bit;
        }else{
            if(level)
                /* XXX No irr clear for edge interrupt */
                s->irr |= bit;
        }
    }

    ioapic_update_irq(s);
}

void
ioapic_legacy_irq(int irq, int level)
{
    ioapic_set_irq(ioapic, irq, level);
}

static inline int find_highest_bit(u32 *data, int length){
        while(length && !data[--length]);
            return __fls(data[length]) +  32 * length;
}

int
get_redir_num(IOAPICState *s, int vector){
    int i = 0;
    if(!s){
        IOAPIC_ERR("Null parameter for get_redir_num\n");
        return -1;
    }
    for(; i < IOAPIC_NUM_PINS-1; i++){
        if (s->redirtbl[i].RedirForm.vector == vector)
            return i;
    }
    return -1;
}

void
ioapic_update_EOI()
{
    int i = 0;
    uint32_t isr_info ;
    uint32_t vector;
    IOAPICState *s = ioapic;

    isr_info = s->isr;

    for (i = 0; i < s->lapic_count; i++){
        if (!s->lapic_info[i] ||
          !test_bit(VL_STATE_EOI, s->lapic_info[i]->vl_state))
            continue;
        get_shareinfo_eoi(s->lapic_info[i]);
        while((vector = find_highest_bit((unsigned int *)&s->lapic_info[i]->vl_eoi[0],VLAPIC_INT_COUNT_32)) != -1){
            int redir_num;
            if ((redir_num = get_redir_num(s, vector)) == -1){
                IOAPIC_ERR("Can't find redir item for %d EOI \n", vector);
                continue;
            }
            if (!test_and_clear_bit(redir_num, &s->isr)){
                IOAPIC_ERR("redir %d not set for %d  EOI\n", redir_num, vector);
                continue;
            }
            clear_bit(vector, &s->lapic_info[i]->vl_eoi[0]); 
        }
        clear_bit(VL_STATE_EOI, &s->lapic_info[i]->vl_state);
        put_shareinfo_eoi(s->lapic_info[i]);
    }
}


void
ioapic_init_apic_info(IOAPICState *s)
{
#ifdef IOAPIC_DEBUG
    fprintf(logfile, "ioapic_init_apic_info\n");
    if (!s)
        return;
#endif

#if 0
    if (!vio || !(vio->vl_number)){
        fprintf(logfile, "null vio or o vl number\n");
        return;
    }

    for (i = 0; i < MAX_LAPIC_NUM; i++) s->lapic_info[i] = NULL;

    s->lapic_count = vio->vl_number;
    for (i = 0; i < vio->vl_number; i++)
        s->lapic_info[i] = vio->vl_info + i;
#endif

}

void
ioapic_intack(IOAPICState *s)
{
#ifdef IOAPIC_DEBUG
    if (!s){
        fprintf(logfile, "ioapic_intack null parameter\n");
        return;
    }
#endif
    if (!s) s->INTR = 0;
}

int
ioapic_has_intr()
{
    return ioapic->INTR;
}

void
do_ioapic()
{
    service_ioapic(ioapic);
    ioapic_intack(ioapic);
}

IOAPICState *
IOAPICInit( )
{
    IOAPICState *s;

    s = qemu_mallocz(sizeof(IOAPICState));
    if (!s){
        fprintf(logfile, "IOAPICInit: malloc failed\n");
        return NULL;
    }

    IOAPICReset(s);
    ioapic_init_apic_info(s);
    register_savevm("ioapic", 0, 1, ioapic_save, ioapic_load, s);
    /* Remove after GFW ready */
    ioapic_update_config(s, 0xfec00000, 1);

    ioapic = s;
    return s;
}
