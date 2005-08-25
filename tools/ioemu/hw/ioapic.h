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

#ifndef __IOAPIC_H
#define __IOAPIC_H

#include "xenctrl.h"
#include <io/ioreq.h>
#include <io/vmx_vlapic.h>

#define IOAPIC_NUM_PINS 24
#define IOAPIC_VERSION_ID 0x11
#define IOAPIC_LEVEL_TRIGGER 1
#define APIC_DM_FIXED	0
#define APIC_DM_LOWPRI	1



#ifdef CONFIG_SMP
#define LOCK_PREFIX "lock ; "
#else
#define LOCK_PREFIX ""
#endif

#ifdef __I386__
#define __OS "q" 
#define __OP "r" 
#else
#define __OS "l"  /* Operation Suffix */
#define __OP "e"  /* Operand Prefix */
#endif

#define ADDR (*(volatile long *) addr)
#if 0
#endif
extern void *shared_page;
extern FILE *logfile;
#ifdef __BIGENDIAN__
typedef union RedirStatus
{
    uint64_t value;
    struct {
        uint8_t dest_id;
        uint8_t reserved[4];
        uint8_t reserve:7;
        uint8_t mask:1;         /* interrupt mask*/
        uint8_t trigmod:1;
        uint8_t remoteirr:1;
        uint8_t polarity:1;
        uint8_t delivestatus:1;
        uint8_t destmode:1;
        uint8_t deliver_mode:3;
        uint8_t vector;
    }RedirForm;
}RedirStatus;
#else
typedef union RedirStatus
{
    uint64_t value;
    struct {
        uint8_t vector;
        uint8_t deliver_mode:3;
        uint8_t destmode:1;
        uint8_t delivestatus:1;
        uint8_t polarity:1;
        uint8_t remoteirr:1;
        uint8_t trigmod:1;
        uint8_t mask:1;         /* interrupt mask*/
        uint8_t reserve:7;
        uint8_t reserved[4];
        uint8_t dest_id;
    }RedirForm;
}RedirStatus;
#endif
/*
 * IOAPICState stands for a instance of a IOAPIC
 */

/* FIXME tmp before working with Local APIC */
#define IOAPIC_MEM_LENGTH 0x100
#define IOAPIC_ENABLE_MASK 0x0
#define IOAPIC_ENABLE_FLAG (1 << IOAPIC_ENABLE_MASK)
#define MAX_LAPIC_NUM 32

struct IOAPICState{
    uint32_t INTR;
    uint32_t id;
    uint32_t arb_id;
    uint32_t  flags;
    unsigned long base_address;
    uint32_t irr;
    uint32_t isr;           /* This is used for level trigger */
    uint8_t  vector_irr[256];
    RedirStatus redirtbl[IOAPIC_NUM_PINS];
    uint32_t ioregsel;
    uint32_t lapic_count;
    vlapic_info *lapic_info[MAX_LAPIC_NUM];
};
#define IOAPIC_REG_APIC_ID 0x0
#define IOAPIC_REG_VERSION 0x1
#define IOAPIC_REG_ARB_ID  0x2
#define IOAPICEnabled(s) (s->flags & IOAPIC_ENABLE_FLAG)

typedef struct IOAPICState IOAPICState;

#endif
