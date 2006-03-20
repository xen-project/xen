

/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
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
 * 
 */

#ifndef _LSAPIC_H
#define _LSAPIC_H
#include <xen/sched.h>

extern void vmx_virq_line_init(struct domain *d);
extern void vtm_init(struct vcpu *vcpu);
extern void vtm_set_itc(struct  vcpu *vcpu, uint64_t new_itc);
extern void vtm_set_itm(struct vcpu *vcpu, uint64_t val);
extern void vtm_set_itv(struct vcpu *vcpu, uint64_t val);
extern void vmx_vexirq(struct vcpu  *vcpu);
extern void vhpi_detection(struct vcpu *vcpu);

#endif
