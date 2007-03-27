/*
 * PAL/SAL call delegation
 *
 * Copyright (c) 2004 Li Susie <susie.li@intel.com>
 * Copyright (c) 2005 Yu Ke <ke.yu@intel.com>
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
 */
  
#include <xen/lib.h>
#include <asm/vcpu.h>
#include <asm/dom_fw.h>
#include <asm/pal.h>
#include <asm/sal.h>

void
pal_emul(struct vcpu *vcpu)
{
	u64 gr28, gr29, gr30, gr31;
	struct ia64_pal_retval result;

	vcpu_get_gr_nat(vcpu, 28, &gr28);  //bank1

	/* FIXME: works only for static calling convention ?  */
	vcpu_get_gr_nat(vcpu, 29, &gr29);
	vcpu_get_gr_nat(vcpu, 30, &gr30); 
	vcpu_get_gr_nat(vcpu, 31, &gr31);

	perfc_incr(vmx_pal_emul);
	result = xen_pal_emulator(gr28, gr29, gr30, gr31);

	vcpu_set_gr(vcpu, 8, result.status, 0);
	vcpu_set_gr(vcpu, 9, result.v0, 0);
	vcpu_set_gr(vcpu, 10, result.v1, 0);
	vcpu_set_gr(vcpu, 11, result.v2, 0);
}

void
sal_emul(struct vcpu *v)
{
	struct sal_ret_values result;
	result = sal_emulator(vcpu_get_gr(v, 32), vcpu_get_gr(v, 33),
	                      vcpu_get_gr(v, 34), vcpu_get_gr(v, 35),
	                      vcpu_get_gr(v, 36), vcpu_get_gr(v, 37),
	                      vcpu_get_gr(v, 38), vcpu_get_gr(v, 39));

	vcpu_set_gr(v, 8, result.r8, 0);
	vcpu_set_gr(v, 9, result.r9, 0);
	vcpu_set_gr(v, 10, result.r10, 0);
	vcpu_set_gr(v, 11, result.r11, 0);
}
