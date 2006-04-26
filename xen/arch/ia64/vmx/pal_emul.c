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

#include <asm/vmx_vcpu.h>
#include <asm/pal.h>
#include <asm/sal.h>
#include <asm/tlb.h>
#include <asm/vmx_mm_def.h>

static void
get_pal_parameters (VCPU *vcpu, UINT64 *gr29,
			UINT64 *gr30, UINT64 *gr31) {

  	vcpu_get_gr_nat(vcpu,29,gr29);
  	vcpu_get_gr_nat(vcpu,30,gr30); 
  	vcpu_get_gr_nat(vcpu,31,gr31);
}

static void
set_pal_result (VCPU *vcpu,struct ia64_pal_retval result) {

	vcpu_set_gr(vcpu,8, result.status,0);
	vcpu_set_gr(vcpu,9, result.v0,0);
	vcpu_set_gr(vcpu,10, result.v1,0);
	vcpu_set_gr(vcpu,11, result.v2,0);
}


static struct ia64_pal_retval
pal_cache_flush (VCPU *vcpu) {
	UINT64 gr28,gr29, gr30, gr31;
	struct ia64_pal_retval result;

	get_pal_parameters (vcpu, &gr29, &gr30, &gr31);
	vcpu_get_gr_nat(vcpu,28,&gr28);

	/* Always call Host Pal in int=1 */
	gr30 = gr30 &(~(0x2UL));

	/* call Host PAL cache flush */
	result=ia64_pal_call_static(gr28 ,gr29, gr30,gr31,1);  // Clear psr.ic when call PAL_CACHE_FLUSH

	/* If host PAL call is interrupted, then loop to complete it */
//	while (result.status == 1) {
//		ia64_pal_call_static(gr28 ,gr29, gr30, 
//				result.v1,1LL);
//	}
	while (result.status != 0) {
        panic("PAL_CACHE_FLUSH ERROR, status %ld", result.status);
	}

	return result;
}

static struct ia64_pal_retval
pal_vm_tr_read (VCPU *vcpu ) {
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented

	return result;
}


static struct ia64_pal_retval
pal_prefetch_visibility (VCPU *vcpu)  {
	/* Due to current MM virtualization algorithm,
	 * We do not allow guest to change mapping attribute.
	 * Thus we will not support PAL_PREFETCH_VISIBILITY
	 */
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented

	return result;
}

static struct ia64_pal_retval
pal_platform_addr(VCPU *vcpu) {
	struct ia64_pal_retval result;

	result.status= 0; //success

	return result;
}

static struct ia64_pal_retval
pal_halt (VCPU *vcpu) {
	//bugbug: to be implement. 
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented

	return result;
}


static struct ia64_pal_retval
pal_halt_light (VCPU *vcpu) {
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented

	return result;
}

static struct ia64_pal_retval
pal_cache_read (VCPU *vcpu) {
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented

	return result;
}

static struct ia64_pal_retval
pal_cache_write (VCPU *vcpu) {
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented

	return result;
}

static struct ia64_pal_retval
pal_bus_get_features(VCPU *vcpu){
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented
	return result;
}

static struct ia64_pal_retval
pal_cache_summary(VCPU *vcpu){
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented
	return result;
}

static struct ia64_pal_retval
pal_cache_init(VCPU *vcpu){
	struct ia64_pal_retval result;
	result.status=0;
	return result;
}

static struct ia64_pal_retval
pal_cache_info(VCPU *vcpu){
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented
	return result;
}

static struct ia64_pal_retval
pal_cache_prot_info(VCPU *vcpu){
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented
	return result;
}

static struct ia64_pal_retval
pal_mem_attrib(VCPU *vcpu){
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented
	return result;
}

static struct ia64_pal_retval
pal_debug_info(VCPU *vcpu){
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented
	return result;
}

static struct ia64_pal_retval
pal_fixed_addr(VCPU *vcpu){
}

static struct ia64_pal_retval
pal_freq_base(VCPU *vcpu){
    struct ia64_pal_retval result;
    struct ia64_sal_retval isrv;

    PAL_CALL(result,PAL_FREQ_BASE, 0, 0, 0);
    if(result.v0 == 0){ //PAL_FREQ_BASE may not be implemented in some platforms, call SAL instead.
        SAL_CALL(isrv, SAL_FREQ_BASE, 
                SAL_FREQ_BASE_PLATFORM, 0, 0, 0, 0, 0, 0);
        result.status = isrv.status;
        result.v0 = isrv.v0;
        result.v1 = result.v2 =0;
    }
    return result;
}

static struct ia64_pal_retval
pal_freq_ratios(VCPU *vcpu){
    struct ia64_pal_retval result;

    PAL_CALL(result,PAL_FREQ_RATIOS, 0, 0, 0);
    return result;
}

static struct ia64_pal_retval
pal_halt_info(VCPU *vcpu){
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented
	return result;
}

static struct ia64_pal_retval
pal_logical_to_physica(VCPU *vcpu){
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented
	return result;
}

static struct ia64_pal_retval
pal_perf_mon_info(VCPU *vcpu){
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented
	return result;
}

static struct ia64_pal_retval
pal_proc_get_features(VCPU *vcpu){
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented
	return result;
}

static struct ia64_pal_retval
pal_ptce_info(VCPU *vcpu){
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented
	return result;
}

static struct ia64_pal_retval
pal_register_info(VCPU *vcpu){
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented
	return result;
}

static struct ia64_pal_retval
pal_rse_info(VCPU *vcpu){
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented
	return result;
}
static struct ia64_pal_retval
pal_test_info(VCPU *vcpu){
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented
	return result;
}

static struct ia64_pal_retval
pal_vm_summary(VCPU *vcpu){
	pal_vm_info_1_u_t vminfo1;
	pal_vm_info_2_u_t vminfo2;	
	struct ia64_pal_retval result;
	
	PAL_CALL(result,PAL_VM_SUMMARY,0,0,0);
	if(!result.status){
		vminfo1.pvi1_val = result.v0;
		vminfo1.pal_vm_info_1_s.max_itr_entry = NITRS -1;
		vminfo1.pal_vm_info_1_s.max_dtr_entry = NDTRS -1;
		result.v0 = vminfo1.pvi1_val;
		vminfo2.pal_vm_info_2_s.impl_va_msb = GUEST_IMPL_VA_MSB;
		vminfo2.pal_vm_info_2_s.rid_size = current->domain->arch.rid_bits;
		result.v1 = vminfo2.pvi2_val;
	} 
	return result;
}

static struct ia64_pal_retval
pal_vm_info(VCPU *vcpu){
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented
	return result;
}

static struct ia64_pal_retval
pal_vm_page_size(VCPU *vcpu){
	struct ia64_pal_retval result;

	result.status= -1; //unimplemented
	return result;
}
void
pal_emul( VCPU *vcpu) {
	UINT64 gr28;
	struct ia64_pal_retval result;


	vcpu_get_gr_nat(vcpu,28,&gr28);  //bank1

	switch (gr28) {
		case PAL_CACHE_FLUSH:
			result = pal_cache_flush (vcpu);
			break;

		case PAL_PREFETCH_VISIBILITY:
			result = pal_prefetch_visibility (vcpu);
			break;

		case PAL_VM_TR_READ:
			result = pal_vm_tr_read (vcpu);
			break;

		case PAL_HALT:
			result = pal_halt (vcpu);
			break;

		case PAL_HALT_LIGHT:
			result = pal_halt_light (vcpu);
			break;

		case PAL_CACHE_READ:
			result = pal_cache_read (vcpu);
			break;

		case PAL_CACHE_WRITE:
			result = pal_cache_write (vcpu);
			break;

		case PAL_PLATFORM_ADDR:
			result = pal_platform_addr (vcpu);
			break;

		case PAL_FREQ_RATIOS:
			result = pal_freq_ratios (vcpu);
			break;

		case PAL_FREQ_BASE:
			result = pal_freq_base (vcpu);
			break;

		case PAL_BUS_GET_FEATURES :
			result = pal_bus_get_features (vcpu);
			break;

		case PAL_CACHE_SUMMARY :
			result = pal_cache_summary (vcpu);
			break;

		case PAL_CACHE_INIT :
			result = pal_cache_init(vcpu);
			break;

		case PAL_CACHE_INFO :
			result = pal_cache_info(vcpu);
			break;

		case PAL_CACHE_PROT_INFO :
			result = pal_cache_prot_info(vcpu);
			break;

		case PAL_MEM_ATTRIB :
			result = pal_mem_attrib(vcpu);
			break;

		case PAL_DEBUG_INFO :
			result = pal_debug_info(vcpu);
			break;

		case PAL_FIXED_ADDR :
			result = pal_fixed_addr(vcpu);
			break;

		case PAL_HALT_INFO :
			result = pal_halt_info(vcpu);
			break;

		case PAL_LOGICAL_TO_PHYSICAL :
			result = pal_logical_to_physica(vcpu);
			break;

		case PAL_PERF_MON_INFO :
			result = pal_perf_mon_info(vcpu);
			break;

		case  PAL_PROC_GET_FEATURES:
			result = pal_proc_get_features(vcpu);
			break;

		case PAL_PTCE_INFO :
			result = pal_ptce_info(vcpu);
			break;

		case PAL_REGISTER_INFO :
			result = pal_register_info(vcpu);
			break;

		case PAL_RSE_INFO :
			result = pal_rse_info(vcpu);
			break;

		case PAL_TEST_PROC :
			result = pal_test_info(vcpu);
			break;

		case PAL_VM_SUMMARY :
			result = pal_vm_summary(vcpu);
			break;

		case PAL_VM_INFO :
			result = pal_vm_info(vcpu);
			break;

		case PAL_VM_PAGE_SIZE :
			result = pal_vm_page_size(vcpu);
			break;

		default:
			panic("pal_emul(): guest call unsupported pal" );
  }
		set_pal_result (vcpu, result);
}


