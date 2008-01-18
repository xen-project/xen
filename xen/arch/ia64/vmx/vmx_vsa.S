/* -*-  Mode:ASM; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx_vsa.c: Call PAL virtualization services.
 * Copyright (c) 2005, Intel Corporation.
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
 *  Arun Sharma <arun.sharma@intel.com>
 *  Xuefei Xu (Anthony Xu) (Anthony.xu@intel.com)
 */

#include <asm/asmmacro.h>


    .text

/*
 * extern UINT64 ia64_call_vsa(UINT64 proc,UINT64 arg1, UINT64 arg2,
 *                  UINT64 arg3, UINT64 arg4, UINT64 arg5,
 *                  UINT64 arg6, UINT64 arg7);
 *
 * XXX: The currently defined services use only 4 args at the max. The
 *  rest are not consumed.
 */
GLOBAL_ENTRY(ia64_call_vsa)
    .regstk 4,4,0,0

rpsave  =   loc0
pfssave =   loc1
psrsave =   loc2
entry   =   loc3
hostret =   r24

    alloc   pfssave=ar.pfs,4,4,0,0
    mov rpsave=rp
    movl    entry=@gprel(__vsa_base)
1:  mov hostret=ip
    mov r25=in1         // copy arguments
    mov r26=in2
    mov r27=in3
    mov psrsave=psr
    ;;
    add entry=entry,gp
    tbit.nz p6,p0=psrsave,14    // IA64_PSR_I
    tbit.nz p7,p0=psrsave,13    // IA64_PSR_IC
    ;;
    ld8 entry=[entry]       // read entry point
    ;;
    add hostret=2f-1b,hostret   // calculate return address
    add entry=entry,in0
    ;;
    rsm psr.i | psr.ic
    ;;
    srlz.d
    mov b6=entry
    br.cond.sptk b6         // call the service
2:
    // Architectural sequence for enabling interrupts if necessary
(p7)    ssm psr.ic
    ;;
(p7)    srlz.d
    ;;
(p6)    ssm psr.i
    ;;
    mov rp=rpsave
    mov ar.pfs=pfssave
    mov r8=r31
    ;;
    srlz.d
    br.ret.sptk rp

END(ia64_call_vsa)

