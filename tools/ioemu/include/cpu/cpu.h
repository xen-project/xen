/////////////////////////////////////////////////////////////////////////
// $Id: cpu.h,v 1.155 2003/12/30 22:12:45 cbothamy Exp $
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


#ifndef BX_CPU_H
#  define BX_CPU_H 1

#include <setjmp.h>
#ifdef BX_USE_VMX
extern "C" {
#include <io/ioreq.h>
}
#endif


#if BX_SUPPORT_APIC
#define BX_CPU_INTR             (BX_CPU_THIS_PTR INTR || BX_CPU_THIS_PTR local_apic.INTR)
#else
#define BX_CPU_INTR             BX_CPU_THIS_PTR INTR
#endif

class BX_CPU_C;
class BX_MEM_C;

#if BX_USE_CPU_SMF == 0
// normal member functions.  This can ONLY be used within BX_CPU_C classes.
// Anyone on the outside should use the BX_CPU macro (defined in bochs.h)
// instead.
#  define BX_CPU_THIS_PTR  this->
#  define BX_CPU_THIS      this
#  define BX_SMF
#  define BX_CPU_C_PREFIX  BX_CPU_C::
// with normal member functions, calling a member fn pointer looks like
// object->*(fnptr)(arg, ...);
// Since this is different from when SMF=1, encapsulate it in a macro.
#  define BX_CPU_CALL_METHOD(func, args) \
            (this->*((BxExecutePtr_t) (func))) args
#  define BX_CPU_CALL_METHODR(func, args) \
            (this->*((BxExecutePtr_tR) (func))) args
#else
// static member functions.  With SMF, there is only one CPU by definition.
#  define BX_CPU_THIS_PTR  BX_CPU(0)->
#  define BX_CPU_THIS      BX_CPU(0)
#  define BX_SMF           static
#  define BX_CPU_C_PREFIX
#  define BX_CPU_CALL_METHOD(func, args) \
            ((BxExecutePtr_t) (func)) args
#  define BX_CPU_CALL_METHODR(func, args) \
            ((BxExecutePtr_tR) (func)) args
#endif

#if BX_SMP_PROCESSORS==1
// single processor simulation, so there's one of everything
BOCHSAPI extern BX_CPU_C       bx_cpu;
#else
// multiprocessor simulation, we need an array of cpus and memories
BOCHSAPI extern BX_CPU_C       *bx_cpu_array[BX_SMP_PROCESSORS];
#endif

class BOCHSAPI BX_CPU_C : public logfunctions {

public: // for now...

  volatile bx_bool async_event;
  volatile bx_bool INTR;
  volatile bx_bool kill_bochs_request;

  // constructors & destructors...
  BX_CPU_C();
  ~BX_CPU_C(void);
  void init (BX_MEM_C *addrspace);
  void interrupt(Bit8u vector);

  BX_SMF void pagingA20Changed(void);
  BX_SMF void reset(unsigned source);
  BX_SMF void set_INTR(bx_bool value);
  BX_SMF void     atexit(void);

  // now for some ancillary functions...
  void cpu_loop(Bit32s max_instr_count);

#ifdef BX_USE_VMX
  ioreq_t* 	__get_ioreq(void);
  ioreq_t* 	get_ioreq(void);
  void 		dispatch_ioreq(ioreq_t *req);
  void		handle_ioreq();
  void		timer_handler();

  int send_event;
#endif
};

#endif  // #ifndef BX_CPU_H
