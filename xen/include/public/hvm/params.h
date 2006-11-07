#ifndef __XEN_PUBLIC_HVM_PARAMS_H__
#define __XEN_PUBLIC_HVM_PARAMS_H__

#include "hvm_op.h"

/* Parameter space for HVMOP_{set,get}_param. */
#define HVM_PARAM_CALLBACK_IRQ 0
#define HVM_PARAM_STORE_PFN    1
#define HVM_PARAM_STORE_EVTCHN 2
#define HVM_PARAM_PAE_ENABLED  4
#define HVM_PARAM_IOREQ_PFN    5
#define HVM_PARAM_BUFIOREQ_PFN 6
#define HVM_NR_PARAMS          7

#endif /* __XEN_PUBLIC_HVM_PARAMS_H__ */
