#ifndef		_REGIONREG_H_
#define		_REGIONREG_H_
#ifdef  CONFIG_VTI
#define XEN_DEFAULT_RID     0xf00000
#define DOMAIN_RID_SHIFT    20
#define DOMAIN_RID_MASK     (~(1U<<DOMAIN_RID_SHIFT -1))
#else //CONFIG_VTI
#define XEN_DEFAULT_RID		7
#endif // CONFIG_VTI
#define	IA64_MIN_IMPL_RID_MSB	17
#define _REGION_ID(x)   ({ia64_rr _v; _v.rrval = (long) (x); _v.rid;})
#define _REGION_PAGE_SIZE(x)    ({ia64_rr _v; _v.rrval = (long) (x); _v.ps;})
#define _REGION_HW_WALKER(x)    ({ia64_rr _v; _v.rrval = (long) (x); _v.ve;})
#define _MAKE_RR(r, sz, v) ({ia64_rr _v; _v.rrval=0;_v.rid=(r);_v.ps=(sz);_v.ve=(v);_v.rrval;})

typedef union ia64_rr {
        struct {
                unsigned long  ve :   1;        /* enable hw walker */
                unsigned long  reserved0   :   1;        /* reserved */
                unsigned long  ps :   6;        /* log page size */
                unsigned long  rid:  24;        /* region id */
                unsigned long  reserved1   :  32;        /* reserved */
        };
        unsigned long rrval;
} ia64_rr;

//
// region register macros
//
#define RR_TO_VE(arg) (((arg) >> 0) & 0x0000000000000001)
#define RR_VE(arg) (((arg) & 0x0000000000000001) << 0)
#define RR_VE_MASK 0x0000000000000001L
#define RR_VE_SHIFT 0
#define RR_TO_PS(arg) (((arg) >> 2) & 0x000000000000003f)
#define RR_PS(arg) (((arg) & 0x000000000000003f) << 2)
#define RR_PS_MASK 0x00000000000000fcL
#define RR_PS_SHIFT 2
#define RR_TO_RID(arg) (((arg) >> 8) & 0x0000000000ffffff)
#define RR_RID(arg) (((arg) & 0x0000000000ffffff) << 8)
#define RR_RID_MASK 0x00000000ffffff00L

#endif		/* !_REGIONREG_H_ */
