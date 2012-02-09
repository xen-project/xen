#ifndef __ARM_BUG_H__
#define __ARM_BUG_H__

#define BUG() __bug(__FILE__, __LINE__)
#define WARN() __warn(__FILE__, __LINE__)

#endif /* __X86_BUG_H__ */
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
