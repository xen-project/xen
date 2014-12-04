#ifndef __ARM_ARM32_BUG_H__
#define __ARM_ARM32_BUG_H__

#include <xen/stringify.h>

/* ARMv7 provides a list of undefined opcode (see A8.8.247 DDI 0406C.b)
 * Use one them encoding A1 to go in exception mode
 */
#define BUG_OPCODE  0xe7f000f0

#define BUG_INSTR ".word " __stringify(BUG_OPCODE)

#endif /* __ARM_ARM32_BUG_H__ */
