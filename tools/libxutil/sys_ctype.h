#ifndef _XENO_SYS_CTYPE_H_
#define _XENO_SYS_CTYPE_H_
/** @file
 ** Replacement for ctype include that can be used
 * from user or kernel code.
 */
#ifdef __KERNEL__
#  include <linux/ctype.h>
#else
#  include <ctype.h>
#endif
#endif /* ! _XENO_SYS_CTYPE_H_ */
