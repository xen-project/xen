#ifndef _XUTIL_SYS_CTYPE_H_
#define _XUTIL_SYS_CTYPE_H_
/** @file
 ** Replacement for ctype include that can be used
 * from user or kernel code.
 */
#ifdef __KERNEL__
#  include <linux/ctype.h>
#else
#  include <ctype.h>
#endif
#endif /* ! _XUTIL_SYS_CTYPE_H_ */
