#ifndef _ASM_TIME_H_
#define _ASM_TIME_H_

#include <asm/linux/time.h>
#include <asm/timex.h>

#define wallclock_time() ((struct tm) { 0 })

#endif /* _ASM_TIME_H_ */
