#ifndef _ASM_TIME_H_
#define _ASM_TIME_H_

#include <asm/linux/time.h>
#include <asm/timex.h>

struct tm;
struct tm wallclock_time(void);

#endif /* _ASM_TIME_H_ */
