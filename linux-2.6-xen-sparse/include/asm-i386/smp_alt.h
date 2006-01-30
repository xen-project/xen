#ifndef __ASM_SMP_ALT_H__
#define __ASM_SMP_ALT_H__

#include <linux/config.h>

#ifdef CONFIG_SMP
#if defined(CONFIG_SMP_ALTERNATIVES) && !defined(MODULE)
#define LOCK \
        "6677: nop\n" \
	".section __smp_alternatives,\"a\"\n" \
	".long 6677b\n" \
	".long 6678f\n" \
	".previous\n" \
	".section __smp_replacements,\"a\"\n" \
	"6678: .byte 1\n" \
	".byte 1\n" \
	".byte 0\n" \
        ".byte 1\n" \
	".byte -1\n" \
	"lock\n" \
	"nop\n" \
	".previous\n"
void prepare_for_smp(void);
void unprepare_for_smp(void);
#else
#define LOCK "lock ; "
#endif
#else
#define LOCK ""
#endif

#endif /* __ASM_SMP_ALT_H__ */
