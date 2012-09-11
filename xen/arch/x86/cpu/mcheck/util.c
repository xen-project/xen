
#include <asm/system.h>
#include "util.h"
#include "mce.h"

void mce_panic_check(void)
{
    if ( is_mc_panic )
    {
        local_irq_enable();
        for ( ; ; )
            halt();
    }
}
