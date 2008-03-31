#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <public/xen.h>

#include "x86_emulate/x86_emulate.h"

#define __emulate_fpu_insn(_op)                 \
do{ rc = X86EMUL_UNHANDLEABLE;                  \
    goto done;                                  \
} while (0)

#include "x86_emulate/x86_emulate.c"
