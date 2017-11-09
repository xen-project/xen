/*
 *  This code provides functions to handle gcc's profiling data format
 *  introduced with gcc 7.
 *
 *  For a better understanding, refer to gcc source:
 *  gcc/gcov-io.h
 *  libgcc/libgcov.c
 *
 *  Uses gcc-internal data definitions.
 */

#include "gcov.h"

#if GCC_VERSION < 70000
#error "Wrong version of GCC used to compile gcov"
#endif

#define GCOV_COUNTERS 9

#include "gcc_4_7.c"

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
