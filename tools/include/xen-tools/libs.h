#ifndef __XEN_TOOLS_LIBS__
#define __XEN_TOOLS_LIBS__

#ifndef BUILD_BUG_ON
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#define BUILD_BUG_ON(p) ({ _Static_assert(!(p), "!(" #p ")"); })
#else
#define BUILD_BUG_ON(p) ((void)sizeof(char[1 - 2 * !!(p)]))
#endif
#endif

#endif	/* __XEN_TOOLS_LIBS__ */
