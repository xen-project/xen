#ifndef __XEN_VERSION_H__
#define __XEN_VERSION_H__

#include <xen/types.h>
#include <xen/elfstructs.h>

const char *xen_compile_date(void);
const char *xen_compile_time(void);
const char *xen_compile_by(void);
const char *xen_compile_domain(void);
const char *xen_compile_host(void);
const char *xen_compiler(void);
unsigned int xen_major_version(void);
unsigned int xen_minor_version(void);
const char *xen_extra_version(void);
const char *xen_changeset(void);
const char *xen_banner(void);
const char *xen_deny(void);
int xen_build_id(const void **p, unsigned int *len);

#ifdef BUILD_ID
void xen_build_init(void);
int xen_build_id_check(const Elf_Note *n, unsigned int n_sz,
                       const void **p, unsigned int *len);
#else
static inline void xen_build_init(void) {};
#endif

#endif /* __XEN_VERSION_H__ */
