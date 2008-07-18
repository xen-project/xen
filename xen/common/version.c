#include <xen/compile.h>
#include <xen/version.h>

const char *xen_compile_date(void)
{
    return XEN_COMPILE_DATE;
}

const char *xen_compile_time(void)
{
    return XEN_COMPILE_TIME;
}

const char *xen_compile_by(void)
{
    return XEN_COMPILE_BY;
}

const char *xen_compile_domain(void)
{
    return XEN_COMPILE_DOMAIN;
}

const char *xen_compile_host(void)
{
    return XEN_COMPILE_HOST;
}

const char *xen_compiler(void)
{
    return XEN_COMPILER;
}

unsigned int xen_major_version(void)
{
    return XEN_VERSION;
}

unsigned int xen_minor_version(void)
{
    return XEN_SUBVERSION;
}

const char *xen_extra_version(void)
{
    return XEN_EXTRAVERSION;
}

const char *xen_changeset(void)
{
    return XEN_CHANGESET;
}

const char *xen_banner(void)
{
    return XEN_BANNER;
}
