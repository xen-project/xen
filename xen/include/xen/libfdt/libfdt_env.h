#ifndef _LIBFDT_ENV_H
#define _LIBFDT_ENV_H

#include <xen/config.h>
#include <xen/types.h>
#include <xen/string.h>
#include <asm/byteorder.h>

#define fdt16_to_cpu(x) be16_to_cpu(x)
#define cpu_to_fdt16(x) cpu_to_be16(x)
#define fdt32_to_cpu(x) be32_to_cpu(x)
#define cpu_to_fdt32(x) cpu_to_be32(x)
#define fdt64_to_cpu(x) be64_to_cpu(x)
#define cpu_to_fdt64(x) cpu_to_be64(x)

/* Xen-specific libfdt error code. */
#define FDT_ERR_XEN(err) (FDT_ERR_MAX + (err))

#endif /* _LIBFDT_ENV_H */
