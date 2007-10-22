#ifndef ASM_NMI_H
#define ASM_NMI_H

#include <public/nmi.h>

#define register_guest_nmi_callback(a)  (-ENOSYS)
#define unregister_guest_nmi_callback() (-ENOSYS)

#endif /* ASM_NMI_H */
