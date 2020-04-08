#ifndef __ASM_X86_HVM_GUEST_ACCESS_H__
#define __ASM_X86_HVM_GUEST_ACCESS_H__

unsigned int copy_to_user_hvm(void *to, const void *from, unsigned int len);
unsigned int clear_user_hvm(void *to, unsigned int len);
unsigned int copy_from_user_hvm(void *to, const void *from, unsigned int len);

#endif /* __ASM_X86_HVM_GUEST_ACCESS_H__ */
