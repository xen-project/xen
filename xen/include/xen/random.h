#ifndef __XEN_RANDOM_H__
#define __XEN_RANDOM_H__

unsigned int get_random(void);

/* The value keeps unchange once initialized for each booting */
extern unsigned int boot_random;

#endif /* __XEN_RANDOM_H__ */
